//! Persistence of organizations and their trusted issuers in an Oxigraph store.
//!
//! Layout:
//! - each organization's identity metadata lives in its own named graph, named after the
//!   organization IRI (`<base>/organizations/<uuid>`), so that an update atomically replaces the
//!   whole record;
//! - the system graph registers the organizations and holds their trusted issuers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oauth2::ClientSecret;
use oxigraph::model::vocab::rdf;
use oxigraph::model::{
  GraphName, GraphNameRef, Literal, NamedNode, NamedNodeRef, NamedOrBlankNode, Quad, QuadRef, Term,
  TermRef,
};
use oxigraph::store::{Store, Transaction};
use url::Url;
use uuid::Uuid;

use identity_metadata_commons::{PartyId, TrustedIssuer, ValidationMethod};

use crate::error::{AppError, AppResult};
use crate::model::{
  Address, Location, Organization, Place, PlaceType, PostalAddress, PostalAddressType,
};

mod vocab {
  use oxigraph::model::NamedNodeRef;

  pub const SYSTEM_GRAPH: NamedNodeRef<'_> =
    NamedNodeRef::new_unchecked("urn:identity-metadata-service:system");
  pub const ISSUER_PREFIX: &str = "urn:identity-metadata-service:issuer:";

  macro_rules! terms {
        ($ns:literal: $($name:ident = $local:literal),* $(,)?) => {
            $(pub const $name: NamedNodeRef<'_> = NamedNodeRef::new_unchecked(concat!($ns, $local));)*
        };
    }

  terms!("urn:identity-metadata-service:vocab#":
      REGISTERED_ORGANIZATION = "RegisteredOrganization",
      TRUSTED_ISSUER = "TrustedIssuer",
      HAS_ISSUER = "trustedIssuer",
      ISSUER_ID = "issuerId",
      ISSUER = "issuer",
      CLIENT_ID = "clientId",
      AUDIENCE = "audience",
      CLIENT_SECRET = "clientSecret",
  );

  pub mod schema {
    use oxigraph::model::NamedNodeRef;
    terms!("http://schema.org/":
        ORGANIZATION = "Organization",
        PLACE = "Place",
        POSTAL_ADDRESS = "PostalAddress",
        NAME = "name",
        LEGAL_NAME = "legalName",
        IDENTIFIER = "identifier",
        LOGO = "logo",
        LOCATION = "location",
        ADDRESS = "address",
    );
    pub const NS: &str = "http://schema.org/";
  }
}
use vocab::schema;

/// A trusted issuer as stored: its public registration, with the secret of the OAuth 2.0 client
/// registered at the issuer for this service when its tokens are introspected.
#[derive(Debug, Clone)]
pub struct StoredIssuer {
  /// Identifier of the registration, assigned by the server.
  pub id: String,
  /// OpenID issuer URL, base of the discovery document.
  pub issuer: String,
  /// How the tokens of the issuer are validated.
  pub token_validation: ValidationMethod,
  /// Audience the tokens must be intended for (`aud` claim); not checked when absent.
  pub audience: Option<String>,
  /// OAuth 2.0 client of this service at the issuer, used for token introspection.
  pub client_id: Option<String>,
  /// Never exposed through the API.
  pub client_secret: Option<ClientSecret>,
}

impl StoredIssuer {
  /// A new registration, validating tokens by introspection when a client is given, or with
  /// the keys of the issuer otherwise.
  pub fn new(
    issuer: String,
    audience: Option<String>,
    client: Option<(String, ClientSecret)>,
  ) -> Self {
    let (client_id, client_secret) = client.unzip();
    Self {
      id: Uuid::new_v4().to_string(),
      issuer,
      token_validation: validation_method(&client_secret),
      audience,
      client_id,
      client_secret,
    }
  }
}

/// The registration exposed through the API, without the client secret.
impl From<StoredIssuer> for TrustedIssuer {
  fn from(issuer: StoredIssuer) -> Self {
    Self {
      id: issuer.id,
      issuer: issuer.issuer,
      token_validation: issuer.token_validation,
      audience: issuer.audience,
      client_id: issuer.client_id,
    }
  }
}

fn validation_method(client_secret: &Option<ClientSecret>) -> ValidationMethod {
  match client_secret {
    Some(_) => ValidationMethod::Introspection,
    None => ValidationMethod::Jwks,
  }
}

#[derive(Clone)]
pub struct Repository {
  store: Store,
  base_url: String,
  /// Serializes writes: Oxigraph transactions are only "repeatable read", so concurrent
  /// check-then-write sequences (e.g. two creations of the same record) must not interleave.
  write_lock: Arc<Mutex<()>>,
}

impl Repository {
  pub fn new(store: Store, base_url: &Url) -> Self {
    Self {
      store,
      base_url: base_url.as_str().trim_end_matches('/').to_owned(),
      write_lock: Arc::default(),
    }
  }

  pub fn organization_iri(&self, id: Uuid) -> String {
    format!("{}/organizations/{id}", self.base_url)
  }

  fn organization_node(&self, id: Uuid) -> AppResult<NamedNode> {
    NamedNode::new(self.organization_iri(id)).map_err(|e| AppError::Internal(e.to_string()))
  }

  fn write<T>(&self, f: impl FnOnce(&mut Transaction<'_>) -> AppResult<T>) -> AppResult<T> {
    let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
    let mut transaction = self.store.start_transaction()?;
    let value = f(&mut transaction)?;
    transaction.commit()?;
    Ok(value)
  }

  /// Runs `f` in a transaction on a registered organization, or fails with "not found".
  fn write_registered<T>(
    &self,
    id: Uuid,
    f: impl FnOnce(&mut Transaction<'_>, &NamedNode) -> AppResult<T>,
  ) -> AppResult<T> {
    let node = self.organization_node(id)?;
    self.write(|t| {
      if !is_registered(t, node.as_ref())? {
        return Err(not_found(id));
      }
      f(t, &node)
    })
  }

  // ---- organizations ----

  /// Registers a new organization; its `identifier` must not be used by another one.
  pub fn create_organization(&self, id: Uuid, org: &Organization) -> AppResult<String> {
    let node = self.organization_node(id)?;
    self.write(|t| {
      if is_registered(t, node.as_ref())? {
        return Err(AppError::Conflict(format!(
          "organization `{id}` already exists"
        )));
      }
      check_identifier_available(t, &org.identifier, node.as_ref())?;
      t.insert(QuadRef::new(
        &node,
        rdf::TYPE,
        vocab::REGISTERED_ORGANIZATION,
        vocab::SYSTEM_GRAPH,
      ));
      t.insert_named_graph(&node);
      t.extend(&organization_quads(&node, org));
      Ok(())
    })?;
    Ok(node.into_string())
  }

  /// Replaces the identity metadata of an organization; its `identifier` may change, but must
  /// not be used by another organization.
  pub fn update_organization(&self, id: Uuid, org: &Organization) -> AppResult<String> {
    self.write_registered(id, |t, node| {
      check_identifier_available(t, &org.identifier, node.as_ref())?;
      t.clear_graph(node)?;
      t.extend(&organization_quads(node, org));
      Ok(node.as_str().to_owned())
    })
  }

  /// Deletes an organization with its trusted issuers.
  pub fn delete_organization(&self, id: Uuid) -> AppResult<()> {
    self.write_registered(id, |t, node| {
      for quad in subject_quads(t, node.as_ref())? {
        if let (vocab::HAS_ISSUER, Term::NamedNode(issuer)) =
          (quad.predicate.as_ref(), &quad.object)
        {
          for issuer_quad in subject_quads(t, issuer.as_ref())? {
            t.remove(&issuer_quad);
          }
        }
        t.remove(&quad);
      }
      t.remove_named_graph(node)?;
      Ok(())
    })
  }

  pub fn get_organization(&self, id: Uuid) -> AppResult<Option<Organization>> {
    let node = self.organization_node(id)?;
    let registration = QuadRef::new(
      &node,
      rdf::TYPE,
      vocab::REGISTERED_ORGANIZATION,
      vocab::SYSTEM_GRAPH,
    );
    if !self.store.contains(registration)? {
      return Ok(None);
    }
    self.read_organization(node.as_ref()).map(Some)
  }

  pub fn list_organizations(&self) -> AppResult<Vec<(String, Organization)>> {
    let mut organizations = Vec::new();
    for quad in self.store.quads_for_pattern(
      None,
      Some(rdf::TYPE),
      Some(vocab::REGISTERED_ORGANIZATION.into()),
      Some(vocab::SYSTEM_GRAPH.into()),
    ) {
      if let NamedOrBlankNode::NamedNode(node) = quad?.subject {
        let org = self.read_organization(node.as_ref())?;
        organizations.push((node.into_string(), org));
      }
    }
    organizations.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(organizations)
  }

  // ---- trusted issuers ----

  pub fn add_issuer(&self, id: Uuid, issuer: &StoredIssuer) -> AppResult<()> {
    let issuer_node = NamedNode::new(format!("{}{}", vocab::ISSUER_PREFIX, issuer.id))
      .map_err(|e| AppError::Internal(e.to_string()))?;
    self.write_registered(id, |t, node| {
      if read_issuers(t, node.as_ref())?
        .iter()
        .any(|existing| existing.issuer == issuer.issuer)
      {
        return Err(AppError::Conflict(format!(
          "issuer `{}` is already trusted by organization `{id}`",
          issuer.issuer
        )));
      }
      let g = vocab::SYSTEM_GRAPH;
      let literal = |value: &str| Literal::from(value);
      t.insert(QuadRef::new(node, vocab::HAS_ISSUER, &issuer_node, g));
      t.insert(QuadRef::new(
        &issuer_node,
        rdf::TYPE,
        vocab::TRUSTED_ISSUER,
        g,
      ));
      t.insert(QuadRef::new(
        &issuer_node,
        vocab::ISSUER_ID,
        &literal(&issuer.id),
        g,
      ));
      t.insert(QuadRef::new(
        &issuer_node,
        vocab::ISSUER,
        &literal(&issuer.issuer),
        g,
      ));
      if let Some(audience) = &issuer.audience {
        t.insert(QuadRef::new(
          &issuer_node,
          vocab::AUDIENCE,
          &literal(audience),
          g,
        ));
      }
      if let Some(client_id) = &issuer.client_id {
        t.insert(QuadRef::new(
          &issuer_node,
          vocab::CLIENT_ID,
          &literal(client_id),
          g,
        ));
      }
      if let Some(secret) = &issuer.client_secret {
        t.insert(QuadRef::new(
          &issuer_node,
          vocab::CLIENT_SECRET,
          &literal(secret.secret()),
          g,
        ));
      }
      Ok(())
    })
  }

  /// Returns `None` when the organization does not exist.
  pub fn list_issuers(&self, id: Uuid) -> AppResult<Option<Vec<StoredIssuer>>> {
    let node = self.organization_node(id)?;
    let t = self.store.start_transaction()?;
    if !is_registered(&t, node.as_ref())? {
      return Ok(None);
    }
    read_issuers(&t, node.as_ref()).map(Some)
  }

  pub fn get_issuer(&self, id: Uuid, issuer_id: &str) -> AppResult<Option<StoredIssuer>> {
    Ok(
      self
        .list_issuers(id)?
        .into_iter()
        .flatten()
        .find(|issuer| issuer.id == issuer_id),
    )
  }

  pub fn remove_issuer(&self, id: Uuid, issuer_id: &str) -> AppResult<()> {
    self.write_registered(id, |t, node| {
      let not_found = || AppError::NotFound(format!("issuer `{issuer_id}` not found"));
      let issuer_node =
        NamedNode::new(format!("{}{issuer_id}", vocab::ISSUER_PREFIX)).map_err(|_| not_found())?;
      let link = QuadRef::new(node, vocab::HAS_ISSUER, &issuer_node, vocab::SYSTEM_GRAPH);
      if !t.contains(link)? {
        return Err(not_found());
      }
      t.remove(link);
      for quad in subject_quads(t, issuer_node.as_ref())? {
        t.remove(&quad);
      }
      Ok(())
    })
  }

  fn read_organization(&self, node: NamedNodeRef<'_>) -> AppResult<Organization> {
    let mut graph = Graph::default();
    for quad in self
      .store
      .quads_for_pattern(None, None, None, Some(GraphNameRef::NamedNode(node)))
    {
      let quad = quad?;
      if let NamedOrBlankNode::NamedNode(subject) = quad.subject {
        graph
          .0
          .entry(subject.into_string())
          .or_default()
          .push((quad.predicate, quad.object));
      }
    }
    graph
      .organization(node.as_str())
      .ok_or_else(|| AppError::Internal(format!("corrupted organization graph <{node}>")))
  }
}

fn not_found(id: Uuid) -> AppError {
  AppError::NotFound(format!("organization `{id}` not found"))
}

/// Fails with a conflict when another registered organization than `owner` has `identifier`.
fn check_identifier_available(
  t: &Transaction<'_>,
  identifier: &PartyId,
  owner: NamedNodeRef<'_>,
) -> AppResult<()> {
  let value = Term::from(Literal::from(identifier.to_string()));
  for quad in t.quads_for_pattern(None, Some(schema::IDENTIFIER), Some(value.as_ref()), None) {
    let quad = quad?;
    // The identifier of an organization is a triple of its own graph about itself.
    let (NamedOrBlankNode::NamedNode(subject), GraphName::NamedNode(graph)) =
      (&quad.subject, &quad.graph_name)
    else {
      continue;
    };
    if subject == graph && subject.as_ref() != owner && is_registered(t, subject.as_ref())? {
      return Err(AppError::Conflict(format!(
        "identifier `{identifier}` is already used by organization <{subject}>"
      )));
    }
  }
  Ok(())
}

fn is_registered(t: &Transaction<'_>, node: NamedNodeRef<'_>) -> AppResult<bool> {
  Ok(t.contains(QuadRef::new(
    node,
    rdf::TYPE,
    vocab::REGISTERED_ORGANIZATION,
    vocab::SYSTEM_GRAPH,
  ))?)
}

fn subject_quads(t: &Transaction<'_>, subject: NamedNodeRef<'_>) -> AppResult<Vec<Quad>> {
  Ok(
    t.quads_for_pattern(
      Some(subject.into()),
      None,
      None,
      Some(vocab::SYSTEM_GRAPH.into()),
    )
    .collect::<Result<_, _>>()?,
  )
}

fn read_issuers(
  t: &Transaction<'_>,
  organization: NamedNodeRef<'_>,
) -> AppResult<Vec<StoredIssuer>> {
  let mut issuers = Vec::new();
  for link in subject_quads(t, organization)? {
    let (vocab::HAS_ISSUER, Term::NamedNode(node)) = (link.predicate.as_ref(), &link.object) else {
      continue;
    };
    let mut issuer = StoredIssuer {
      id: String::new(),
      issuer: String::new(),
      token_validation: ValidationMethod::Jwks,
      audience: None,
      client_id: None,
      client_secret: None,
    };
    for quad in subject_quads(t, node.as_ref())? {
      let Term::Literal(value) = quad.object else {
        continue;
      };
      let value = value.value().to_owned();
      match quad.predicate.as_ref() {
        vocab::ISSUER_ID => issuer.id = value,
        vocab::ISSUER => issuer.issuer = value,
        vocab::CLIENT_ID => issuer.client_id = Some(value),
        vocab::AUDIENCE => issuer.audience = Some(value),
        vocab::CLIENT_SECRET => issuer.client_secret = Some(ClientSecret::new(value)),
        _ => {}
      }
    }
    issuer.token_validation = validation_method(&issuer.client_secret);
    issuers.push(issuer);
  }
  issuers.sort_by(|a, b| a.issuer.cmp(&b.issuer));
  Ok(issuers)
}

// ---- RDF mapping of organizations ----

fn organization_quads(node: &NamedNode, org: &Organization) -> Vec<Quad> {
  let graph = GraphName::NamedNode(node.clone());
  let mut quads = Vec::new();
  let mut add = |subject: &NamedNode, predicate: NamedNodeRef<'_>, object: Term| {
    quads.push(Quad::new(subject.clone(), predicate, object, graph.clone()));
  };
  let text = |value: &str| Term::from(Literal::from(value));
  let child = |fragment: &str| NamedNode::new_unchecked(format!("{}#{fragment}", node.as_str()));

  add(node, rdf::TYPE, schema::ORGANIZATION.into());
  add(node, schema::IDENTIFIER, text(&org.identifier.to_string()));
  add(node, schema::NAME, text(&org.name));
  if let Some(legal_name) = &org.legal_name {
    add(node, schema::LEGAL_NAME, text(legal_name));
  }
  if let Some(logo) = &org.logo {
    add(
      node,
      schema::LOGO,
      NamedNode::new_unchecked(logo.as_str()).into(),
    );
  }

  let add_postal_address = |add: &mut dyn FnMut(&NamedNode, NamedNodeRef<'_>, Term),
                            subject: &NamedNode,
                            address: &PostalAddress| {
    add(subject, rdf::TYPE, schema::POSTAL_ADDRESS.into());
    for (name, value) in address.fields() {
      if let Some(value) = value {
        let predicate = NamedNode::new_unchecked(format!("{}{name}", schema::NS));
        add(subject, predicate.as_ref(), text(value));
      }
    }
  };

  match &org.location {
    None => {}
    Some(Location::Text(value)) => add(node, schema::LOCATION, text(value)),
    Some(Location::PostalAddress(address)) => {
      let location = child("location");
      add(node, schema::LOCATION, location.clone().into());
      add_postal_address(&mut add, &location, address);
    }
    Some(Location::Place(place)) => {
      let location = child("location");
      add(node, schema::LOCATION, location.clone().into());
      add(&location, rdf::TYPE, schema::PLACE.into());
      if let Some(name) = &place.name {
        add(&location, schema::NAME, text(name));
      }
      match &place.address {
        None => {}
        Some(Address::Text(value)) => add(&location, schema::ADDRESS, text(value)),
        Some(Address::PostalAddress(address)) => {
          let address_node = child("address");
          add(&location, schema::ADDRESS, address_node.clone().into());
          add_postal_address(&mut add, &address_node, address);
        }
      }
    }
  }
  quads
}

/// Triples of a named graph indexed by subject IRI.
#[derive(Default)]
struct Graph(HashMap<String, Vec<(NamedNode, Term)>>);

impl Graph {
  fn objects<'a>(
    &'a self,
    subject: &str,
    predicate: NamedNodeRef<'a>,
  ) -> impl Iterator<Item = TermRef<'a>> {
    self
      .0
      .get(subject)
      .into_iter()
      .flatten()
      .filter(move |(p, _)| p.as_ref() == predicate)
      .map(|(_, o)| o.as_ref())
  }

  fn literal(&self, subject: &str, predicate: NamedNodeRef<'_>) -> Option<String> {
    self
      .objects(subject, predicate)
      .find_map(|term| match term {
        TermRef::Literal(l) => Some(l.value().to_owned()),
        _ => None,
      })
  }

  fn has_type(&self, subject: &str, class: NamedNodeRef<'_>) -> bool {
    self.objects(subject, rdf::TYPE).any(|t| t == class.into())
  }

  fn organization(&self, iri: &str) -> Option<Organization> {
    if !self.has_type(iri, schema::ORGANIZATION) {
      return None;
    }
    let location = match self.objects(iri, schema::LOCATION).next() {
      None => None,
      Some(TermRef::Literal(l)) => Some(Location::Text(l.value().to_owned())),
      Some(TermRef::NamedNode(n)) if self.has_type(n.as_str(), schema::PLACE) => {
        let address = match self.objects(n.as_str(), schema::ADDRESS).next() {
          None => None,
          Some(TermRef::Literal(l)) => Some(Address::Text(l.value().to_owned())),
          Some(TermRef::NamedNode(a)) => {
            Some(Address::PostalAddress(self.postal_address(a.as_str())))
          }
          Some(_) => return None,
        };
        Some(Location::Place(Place {
          kind: PlaceType::Place,
          name: self.literal(n.as_str(), schema::NAME),
          address,
        }))
      }
      Some(TermRef::NamedNode(n)) => Some(Location::PostalAddress(self.postal_address(n.as_str()))),
      Some(_) => return None,
    };
    Some(Organization {
      identifier: self.literal(iri, schema::IDENTIFIER)?.parse().ok()?,
      name: self.literal(iri, schema::NAME)?,
      legal_name: self.literal(iri, schema::LEGAL_NAME),
      location,
      logo: self.objects(iri, schema::LOGO).find_map(|term| match term {
        TermRef::NamedNode(n) => Url::parse(n.as_str()).ok(),
        _ => None,
      }),
    })
  }

  fn postal_address(&self, subject: &str) -> PostalAddress {
    let mut address = PostalAddress {
      kind: PostalAddressType::PostalAddress,
      ..Default::default()
    };
    for (predicate, object) in self.0.get(subject).into_iter().flatten() {
      if let (Some(name), Term::Literal(value)) =
        (predicate.as_str().strip_prefix(schema::NS), object)
        && let Some(field) = address.field_mut(name)
      {
        *field = Some(value.value().to_owned());
      }
    }
    address
  }
}
