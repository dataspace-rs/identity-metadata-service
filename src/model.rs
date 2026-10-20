//! JSON-LD representation of the identity metadata, based on schema.org `Organization`.

use identity_metadata_commons::PartyId;
use serde_json::Value;
use url::Url;

use crate::error::AppError;

pub use identity_metadata_commons::{
  Address, Location, OrganizationDocument, OrganizationGraph, OrganizationType, Place, PlaceType,
  PostalAddress, PostalAddressType, SCHEMA_ORG_CONTEXT,
};

/// JSON-LD contexts accepted on input; they all map terms to the schema.org vocabulary.
const ACCEPTED_CONTEXTS: &[&str] = &[
  "https://schema.org",
  "https://schema.org/",
  "http://schema.org",
  "http://schema.org/",
];

/// Validated identity metadata of an organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Organization {
  pub identifier: PartyId,
  pub name: String,
  pub legal_name: Option<String>,
  pub location: Option<Location>,
  pub logo: Option<Url>,
}

impl Organization {
  pub fn into_document(self, id: String) -> OrganizationDocument {
    OrganizationDocument {
      context: Some(Value::String(SCHEMA_ORG_CONTEXT.to_owned())),
      id: Some(id),
      kind: OrganizationType::Organization,
      identifier: self.identifier.to_string(),
      name: self.name,
      legal_name: self.legal_name,
      location: self.location,
      logo: self.logo.map(String::from),
    }
  }
}

impl TryFrom<OrganizationDocument> for Organization {
  type Error = AppError;

  fn try_from(doc: OrganizationDocument) -> Result<Self, Self::Error> {
    let invalid = |msg: String| AppError::Unprocessable(msg);

    if !doc
      .context
      .as_ref()
      .and_then(Value::as_str)
      .is_some_and(|c| ACCEPTED_CONTEXTS.contains(&c))
    {
      return Err(invalid(format!(
        "`@context` must be \"{SCHEMA_ORG_CONTEXT}\""
      )));
    }
    let identifier: PartyId = doc
      .identifier
      .parse()
      .map_err(|e| invalid(format!("`identifier`: {e}")))?;
    let name = non_blank("name", doc.name)?;
    let legal_name = doc
      .legal_name
      .map(|v| non_blank("legalName", v))
      .transpose()?;
    let logo = doc
      .logo
      .map(|logo| {
        Url::parse(&logo)
          .ok()
          .filter(|url| matches!(url.scheme(), "http" | "https"))
          .ok_or_else(|| invalid("`logo` must be an absolute http(s) URL".into()))
      })
      .transpose()?;
    let location = doc.location.map(validate_location).transpose()?;

    Ok(Self {
      identifier,
      name,
      legal_name,
      location,
      logo,
    })
  }
}

const MAX_TEXT_LEN: usize = 1024;

fn non_blank(field: &str, value: String) -> Result<String, AppError> {
  let value = value.trim();
  if value.is_empty() {
    return Err(AppError::Unprocessable(format!(
      "`{field}` must not be empty"
    )));
  }
  if value.chars().count() > MAX_TEXT_LEN {
    return Err(AppError::Unprocessable(format!(
      "`{field}` must be at most {MAX_TEXT_LEN} characters"
    )));
  }
  Ok(value.to_owned())
}

fn validate_postal_address(mut address: PostalAddress) -> Result<PostalAddress, AppError> {
  for (name, _) in PostalAddress::default().fields() {
    let field = address.field_mut(name).expect("known field");
    *field = field.take().map(|v| non_blank(name, v)).transpose()?;
  }
  if address.fields().iter().all(|(_, v)| v.is_none()) {
    return Err(AppError::Unprocessable(
      "`PostalAddress` must have at least one property".into(),
    ));
  }
  Ok(address)
}

fn validate_location(location: Location) -> Result<Location, AppError> {
  Ok(match location {
    Location::Text(text) => Location::Text(non_blank("location", text)?),
    Location::PostalAddress(address) => Location::PostalAddress(validate_postal_address(address)?),
    Location::Place(place) => {
      let name = place
        .name
        .map(|n| non_blank("location.name", n))
        .transpose()?;
      let address = match place.address {
        Some(Address::Text(text)) => Some(Address::Text(non_blank("location.address", text)?)),
        Some(Address::PostalAddress(a)) => {
          Some(Address::PostalAddress(validate_postal_address(a)?))
        }
        None => None,
      };
      if name.is_none() && address.is_none() {
        return Err(AppError::Unprocessable(
          "`Place` must have a `name` or an `address`".into(),
        ));
      }
      Location::Place(Place {
        kind: PlaceType::Place,
        name,
        address,
      })
    }
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use serde_json::json;

  fn parse(value: Value) -> Result<Organization, AppError> {
    let doc: OrganizationDocument =
      serde_json::from_value(value).map_err(|e| AppError::BadRequest(e.to_string()))?;
    doc.try_into()
  }

  #[test]
  fn parses_full_document() {
    let org = parse(json!({
            "@context": "https://schema.org",
            "@type": "Organization",
            "identifier": "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0002:552100554",
            "name": "ACME",
            "legalName": "ACME SAS",
            "logo": "https://acme.example/logo.png",
            "location": {
                "@type": "Place",
                "name": "HQ",
                "address": {"@type": "PostalAddress", "addressLocality": "Paris", "addressCountry": "FR"}
            }
        }))
        .unwrap();
    assert_eq!(org.name, "ACME");
    assert!(matches!(org.location, Some(Location::Place(_))));
  }

  #[test]
  fn rejects_invalid_documents() {
    let base = json!({
        "@context": "https://schema.org",
        "@type": "Organization",
        "identifier": "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0002:552100554",
        "name": "ACME"
    });
    let with = |key: &str, value: Value| {
      let mut doc = base.clone();
      doc[key] = value;
      doc
    };
    assert!(parse(base.clone()).is_ok());
    assert!(parse(with("@type", json!("Person"))).is_err());
    assert!(parse(with("@context", json!("https://example.org"))).is_err());
    assert!(parse(with("identifier", json!("urn:x:y"))).is_err());
    assert!(parse(with("name", json!("  "))).is_err());
    assert!(parse(with("logo", json!("ftp://example.org/logo.png"))).is_err());
    assert!(parse(with("unknown", json!("x"))).is_err());
    assert!(parse(with("location", json!({"@type": "Place"}))).is_err());
    assert!(parse(with("location", json!({"@type": "City", "name": "Paris"}))).is_err());
  }
}
