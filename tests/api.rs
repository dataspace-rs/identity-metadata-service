use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;

use axum::body::Body;
use axum::extract::Form;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use identity_metadata_service::config::{Config, RootIdentity};
use identity_metadata_service::{AppState, app};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use oauth2::ClientSecret;
use oxigraph::store::Store;
use serde_json::{Value, json};
use tower::ServiceExt;

const IDENTIFIER: &str = "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0002:552100554";
const OTHER_IDENTIFIER: &str = "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088:4035811991021";
/// An organization id that is never registered.
const UNKNOWN_ID: &str = "00000000-0000-4000-8000-000000000000";
/// Secret of the OAuth 2.0 clients of the service at the mock providers.
const CLIENT_SECRET: &str = "s3cret";

/// An opaque access token, recognized by the mock provider of `issuer`.
fn opaque_token(issuer: &str, subject: &str) -> String {
  format!("opaque|{issuer}|{subject}")
}

/// A JWT access token (unsigned: only the provider's introspection answer matters).
fn jwt_token(issuer: &str, subject: &str) -> String {
  let encode = |value: Value| URL_SAFE_NO_PAD.encode(value.to_string());
  format!(
    "{}.{}.signature",
    encode(json!({"alg": "RS256", "typ": "at+jwt"})),
    encode(json!({"iss": issuer, "sub": subject}))
  )
}

/// Audience of the tokens of the mock providers, except for the subject `other-audience`.
const AUDIENCE: &str = "ims-api";
/// Id of the signing key of the mock providers.
const KEY_ID: &str = "key-1";

/// The Ed25519 signing key of the mock provider of `issuer`, distinct for each provider.
fn signing_key(issuer: &str) -> SigningKey {
  let mut seed = [7u8; 32];
  for (i, byte) in issuer.bytes().enumerate() {
    seed[i % 32] ^= byte.wrapping_mul(i as u8 + 1);
  }
  SigningKey::from_bytes(&seed)
}

/// A JWT access token for `AUDIENCE`, signed with the key of the mock provider of `signer`,
/// expiring in `expires_in` seconds.
fn signed_token(signer: &str, issuer: &str, subject: &str, expires_in: i64) -> String {
  let mut claims = token_claims(issuer, subject, expires_in);
  claims["aud"] = json!(AUDIENCE);
  sign(signer, &claims)
}

fn token_claims(issuer: &str, subject: &str, expires_in: i64) -> Value {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs() as i64;
  json!({"iss": issuer, "sub": subject, "client_id": "some-app", "iat": now, "exp": now + expires_in})
}

/// Signs `claims` with the key of the mock provider of `signer`.
fn sign(signer: &str, claims: &Value) -> String {
  // PKCS#8 v1 encoding of an Ed25519 private key (RFC 8410).
  let mut der = vec![
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ];
  der.extend_from_slice(signing_key(signer).as_bytes());
  let mut header = Header::new(Algorithm::EdDSA);
  header.kid = Some(KEY_ID.into());
  header.typ = Some("at+jwt".into());
  jsonwebtoken::encode(&header, claims, &EncodingKey::from_ed_der(&der)).unwrap()
}

/// Subject of a token issued by the mock provider of `issuer`, unless revoked.
fn token_subject(issuer: &str, token: &str) -> Option<String> {
  let (token_issuer, subject) = match token.split('|').collect::<Vec<_>>().as_slice() {
    ["opaque", iss, sub] => (iss.to_string(), sub.to_string()),
    _ => {
      let payload = token.split('.').nth(1)?;
      let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
      (
        claims["iss"].as_str()?.to_owned(),
        claims["sub"].as_str()?.to_owned(),
      )
    }
  };
  (token_issuer == issuer && subject != "revoked").then_some(subject)
}

/// Starts a minimal OpenID provider with an RFC 7662 introspection endpoint and a key set.
async fn start_identity_provider() -> String {
  let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
  let issuer = format!("http://{}", listener.local_addr().unwrap());

  let configuration = json!({
      "issuer": issuer,
      "introspection_endpoint": format!("{issuer}/introspect"),
      "jwks_uri": format!("{issuer}/jwks"),
  });
  let jwks = json!({"keys": [
      // Keys for encryption, or of unsupported types, are ignored.
      {"kty": "RSA", "use": "enc", "kid": "enc", "n": "AQAB", "e": "AQAB"},
      {"kty": "unknown", "kid": "other"},
      {
          "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": KEY_ID,
          "x": URL_SAFE_NO_PAD.encode(signing_key(&issuer).verifying_key().as_bytes()),
      },
  ]});
  let introspection_issuer = issuer.clone();
  let router = Router::new()
    .route(
      "/.well-known/openid-configuration",
      get(move || async move { Json(configuration) }),
    )
    .route("/jwks", get(move || async move { Json(jwks) }))
    .route(
      "/introspect",
      post(
        move |headers: HeaderMap, Form(form): Form<HashMap<String, String>>| {
          let issuer = introspection_issuer.clone();
          async move {
            // The service must authenticate with its client credentials.
            let authenticated = headers
              .get(header::AUTHORIZATION)
              .and_then(|v| v.to_str().ok()?.strip_prefix("Basic "))
              .and_then(|v| String::from_utf8(STANDARD.decode(v).ok()?).ok())
              .is_some_and(|v| v.ends_with(&format!(":{CLIENT_SECRET}")));
            if !authenticated {
              return StatusCode::UNAUTHORIZED.into_response();
            }
            let now = SystemTime::now()
              .duration_since(UNIX_EPOCH)
              .unwrap()
              .as_secs();
            match form.get("token").and_then(|t| token_subject(&issuer, t)) {
              Some(sub) => Json(json!({
                  "active": true,
                  "iss": issuer,
                  "sub": sub,
                  "client_id": "some-app",
                  "aud": if sub == "other-audience" { "other-api" } else { AUDIENCE },
                  "exp": now + 300,
              })),
              None => Json(json!({ "active": false })),
            }
            .into_response()
          }
        },
      ),
    );
  tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
  issuer
}

fn test_app(root_issuer: &str) -> Router {
  test_app_with_client(root_issuer, true)
}

/// The application, validating the tokens of the root issuer by introspection with a client,
/// or with its keys.
fn test_app_with_client(root_issuer: &str, with_client: bool) -> Router {
  let config = Config {
    bind: "127.0.0.1:0".parse().unwrap(),
    data_dir: None,
    public_base_url: "https://ims.example/".parse().unwrap(),
    root: RootIdentity {
      issuer: root_issuer.into(),
      client_id: with_client.then(|| "ims".into()),
      client_secret: with_client.then(|| ClientSecret::new(CLIENT_SECRET.into())),
      audience: None,
      admins: vec!["root-admin".into()],
    },
    allow_insecure_issuers: true,
  };
  app(AppState::new(&config, Store::new().unwrap()))
}

struct Client {
  app: Router,
}

impl Client {
  async fn call(
    &self,
    method: Method,
    uri: &str,
    token: Option<&str>,
    content_type: &str,
    body: Option<Value>,
  ) -> (StatusCode, HeaderMap, Value) {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
      request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let body = match body {
      Some(body) => {
        request = request.header(header::CONTENT_TYPE, content_type);
        Body::from(body.to_string())
      }
      None => Body::empty(),
    };
    let response = self
      .app
      .clone()
      .oneshot(request.body(body).unwrap())
      .await
      .unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (parts.status, parts.headers, value)
  }

  async fn get(&self, uri: &str) -> (StatusCode, HeaderMap, Value) {
    self.call(Method::GET, uri, None, "", None).await
  }

  async fn json(
    &self,
    method: Method,
    uri: &str,
    token: &str,
    body: Option<Value>,
  ) -> (StatusCode, Value) {
    let (status, _, body) = self
      .call(method, uri, Some(token), "application/json", body)
      .await;
    (status, body)
  }

  async fn json_ld(
    &self,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Value,
  ) -> (StatusCode, HeaderMap, Value) {
    self
      .call(method, uri, token, "application/ld+json", Some(body))
      .await
  }
}

fn organization(name: &str) -> Value {
  organization_with_id(IDENTIFIER, name)
}

fn organization_with_id(identifier: &str, name: &str) -> Value {
  json!({
      "@context": "https://schema.org",
      "@type": "Organization",
      "identifier": identifier,
      "name": name,
      "legalName": "ACME SAS",
      "logo": "https://acme.example/logo.png",
      "location": {
          "@type": "Place",
          "name": "Head office",
          "address": {
              "@type": "PostalAddress",
              "streetAddress": "1 rue de la Paix",
              "postalCode": "75002",
              "addressLocality": "Paris",
              "addressCountry": "FR"
          }
      }
  })
}

#[tokio::test]
async fn full_lifecycle() {
  let root_issuer = start_identity_provider().await;
  let org_issuer = start_identity_provider().await;
  let client = Client {
    app: test_app(&root_issuer),
  };
  let admin = opaque_token(&root_issuer, "root-admin");
  let admin_jwt = jwt_token(&root_issuer, "root-admin");
  let writer = opaque_token(&org_issuer, "alice");
  let writer_jwt = jwt_token(&org_issuer, "alice");

  // Administration requires an active token of the root identity, for an allowed subject.
  let (status, headers, _) = client
    .call(Method::GET, "/admin/organizations", None, "", None)
    .await;
  assert_eq!(status, StatusCode::UNAUTHORIZED);
  assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
  for (token, expected) in [
    (opaque_token(&root_issuer, "mallory"), StatusCode::FORBIDDEN),
    (
      opaque_token(&root_issuer, "revoked"),
      StatusCode::UNAUTHORIZED,
    ),
    (
      jwt_token("https://untrusted.example", "root-admin"),
      StatusCode::UNAUTHORIZED,
    ),
    (writer.clone(), StatusCode::UNAUTHORIZED),
    (writer_jwt.clone(), StatusCode::UNAUTHORIZED),
    (admin.clone(), StatusCode::OK),
    (admin_jwt.clone(), StatusCode::OK),
  ] {
    let (status, body) = client
      .json(Method::GET, "/admin/organizations", &token, None)
      .await;
    assert_eq!(status, expected, "{token}: {body}");
  }

  // Only administrators register organizations.
  let (status, _, _) = client
    .json_ld(
      Method::POST,
      "/admin/organizations",
      None,
      organization("ACME"),
    )
    .await;
  assert_eq!(status, StatusCode::UNAUTHORIZED);
  let mut invalid = organization("ACME");
  invalid["identifier"] = json!("urn:oasis:names:tc:ebcore:partyid-type:iso6523:0002:552100555");
  let (status, _, body) = client
    .json_ld(Method::POST, "/admin/organizations", Some(&admin), invalid)
    .await;
  assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
  assert!(
    body["detail"].as_str().unwrap().contains("check digit"),
    "{body}"
  );
  let (status, headers, created) = client
    .json_ld(
      Method::POST,
      "/admin/organizations",
      Some(&admin),
      organization("ACME"),
    )
    .await;
  assert_eq!(status, StatusCode::CREATED, "{created}");
  // The organization is identified by a UUID assigned by the server.
  let iri = headers[header::LOCATION].to_str().unwrap().to_owned();
  let id = iri
    .strip_prefix("https://ims.example/organizations/")
    .unwrap()
    .to_owned();
  assert_eq!(uuid::Uuid::parse_str(&id).unwrap().get_version_num(), 4);
  let org_url = format!("/organizations/{id}");
  let mut expected = organization("ACME");
  expected["@id"] = json!(iri);
  assert_eq!(created, expected);
  // The `identifier` is unique among organizations.
  let (status, _, body) = client
    .json_ld(
      Method::POST,
      "/admin/organizations",
      Some(&admin),
      organization("ACME"),
    )
    .await;
  assert_eq!(status, StatusCode::CONFLICT, "{body}");

  // Public read.
  let (status, headers, fetched) = client.get(&org_url).await;
  assert_eq!(status, StatusCode::OK);
  assert_eq!(headers[header::CONTENT_TYPE], "application/ld+json");
  assert_eq!(fetched, expected);
  let (status, _, _) = client.get(&format!("/organizations/{UNKNOWN_ID}")).await;
  assert_eq!(status, StatusCode::NOT_FOUND);
  for invalid in ["not-a-uuid", IDENTIFIER] {
    let (status, _, _) = client.get(&format!("/organizations/{invalid}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}");
  }

  // No trusted issuer yet: the organization's tokens are rejected.
  let (status, _, _) = client
    .json_ld(Method::PUT, &org_url, Some(&writer), organization("ACME"))
    .await;
  assert_eq!(status, StatusCode::UNAUTHORIZED);

  // Register the organization's identity provider.
  let issuers_url = format!("/admin/organizations/{id}/issuers");
  let (status, _) = client
    .json(
      Method::POST,
      &issuers_url,
      &admin,
      Some(json!({"issuer": org_issuer, "clientId": "ims"})),
    )
    .await;
  assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
  let new_issuer = |issuer: &str| json!({"issuer": issuer, "audience": AUDIENCE, "clientId": "ims", "clientSecret": CLIENT_SECRET});
  let (status, body) = client
    .json(
      Method::POST,
      &issuers_url,
      &admin,
      Some(new_issuer("http://127.0.0.1:1")),
    )
    .await;
  assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
  let (status, _) = client
    .json(
      Method::POST,
      &format!("/admin/organizations/{UNKNOWN_ID}/issuers"),
      &admin,
      Some(new_issuer(&org_issuer)),
    )
    .await;
  assert_eq!(status, StatusCode::NOT_FOUND);
  let (status, registered) = client
    .json(
      Method::POST,
      &issuers_url,
      &admin,
      Some(new_issuer(&org_issuer)),
    )
    .await;
  assert_eq!(status, StatusCode::CREATED, "{registered}");
  assert_eq!(registered["clientId"], "ims");
  assert_eq!(registered["tokenValidation"], "introspection");
  assert_eq!(registered["audience"], AUDIENCE);
  assert!(registered.get("clientSecret").is_none());
  let (status, _) = client
    .json(
      Method::POST,
      &issuers_url,
      &admin,
      Some(new_issuer(&org_issuer)),
    )
    .await;
  assert_eq!(status, StatusCode::CONFLICT);
  let (status, issuers) = client.json(Method::GET, &issuers_url, &admin, None).await;
  assert_eq!((status, issuers), (StatusCode::OK, json!([registered])));

  // Tokens for another audience are rejected.
  let (status, _, _) = client
    .json_ld(
      Method::PUT,
      &org_url,
      Some(&opaque_token(&org_issuer, "other-audience")),
      organization("ACME"),
    )
    .await;
  assert_eq!(status, StatusCode::UNAUTHORIZED);

  // Unauthenticated updates are rejected before the body is looked at.
  let (status, _, _) = client
    .json_ld(Method::PUT, &org_url, None, organization("ACME"))
    .await;
  assert_eq!(status, StatusCode::UNAUTHORIZED);
  let (status, _, _) = client.json_ld(Method::PUT, &org_url, None, json!({})).await;
  assert_eq!(status, StatusCode::UNAUTHORIZED);
  let revoked = opaque_token(&org_issuer, "revoked");
  let (status, _, _) = client
    .json_ld(Method::PUT, &org_url, Some(&revoked), organization("ACME"))
    .await;
  assert_eq!(status, StatusCode::UNAUTHORIZED);

  // Body validation.
  let (status, _, _) = client
    .call(
      Method::PUT,
      &org_url,
      Some(&writer),
      "text/plain",
      Some(organization("ACME")),
    )
    .await;
  assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
  let (status, _, _) = client
    .json_ld(Method::PUT, &org_url, Some(&writer), organization(" "))
    .await;
  assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

  // The `identifier` may change, as long as no other organization uses it.
  let (status, _, updated) = client
    .json_ld(
      Method::PUT,
      &org_url,
      Some(&writer),
      organization_with_id(OTHER_IDENTIFIER, "ACME"),
    )
    .await;
  assert_eq!(status, StatusCode::OK, "{updated}");
  assert_eq!(updated["identifier"], OTHER_IDENTIFIER);
  let (status, headers, _) = client
    .json_ld(
      Method::POST,
      "/admin/organizations",
      Some(&admin),
      organization("Other"),
    )
    .await;
  assert_eq!(status, StatusCode::CREATED);
  let (status, _, body) = client
    .json_ld(Method::PUT, &org_url, Some(&writer), organization("ACME"))
    .await;
  assert_eq!(status, StatusCode::CONFLICT, "{body}");
  let (status, _) = client
    .json(
      Method::DELETE,
      headers[header::LOCATION]
        .to_str()
        .unwrap()
        .strip_prefix("https://ims.example")
        .map(|path| format!("/admin{path}"))
        .as_deref()
        .unwrap(),
      &admin,
      None,
    )
    .await;
  assert_eq!(status, StatusCode::NO_CONTENT);

  // Update with opaque and JWT tokens of the organization's issuer; the update replaces the
  // whole record.
  let update = json!({
      "@context": "https://schema.org",
      "@type": "Organization",
      "identifier": IDENTIFIER,
      "name": "ACME Group",
      "location": "Paris, France"
  });
  for token in [&writer, &writer_jwt] {
    let (status, _, updated) = client
      .json_ld(Method::PUT, &org_url, Some(token), update.clone())
      .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
  }
  let (_, _, fetched) = client.get(&org_url).await;
  let mut expected = update.clone();
  expected["@id"] = json!(iri);
  assert_eq!(fetched, expected);

  // Administrators may update any organization; other root users may not.
  let (status, _, _) = client
    .json_ld(Method::PUT, &org_url, Some(&admin_jwt), update.clone())
    .await;
  assert_eq!(status, StatusCode::OK);
  let mallory = opaque_token(&root_issuer, "mallory");
  let (status, _, _) = client
    .json_ld(Method::PUT, &org_url, Some(&mallory), update.clone())
    .await;
  assert_eq!(status, StatusCode::FORBIDDEN);
  let (status, _, _) = client
    .json_ld(
      Method::PUT,
      &format!("/organizations/{UNKNOWN_ID}"),
      Some(&admin),
      organization_with_id(OTHER_IDENTIFIER, "Other"),
    )
    .await;
  assert_eq!(status, StatusCode::NOT_FOUND);

  let (status, list) = client
    .json(Method::GET, "/admin/organizations", &admin, None)
    .await;
  assert_eq!(status, StatusCode::OK);
  assert_eq!(
    list["@graph"],
    json!([{
        "@id": iri, "@type": "Organization", "identifier": IDENTIFIER,
        "name": "ACME Group", "location": "Paris, France"
    }])
  );

  // Unregistering the issuer revokes the write access of its tokens.
  let issuer_id = registered["id"].as_str().unwrap();
  let (status, _) = client
    .json(
      Method::DELETE,
      &format!("{issuers_url}/{issuer_id}"),
      &admin,
      None,
    )
    .await;
  assert_eq!(status, StatusCode::NO_CONTENT);
  let (status, _, _) = client
    .json_ld(Method::PUT, &org_url, Some(&writer), update)
    .await;
  assert_eq!(status, StatusCode::UNAUTHORIZED);

  // Deleting the organization.
  let (status, _) = client
    .json(
      Method::DELETE,
      &format!("/admin/organizations/{id}"),
      &admin,
      None,
    )
    .await;
  assert_eq!(status, StatusCode::NO_CONTENT);
  let (status, _, _) = client.get(&org_url).await;
  assert_eq!(status, StatusCode::NOT_FOUND);
  let (_, list) = client
    .json(Method::GET, "/admin/organizations", &admin, None)
    .await;
  assert_eq!(list["@graph"], json!([]));
}

#[tokio::test]
async fn organizations_are_isolated() {
  let root_issuer = start_identity_provider().await;
  let first_issuer = start_identity_provider().await;
  let second_issuer = start_identity_provider().await;
  let other_issuer = start_identity_provider().await;
  let client = Client {
    app: test_app(&root_issuer),
  };
  let admin = opaque_token(&root_issuer, "root-admin");

  let mut ids = HashMap::new();
  for identifier in [IDENTIFIER, OTHER_IDENTIFIER] {
    let (status, _, created) = client
      .json_ld(
        Method::POST,
        "/admin/organizations",
        Some(&admin),
        organization_with_id(identifier, "x"),
      )
      .await;
    assert_eq!(status, StatusCode::CREATED);
    let iri = created["@id"].as_str().unwrap();
    ids.insert(identifier, iri.rsplit('/').next().unwrap().to_owned());
  }
  for (identifier, issuer) in [
    (IDENTIFIER, &first_issuer),
    (IDENTIFIER, &second_issuer),
    (OTHER_IDENTIFIER, &other_issuer),
  ] {
    let (status, body) = client
      .json(
        Method::POST,
        &format!("/admin/organizations/{}/issuers", ids[identifier]),
        &admin,
        Some(json!({"issuer": issuer, "clientId": "ims", "clientSecret": CLIENT_SECRET})),
      )
      .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
  }

  let first_url = format!("/organizations/{}", ids[IDENTIFIER]);
  let other_url = format!("/organizations/{}", ids[OTHER_IDENTIFIER]);
  // Tokens of every trusted issuer of an organization are accepted, opaque or JWT.
  for token in [
    opaque_token(&first_issuer, "alice"),
    opaque_token(&second_issuer, "bob"),
    jwt_token(&second_issuer, "bob"),
  ] {
    let (status, _, _) = client
      .json_ld(Method::PUT, &first_url, Some(&token), organization("ACME"))
      .await;
    assert_eq!(status, StatusCode::OK, "{token}");
  }
  // ... but not for another organization.
  for token in [
    opaque_token(&first_issuer, "alice"),
    jwt_token(&first_issuer, "alice"),
  ] {
    let (status, _, _) = client
      .json_ld(
        Method::PUT,
        &other_url,
        Some(&token),
        organization_with_id(OTHER_IDENTIFIER, "x"),
      )
      .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{token}");
  }
  let token = opaque_token(&other_issuer, "carol");
  let (status, _, _) = client
    .json_ld(
      Method::PUT,
      &other_url,
      Some(&token),
      organization_with_id(OTHER_IDENTIFIER, "x"),
    )
    .await;
  assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn validates_jwt_with_jwks() {
  let root_issuer = start_identity_provider().await;
  let org_issuer = start_identity_provider().await;
  let client = Client {
    app: test_app_with_client(&root_issuer, false),
  };
  let admin = signed_token(&root_issuer, &root_issuer, "root-admin", 300);

  // Without client at the root issuer, only JWTs signed with its keys are accepted.
  for (token, expected) in [
    (admin.clone(), StatusCode::OK),
    (
      signed_token(&root_issuer, &root_issuer, "mallory", 300),
      StatusCode::FORBIDDEN,
    ),
    (
      signed_token(&root_issuer, &root_issuer, "root-admin", -300),
      StatusCode::UNAUTHORIZED,
    ),
    (
      signed_token(&org_issuer, &root_issuer, "root-admin", 300),
      StatusCode::UNAUTHORIZED,
    ),
    (
      signed_token(&root_issuer, &org_issuer, "root-admin", 300),
      StatusCode::UNAUTHORIZED,
    ),
    (
      jwt_token(&root_issuer, "root-admin"),
      StatusCode::UNAUTHORIZED,
    ),
    (
      opaque_token(&root_issuer, "root-admin"),
      StatusCode::UNAUTHORIZED,
    ),
    (format!("{admin}x"), StatusCode::UNAUTHORIZED),
  ] {
    let (status, body) = client
      .json(Method::GET, "/admin/organizations", &token, None)
      .await;
    assert_eq!(status, expected, "{token}: {body}");
  }

  let (status, _, created) = client
    .json_ld(
      Method::POST,
      "/admin/organizations",
      Some(&admin),
      organization("ACME"),
    )
    .await;
  assert_eq!(status, StatusCode::CREATED);
  let org_url = created["@id"]
    .as_str()
    .unwrap()
    .strip_prefix("https://ims.example")
    .unwrap()
    .to_owned();

  // An issuer trusted without client: its tokens are verified with its keys.
  let (status, registered) = client
    .json(
      Method::POST,
      &format!("/admin{org_url}/issuers"),
      &admin,
      Some(json!({"issuer": org_issuer, "audience": AUDIENCE})),
    )
    .await;
  assert_eq!(status, StatusCode::CREATED, "{registered}");
  assert_eq!(registered["tokenValidation"], "jwks");
  assert_eq!(registered["audience"], AUDIENCE);
  assert!(registered.get("clientId").is_none());

  for (token, expected) in [
    (
      signed_token(&org_issuer, &org_issuer, "alice", 300),
      StatusCode::OK,
    ),
    (admin.clone(), StatusCode::OK),
    (
      signed_token(&root_issuer, &org_issuer, "alice", 300),
      StatusCode::UNAUTHORIZED,
    ),
    (opaque_token(&org_issuer, "alice"), StatusCode::UNAUTHORIZED),
    // The audience is required, and must match.
    (
      sign(&org_issuer, &token_claims(&org_issuer, "alice", 300)),
      StatusCode::UNAUTHORIZED,
    ),
    (
      sign(&org_issuer, &{
        let mut claims = token_claims(&org_issuer, "alice", 300);
        claims["aud"] = json!(["other-api", AUDIENCE]);
        claims
      }),
      StatusCode::OK,
    ),
    (
      sign(&org_issuer, &{
        let mut claims = token_claims(&org_issuer, "alice", 300);
        claims["aud"] = json!("other-api");
        claims
      }),
      StatusCode::UNAUTHORIZED,
    ),
  ] {
    let (status, _, body) = client
      .json_ld(Method::PUT, &org_url, Some(&token), organization("ACME"))
      .await;
    assert_eq!(status, expected, "{token}: {body}");
  }
}

#[tokio::test]
async fn serves_openapi_and_swagger_ui() {
  let client = Client {
    app: test_app("https://login.example.com"),
  };

  let (status, headers, spec) = client.get("/openapi.json").await;
  assert_eq!(status, StatusCode::OK);
  assert_eq!(headers[header::CONTENT_TYPE], "application/json");
  assert_eq!(spec["openapi"], "3.1.0");
  let mut paths: Vec<_> = spec["paths"].as_object().unwrap().keys().cloned().collect();
  paths.sort();
  assert_eq!(
    paths,
    [
      "/admin/organizations",
      "/admin/organizations/{id}",
      "/admin/organizations/{id}/issuers",
      "/admin/organizations/{id}/issuers/{issuer_id}",
      "/health",
      "/organizations/{id}",
    ]
  );
  let organization = &spec["paths"]["/organizations/{id}"];
  assert!(organization["get"].get("security").is_none());
  assert_eq!(
    organization["put"]["security"],
    json!([{"bearer_token": []}])
  );
  assert!(organization["put"]["requestBody"]["content"]["application/ld+json"].is_object());
  assert_eq!(
    spec["components"]["securitySchemes"]["bearer_token"]["scheme"],
    "bearer"
  );
  for schema in [
    "Organization",
    "Location",
    "Place",
    "PostalAddress",
    "TrustedIssuer",
    "NewIssuer",
    "ValidationMethod",
    "ProblemDetails",
  ] {
    assert!(
      spec["components"]["schemas"][schema].is_object(),
      "{schema}"
    );
  }

  let (status, headers, _) = client.get("/swagger-ui").await;
  assert_eq!(status, StatusCode::OK);
  assert!(
    headers[header::CONTENT_TYPE]
      .to_str()
      .unwrap()
      .starts_with("text/html")
  );
}
