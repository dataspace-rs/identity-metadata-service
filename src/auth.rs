//! Validation of OAuth 2.0 bearer tokens issued by trusted identity providers.
//!
//! Tokens are obtained elsewhere; this service only validates them, in one of two ways per
//! issuer, both relying on the issuer's OpenID Connect Discovery document:
//! - with a client of this service at the issuer: OAuth 2.0 Token Introspection (RFC 7662,
//!   using `oauth2`) at its `introspection_endpoint`, for JWT and opaque tokens;
//! - without client: verification of the signature of JWT access tokens with the keys published
//!   at its `jwks_uri` (using `jsonwebtoken`), and of their `iss`, `exp` and `nbf` claims.
//!
//! When an audience is configured for an issuer, its tokens must also name it in their `aud`.
//!
//! - The root identity is the provider configured for the platform: its tokens administer
//!   organizations and their trusted issuers, and may update any organization.
//! - Tokens of an organization's trusted issuers may update that organization only.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{Jwk, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{DecodingKey, Validation};
use oauth2::basic::BasicClient;
use oauth2::{
  AccessToken, ClientId, ClientSecret, EndpointNotSet, EndpointSet, IntrospectionUrl,
  TokenIntrospectionResponse, reqwest,
};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::store::StoredIssuer;

/// How long discovery documents and key sets are cached.
const DISCOVERY_TTL: Duration = Duration::from_secs(300);
/// Minimal delay between two fetches of the key set of an issuer, when a token is signed by an
/// unknown key (e.g. after a key rotation).
const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// Clock skew tolerated on `exp` and `nbf`.
const LEEWAY_SECONDS: u64 = 60;

/// The trusted identity provider that issued a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Provider {
  Root,
  #[serde(rename_all = "camelCase")]
  Organization {
    /// Id of the organization.
    organization: String,
    issuer_id: String,
  },
}

/// The caller, as described by the introspection response or the claims of its token.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
  pub provider: Provider,
  pub issuer: String,
  pub subject: Option<String>,
  pub client_id: Option<String>,
}

impl Identity {
  /// A name for logs: the subject, or the client for client credentials tokens.
  pub fn name(&self) -> &str {
    self
      .subject
      .as_deref()
      .or(self.client_id.as_deref())
      .unwrap_or("unknown")
  }
}

/// How the tokens of an issuer are validated.
#[derive(Clone)]
pub enum TokenValidation {
  /// Token introspection, with the OAuth 2.0 client of this service at the issuer.
  Introspection {
    client_id: ClientId,
    client_secret: ClientSecret,
  },
  /// Signature verification of JWT access tokens with the issuer's published keys.
  Jwks,
}

impl TokenValidation {
  /// Introspection when client credentials are given, JWKS otherwise.
  pub fn new(client_id: Option<String>, client_secret: Option<ClientSecret>) -> Self {
    match (client_id, client_secret) {
      (Some(client_id), Some(client_secret)) => Self::Introspection {
        client_id: ClientId::new(client_id),
        client_secret,
      },
      _ => Self::Jwks,
    }
  }
}

/// A trusted provider, with the way its tokens are validated.
#[derive(Clone)]
struct Registration {
  provider: Provider,
  issuer: String,
  validation: TokenValidation,
  /// Audience the tokens must be intended for, if any.
  audience: Option<String>,
}

#[derive(Clone, Deserialize)]
struct ProviderMetadata {
  issuer: String,
  introspection_endpoint: Option<String>,
  jwks_uri: Option<String>,
}

#[derive(Deserialize)]
struct RawJwkSet {
  keys: Vec<serde_json::Value>,
}

/// Claims read from a verified JWT access token (RFC 9068).
#[derive(Deserialize)]
struct AccessTokenClaims {
  sub: Option<String>,
  client_id: Option<String>,
  /// Authorized party, used by some providers instead of `client_id`.
  azp: Option<String>,
}

struct CachedKeys {
  fetched_at: Instant,
  keys: Arc<Vec<Jwk>>,
}

type IntrospectionClient =
  BasicClient<EndpointNotSet, EndpointNotSet, EndpointSet, EndpointNotSet, EndpointNotSet>;

pub struct Authenticator {
  root: Registration,
  root_admins: Vec<String>,
  allow_insecure_http: bool,
  http: reqwest::Client,
  /// Discovery documents by issuer.
  discovery: RwLock<HashMap<String, (Instant, ProviderMetadata)>>,
  /// Signing keys by issuer.
  jwks: RwLock<HashMap<String, CachedKeys>>,
}

impl Authenticator {
  pub fn new(config: &Config) -> Self {
    let http = reqwest::Client::builder()
      .timeout(Duration::from_secs(10))
      // Following redirects would expose the service to SSRF (see the oauth2 documentation).
      .redirect(reqwest::redirect::Policy::none())
      .build()
      .expect("valid HTTP client configuration");
    Self {
      root: Registration {
        provider: Provider::Root,
        issuer: config.root.issuer.clone(),
        validation: TokenValidation::new(
          config.root.client_id.clone(),
          config.root.client_secret.clone(),
        ),
        audience: config.root.audience.clone(),
      },
      root_admins: config.root.admins.clone(),
      allow_insecure_http: config.allow_insecure_issuers,
      http,
      discovery: RwLock::default(),
      jwks: RwLock::default(),
    }
  }

  /// Checks that a provider URL is absolute and uses https (http only when allowed).
  pub fn check_url(&self, value: &str, field: &str) -> AppResult<Url> {
    let url = Url::parse(value)
      .map_err(|e| AppError::Unprocessable(format!("`{field}` is not a valid URL: {e}")))?;
    match url.scheme() {
      "https" => Ok(url),
      "http" if self.allow_insecure_http => Ok(url),
      _ => Err(AppError::Unprocessable(format!("`{field}` must use https"))),
    }
  }

  /// Checks that the tokens of an issuer can be validated: its discovery document must expose
  /// an introspection endpoint, or a key set with at least one signing key.
  pub async fn check_provider(&self, issuer: &str, validation: &TokenValidation) -> AppResult<()> {
    match validation {
      TokenValidation::Introspection { .. } => self.introspection_endpoint(issuer).await.map(drop),
      TokenValidation::Jwks => {
        if self.signing_keys(issuer, true).await?.is_empty() {
          return Err(AppError::BadGateway(format!(
            "the key set of `{issuer}` has no supported signing key"
          )));
        }
        Ok(())
      }
    }
  }

  /// Fetches a JSON document from a provider.
  async fn fetch_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> AppResult<T> {
    let fetch = async {
      self
        .http
        .get(url)
        .header(header::ACCEPT, "application/json")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await
    };
    let body = fetch
      .await
      .map_err(|e| AppError::BadGateway(format!("failed to fetch `{url}`: {e}")))?;
    serde_json::from_slice(&body)
      .map_err(|e| AppError::BadGateway(format!("invalid response from `{url}`: {e}")))
  }

  /// Resolves the metadata of an issuer through OpenID Connect Discovery.
  async fn metadata(&self, issuer: &str) -> AppResult<ProviderMetadata> {
    if let Some((fetched_at, metadata)) = self
      .discovery
      .read()
      .unwrap_or_else(|e| e.into_inner())
      .get(issuer)
      && fetched_at.elapsed() < DISCOVERY_TTL
    {
      return Ok(metadata.clone());
    }

    let url = format!(
      "{}/.well-known/openid-configuration",
      issuer.trim_end_matches('/')
    );
    let metadata: ProviderMetadata = self.fetch_json(&url).await?;
    if metadata.issuer != issuer {
      return Err(AppError::BadGateway(format!(
        "OpenID configuration of `{issuer}` declares issuer `{}`",
        metadata.issuer
      )));
    }
    for (field, endpoint) in [
      ("introspection_endpoint", &metadata.introspection_endpoint),
      ("jwks_uri", &metadata.jwks_uri),
    ] {
      if let Some(endpoint) = endpoint {
        self
          .check_url(endpoint, field)
          .map_err(|e| AppError::BadGateway(e.to_string()))?;
      }
    }

    self
      .discovery
      .write()
      .unwrap_or_else(|e| e.into_inner())
      .insert(issuer.to_owned(), (Instant::now(), metadata.clone()));
    Ok(metadata)
  }

  async fn introspection_endpoint(&self, issuer: &str) -> AppResult<String> {
    self
      .metadata(issuer)
      .await?
      .introspection_endpoint
      .ok_or_else(|| {
        AppError::BadGateway(format!(
          "`{issuer}` does not expose an introspection endpoint"
        ))
      })
  }

  /// Returns the signing keys published at the `jwks_uri` of an issuer. With `refresh`, the key
  /// set is fetched again unless it was fetched less than `JWKS_REFRESH_INTERVAL` ago.
  async fn signing_keys(&self, issuer: &str, refresh: bool) -> AppResult<Arc<Vec<Jwk>>> {
    if let Some(cached) = self
      .jwks
      .read()
      .unwrap_or_else(|e| e.into_inner())
      .get(issuer)
    {
      let age = cached.fetched_at.elapsed();
      let max_age = if refresh {
        JWKS_REFRESH_INTERVAL
      } else {
        DISCOVERY_TTL
      };
      if age < max_age {
        return Ok(cached.keys.clone());
      }
    }

    let jwks_uri = self
      .metadata(issuer)
      .await?
      .jwks_uri
      .ok_or_else(|| AppError::BadGateway(format!("`{issuer}` does not expose a `jwks_uri`")))?;
    let set: RawJwkSet = self.fetch_json(&jwks_uri).await?;
    // Keys of unsupported types or for encryption are skipped rather than failing the set.
    let keys: Vec<Jwk> = set
      .keys
      .into_iter()
      .filter_map(|key| serde_json::from_value::<Jwk>(key).ok())
      .filter(
        |key| !matches!(key.common.public_key_use, Some(ref u) if *u != PublicKeyUse::Signature),
      )
      .filter(|key| DecodingKey::from_jwk(key).is_ok_and(|k| is_asymmetric(k.family())))
      .collect();
    let keys = Arc::new(keys);
    self.jwks.write().unwrap_or_else(|e| e.into_inner()).insert(
      issuer.to_owned(),
      CachedKeys {
        fetched_at: Instant::now(),
        keys: keys.clone(),
      },
    );
    Ok(keys)
  }

  /// Authenticates a token of the root identity allowed to administer.
  pub async fn authenticate_admin(&self, headers: &HeaderMap) -> AppResult<Identity> {
    let identity = self
      .authenticate(headers, std::slice::from_ref(&self.root))
      .await?;
    self.check_root_admin(&identity)?;
    Ok(identity)
  }

  /// Authenticates a token allowed to update an organization: issued by one of its trusted
  /// issuers, or by the root identity to an administrator.
  pub async fn authenticate_writer(
    &self,
    headers: &HeaderMap,
    organization: Uuid,
    issuers: Vec<StoredIssuer>,
  ) -> AppResult<Identity> {
    let mut candidates: Vec<_> = issuers
      .into_iter()
      .map(|issuer| Registration {
        provider: Provider::Organization {
          organization: organization.to_string(),
          issuer_id: issuer.id,
        },
        issuer: issuer.issuer,
        validation: TokenValidation::new(issuer.client_id, issuer.client_secret),
        audience: issuer.audience,
      })
      .collect();
    candidates.push(self.root.clone());
    let identity = self.authenticate(headers, &candidates).await?;
    if identity.provider == Provider::Root {
      self.check_root_admin(&identity)?;
    }
    Ok(identity)
  }

  fn check_root_admin(&self, identity: &Identity) -> AppResult<()> {
    let allowed = self.root_admins.is_empty()
      || [&identity.subject, &identity.client_id]
        .into_iter()
        .flatten()
        .any(|name| self.root_admins.contains(name));
    if allowed {
      Ok(())
    } else {
      Err(AppError::Forbidden("not an administrator".into()))
    }
  }

  async fn authenticate(
    &self,
    headers: &HeaderMap,
    candidates: &[Registration],
  ) -> AppResult<Identity> {
    let token = bearer_token(headers)?;
    // A JWT names its issuer: it is only validated by that issuer. Opaque tokens are tried
    // against each candidate issuer validating tokens by introspection, in turn.
    let candidates: Vec<_> = match unverified_issuer(token) {
      Some(iss) => candidates.iter().filter(|r| r.issuer == iss).collect(),
      None => candidates
        .iter()
        .filter(|r| matches!(r.validation, TokenValidation::Introspection { .. }))
        .collect(),
    };
    if candidates.is_empty() {
      return Err(AppError::Unauthorized("untrusted token issuer".into()));
    }
    for registration in candidates {
      let identity = match &registration.validation {
        TokenValidation::Introspection {
          client_id,
          client_secret,
        } => {
          self
            .introspect(registration, client_id, client_secret, token)
            .await?
        }
        TokenValidation::Jwks => self.verify_jwt(registration, token).await?,
      };
      if let Some(identity) = identity {
        return Ok(identity);
      }
    }
    Err(AppError::Unauthorized("invalid or expired token".into()))
  }

  /// Returns the identity behind an active token, or `None` when the issuer rejects it.
  async fn introspect(
    &self,
    registration: &Registration,
    client_id: &ClientId,
    client_secret: &ClientSecret,
    token: &str,
  ) -> AppResult<Option<Identity>> {
    let endpoint = self.introspection_endpoint(&registration.issuer).await?;
    let client: IntrospectionClient = BasicClient::new(client_id.clone())
      .set_client_secret(client_secret.clone())
      .set_introspection_url(
        IntrospectionUrl::new(endpoint).map_err(|e| AppError::BadGateway(e.to_string()))?,
      );
    let response = client
      .introspect(&AccessToken::new(token.to_owned()))
      .request_async(&self.http)
      .await
      .map_err(|e| {
        AppError::BadGateway(format!(
          "token introspection at `{}` failed: {e}",
          registration.issuer
        ))
      })?;

    let now = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |d| d.as_secs() as i64);
    if !response.active()
      || response.iss().is_some_and(|iss| iss != registration.issuer)
      || response.exp().is_some_and(|exp| exp.timestamp() <= now)
      || registration.audience.as_ref().is_some_and(|audience| {
        !response
          .aud()
          .is_some_and(|aud| aud.iter().any(|a| a == audience))
      })
    {
      return Ok(None);
    }
    Ok(Some(Identity {
      provider: registration.provider.clone(),
      issuer: registration.issuer.clone(),
      subject: response.sub().map(String::from),
      client_id: response.client_id().map(|id| id.as_str().to_owned()),
    }))
  }

  /// Verifies a JWT access token with the keys of its issuer: returns the identity behind a
  /// valid token, or `None` when the token is not valid.
  async fn verify_jwt(
    &self,
    registration: &Registration,
    token: &str,
  ) -> AppResult<Option<Identity>> {
    let Ok(header) = jsonwebtoken::decode_header(token) else {
      return Ok(None);
    };
    // Only asymmetric algorithms: the keys are public.
    let algorithm = header.alg;
    if !is_asymmetric(algorithm.family()) {
      return Ok(None);
    }
    let issuer = &registration.issuer;
    let mut keys = self.signing_keys(issuer, false).await?;
    let known = |keys: &[Jwk]| match &header.kid {
      Some(kid) => keys.iter().any(|k| k.common.key_id.as_ref() == Some(kid)),
      None => true,
    };
    if !known(&keys) {
      // The issuer may have rotated its keys.
      keys = self.signing_keys(issuer, true).await?;
    }

    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    validation.set_required_spec_claims(&["exp", "iss"]);
    validation.validate_nbf = true;
    match &registration.audience {
      Some(audience) => {
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
      }
      None => validation.validate_aud = false,
    }
    validation.leeway = LEEWAY_SECONDS;

    let candidates = keys.iter().filter(|key| {
      header
        .kid
        .as_ref()
        .is_none_or(|kid| key.common.key_id.as_ref() == Some(kid))
        && key
          .common
          .key_algorithm
          .is_none_or(|alg| alg == KeyAlgorithm::from(algorithm))
    });
    for key in candidates {
      let Ok(decoding_key) = DecodingKey::from_jwk(key) else {
        continue;
      };
      if decoding_key.family() != algorithm.family() {
        continue;
      }
      if let Ok(data) = jsonwebtoken::decode::<AccessTokenClaims>(token, &decoding_key, &validation)
      {
        let claims = data.claims;
        return Ok(Some(Identity {
          provider: registration.provider.clone(),
          issuer: issuer.clone(),
          subject: claims.sub,
          client_id: claims.client_id.or(claims.azp),
        }));
      }
    }
    Ok(None)
  }
}

fn is_asymmetric(family: jsonwebtoken::AlgorithmFamily) -> bool {
  !matches!(family, jsonwebtoken::AlgorithmFamily::Hmac)
}

fn bearer_token(headers: &HeaderMap) -> AppResult<&str> {
  headers
    .get(header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .and_then(|value| {
      let (scheme, token) = value.split_once(' ')?;
      scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
    })
    .filter(|token| !token.is_empty())
    .ok_or_else(|| AppError::Unauthorized("missing bearer token".into()))
}

/// Reads the `iss` claim of a JWT access token without verifying it: it only selects the issuer
/// that validates the token.
fn unverified_issuer(token: &str) -> Option<String> {
  let mut parts = token.split('.');
  let (Some(_), Some(payload), Some(_), None) =
    (parts.next(), parts.next(), parts.next(), parts.next())
  else {
    return None;
  };
  let claims: serde_json::Value =
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
  claims.get("iss")?.as_str().map(String::from)
}
