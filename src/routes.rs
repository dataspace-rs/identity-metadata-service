use axum::body::Bytes;
use axum::extract::{Extension, FromRequest, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::auth::Identity;
use crate::auth::TokenValidation;
use crate::error::{AppError, AppResult, ProblemDetails};
use crate::model::{Organization, OrganizationDocument, OrganizationGraph, SCHEMA_ORG_CONTEXT};
use crate::openapi;
use crate::store::StoredIssuer;
use crate::{AppState, blocking};
use identity_metadata_commons::{NewIssuer, TrustedIssuer};

pub fn router(state: AppState) -> Router {
  let admin = Router::new()
    .route(
      "/organizations",
      get(list_organizations).post(create_organization),
    )
    .route("/organizations/{id}", delete(delete_organization))
    .route(
      "/organizations/{id}/issuers",
      get(list_issuers).post(register_issuer),
    )
    .route(
      "/organizations/{id}/issuers/{issuer_id}",
      delete(unregister_issuer),
    )
    .route_layer(middleware::from_fn_with_state(state.clone(), require_admin));

  Router::new()
    .route("/health", get(health))
    .route("/openapi.json", get(openapi::openapi_json))
    .route("/swagger-ui", get(openapi::swagger_ui))
    .route(
      "/organizations/{id}",
      get(get_organization).put(update_organization),
    )
    .nest("/admin", admin)
    .layer(TraceLayer::new_for_http())
    .with_state(state)
}

/// A JSON-LD request or response body (`application/ld+json`).
pub struct JsonLd<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for JsonLd<T> {
  type Rejection = AppError;

  async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
    let media_type = req
      .headers()
      .get(header::CONTENT_TYPE)
      .and_then(|v| v.to_str().ok())
      .and_then(|v| v.split(';').next())
      .map(|v| v.trim().to_ascii_lowercase());
    if !matches!(
      media_type.as_deref(),
      Some("application/ld+json" | "application/json")
    ) {
      return Err(AppError::UnsupportedMediaType(
        "expected an `application/ld+json` body".into(),
      ));
    }
    let body = Bytes::from_request(req, state)
      .await
      .map_err(|e| AppError::BadRequest(e.body_text()))?;
    serde_json::from_slice(&body)
      .map(JsonLd)
      .map_err(|e| match e.classify() {
        serde_json::error::Category::Data => AppError::Unprocessable(e.to_string()),
        _ => AppError::BadRequest(e.to_string()),
      })
  }
}

impl<T: Serialize> IntoResponse for JsonLd<T> {
  fn into_response(self) -> Response {
    match serde_json::to_vec(&self.0) {
      Ok(body) => (
        [(
          header::CONTENT_TYPE,
          HeaderValue::from_static("application/ld+json"),
        )],
        body,
      )
        .into_response(),
      Err(e) => AppError::Internal(e.to_string()).into_response(),
    }
  }
}

fn parse_id(value: &str) -> AppResult<Uuid> {
  Uuid::parse_str(value).map_err(|e| AppError::BadRequest(format!("invalid organization id: {e}")))
}

fn not_found(id: Uuid) -> AppError {
  AppError::NotFound(format!("organization `{id}` not found"))
}

/// Liveness probe.
#[utoipa::path(
  get,
  path = "/health",
  tag = "health",
  responses((status = 200, description = "The service is up", body = String, content_type = "text/plain", example = "ok"))
)]
pub(crate) async fn health() -> &'static str {
  "ok"
}

// ---- administration ----

/// Requires a bearer token of the root identity, for an allowed administrator.
async fn require_admin(
  State(state): State<AppState>,
  mut request: Request,
  next: Next,
) -> Response {
  match state
    .authenticator()
    .authenticate_admin(request.headers())
    .await
  {
    Ok(identity) => {
      request.extensions_mut().insert(identity);
      next.run(request).await
    }
    Err(e) => e.into_response(),
  }
}

/// List the registered organizations.
#[utoipa::path(
  get,
  path = "/admin/organizations",
  tag = "administration",
  security(("bearer_token" = [])),
  responses(
    (status = 200, description = "Registered organizations", body = OrganizationGraph, content_type = "application/ld+json"),
    (status = 401, description = "Missing, invalid or expired token", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json"),
  )
)]
pub(crate) async fn list_organizations(
  State(state): State<AppState>,
) -> AppResult<JsonLd<OrganizationGraph>> {
  let repository = state.repository().clone();
  let organizations = blocking(move || repository.list_organizations()).await?;
  let graph = organizations
    .into_iter()
    .map(|(iri, org)| OrganizationDocument {
      context: None,
      ..org.into_document(iri)
    })
    .collect();
  Ok(JsonLd(OrganizationGraph {
    context: SCHEMA_ORG_CONTEXT.to_owned(),
    graph,
  }))
}

/// Register an organization with its initial identity metadata.
#[utoipa::path(
  post,
  path = "/admin/organizations",
  tag = "administration",
  security(("bearer_token" = [])),
  request_body(content = OrganizationDocument, content_type = "application/ld+json"),
  responses(
    (status = 201, description = "Organization registered", body = OrganizationDocument, content_type = "application/ld+json",
      headers(("Location" = String, description = "IRI of the organization: `<base>/organizations/<id>`"))),
    (status = 401, description = "Missing, invalid or expired token", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 409, description = "`identifier` already used by another organization", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 415, description = "Body is not `application/ld+json`", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 422, description = "Invalid document (e.g. identifier)", body = ProblemDetails, content_type = "application/problem+json"),
  )
)]
pub(crate) async fn create_organization(
  State(state): State<AppState>,
  Extension(identity): Extension<Identity>,
  JsonLd(document): JsonLd<OrganizationDocument>,
) -> AppResult<Response> {
  let org = Organization::try_from(document)?;
  let id = Uuid::new_v4();
  let repository = state.repository().clone();
  let saved = org.clone();
  let iri = blocking(move || repository.create_organization(id, &saved)).await?;
  tracing::info!(%id, identifier = %org.identifier, by = identity.name(), "organization created");

  let location =
    HeaderValue::try_from(iri.as_str()).map_err(|e| AppError::Internal(e.to_string()))?;
  Ok(
    (
      StatusCode::CREATED,
      [(header::LOCATION, location)],
      JsonLd(org.into_document(iri)),
    )
      .into_response(),
  )
}

/// Delete an organization with its trusted issuers.
#[utoipa::path(
  delete,
  path = "/admin/organizations/{id}",
  tag = "administration",
  security(("bearer_token" = [])),
  params(("id" = Uuid, Path, description = "Id of the organization, assigned at registration", example = "6f1c2b9e-3d4a-4e8b-9c1f-2a7d5e8b4c3a")),
  responses(
    (status = 204, description = "Organization deleted"),
    (status = 400, description = "Invalid organization id", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 401, description = "Missing, invalid or expired token", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 404, description = "Unknown organization", body = ProblemDetails, content_type = "application/problem+json"),
  )
)]
pub(crate) async fn delete_organization(
  State(state): State<AppState>,
  Path(id): Path<String>,
) -> AppResult<StatusCode> {
  let id = parse_id(&id)?;
  let repository = state.repository().clone();
  blocking(move || repository.delete_organization(id)).await?;
  tracing::info!(%id, "organization deleted");
  Ok(StatusCode::NO_CONTENT)
}

async fn list_trusted_issuers(state: &AppState, id: Uuid) -> AppResult<Vec<StoredIssuer>> {
  let repository = state.repository().clone();
  blocking(move || repository.list_issuers(id)?.ok_or_else(|| not_found(id))).await
}

/// List the trusted issuers of an organization.
#[utoipa::path(
  get,
  path = "/admin/organizations/{id}/issuers",
  tag = "administration",
  security(("bearer_token" = [])),
  params(("id" = Uuid, Path, description = "Id of the organization, assigned at registration", example = "6f1c2b9e-3d4a-4e8b-9c1f-2a7d5e8b4c3a")),
  responses(
    (status = 200, description = "Trusted issuers", body = Vec<TrustedIssuer>),
    (status = 400, description = "Invalid organization id", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 401, description = "Missing, invalid or expired token", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 404, description = "Unknown organization", body = ProblemDetails, content_type = "application/problem+json"),
  )
)]
pub(crate) async fn list_issuers(
  State(state): State<AppState>,
  Path(id): Path<String>,
) -> AppResult<Json<Vec<TrustedIssuer>>> {
  let issuers = list_trusted_issuers(&state, parse_id(&id)?).await?;
  Ok(Json(issuers.into_iter().map(TrustedIssuer::from).collect()))
}

/// Trust an identity provider for an organization: its tokens may update the organization.
#[utoipa::path(
  post,
  path = "/admin/organizations/{id}/issuers",
  tag = "administration",
  security(("bearer_token" = [])),
  params(("id" = Uuid, Path, description = "Id of the organization, assigned at registration", example = "6f1c2b9e-3d4a-4e8b-9c1f-2a7d5e8b4c3a")),
  request_body = NewIssuer,
  responses(
    (status = 201, description = "Issuer trusted", body = TrustedIssuer),
    (status = 400, description = "Invalid organization id", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 401, description = "Missing, invalid or expired token", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 404, description = "Unknown organization", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 409, description = "Issuer already trusted by the organization", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 422, description = "Invalid issuer, or provider unable to validate tokens (no introspection endpoint, or no signing key)", body = ProblemDetails, content_type = "application/problem+json"),
  )
)]
pub(crate) async fn register_issuer(
  State(state): State<AppState>,
  Path(id): Path<String>,
  Json(input): Json<NewIssuer>,
) -> AppResult<(StatusCode, Json<TrustedIssuer>)> {
  let id = parse_id(&id)?;
  state.authenticator().check_url(&input.issuer, "issuer")?;
  let client = match (input.client_id, input.client_secret) {
    (None, None) => None,
    (Some(client_id), Some(client_secret))
      if !client_id.trim().is_empty() && !client_secret.is_empty() =>
    {
      Some((client_id, oauth2::ClientSecret::new(client_secret)))
    }
    _ => {
      return Err(AppError::Unprocessable(
        "`clientId` and `clientSecret` must be given together, and not be empty".into(),
      ));
    }
  };
  let audience = match input.audience {
    Some(audience) if audience.trim().is_empty() => {
      return Err(AppError::Unprocessable(
        "`audience` must not be empty".into(),
      ));
    }
    audience => audience,
  };
  let issuer = StoredIssuer::new(input.issuer, audience, client);
  // Fail fast on a provider that cannot validate tokens.
  let validation = TokenValidation::new(issuer.client_id.clone(), issuer.client_secret.clone());
  state
    .authenticator()
    .check_provider(&issuer.issuer, &validation)
    .await
    .map_err(|e| match e {
      AppError::BadGateway(msg) => {
        AppError::Unprocessable(format!("invalid OpenID provider: {msg}"))
      }
      e => e,
    })?;

  let repository = state.repository().clone();
  let stored = issuer.clone();
  blocking(move || repository.add_issuer(id, &stored)).await?;
  tracing::info!(%id, issuer = %issuer.issuer, issuer_id = %issuer.id, "trusted issuer registered");
  Ok((StatusCode::CREATED, Json(issuer.into())))
}

/// Stop trusting an identity provider for an organization.
#[utoipa::path(
  delete,
  path = "/admin/organizations/{id}/issuers/{issuer_id}",
  tag = "administration",
  security(("bearer_token" = [])),
  params(
    ("id" = Uuid, Path, description = "Id of the organization, assigned at registration", example = "6f1c2b9e-3d4a-4e8b-9c1f-2a7d5e8b4c3a"),
    ("issuer_id" = String, Path, description = "Identifier of the trusted issuer registration"),
  ),
  responses(
    (status = 204, description = "Issuer no longer trusted"),
    (status = 400, description = "Invalid organization id", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 401, description = "Missing, invalid or expired token", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 403, description = "Not an administrator", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 404, description = "Unknown organization or issuer", body = ProblemDetails, content_type = "application/problem+json"),
  )
)]
pub(crate) async fn unregister_issuer(
  State(state): State<AppState>,
  Path((id, issuer_id)): Path<(String, String)>,
) -> AppResult<StatusCode> {
  let id = parse_id(&id)?;
  let repository = state.repository().clone();
  let removed = issuer_id.clone();
  blocking(move || repository.remove_issuer(id, &removed)).await?;
  tracing::info!(%id, %issuer_id, "trusted issuer unregistered");
  Ok(StatusCode::NO_CONTENT)
}

// ---- organizations ----

/// Get the identity metadata of an organization.
#[utoipa::path(
  get,
  path = "/organizations/{id}",
  tag = "organizations",
  params(("id" = Uuid, Path, description = "Id of the organization, assigned at registration", example = "6f1c2b9e-3d4a-4e8b-9c1f-2a7d5e8b4c3a")),
  responses(
    (status = 200, description = "Identity metadata", body = OrganizationDocument, content_type = "application/ld+json"),
    (status = 400, description = "Invalid organization id", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 404, description = "Unknown organization", body = ProblemDetails, content_type = "application/problem+json"),
  )
)]
pub(crate) async fn get_organization(
  State(state): State<AppState>,
  Path(id): Path<String>,
) -> AppResult<JsonLd<OrganizationDocument>> {
  let id = parse_id(&id)?;
  let repository = state.repository().clone();
  blocking(move || {
    let org = repository
      .get_organization(id)?
      .ok_or_else(|| not_found(id))?;
    Ok(JsonLd(org.into_document(repository.organization_iri(id))))
  })
  .await
}

/// Replace the identity metadata of an organization.
///
/// Requires a token of one of the organization's trusted issuers, or of an administrator.
#[utoipa::path(
  put,
  path = "/organizations/{id}",
  tag = "organizations",
  security(("bearer_token" = [])),
  params(("id" = Uuid, Path, description = "Id of the organization, assigned at registration", example = "6f1c2b9e-3d4a-4e8b-9c1f-2a7d5e8b4c3a")),
  request_body(content = OrganizationDocument, content_type = "application/ld+json",
    description = "The whole record; its `identifier` may change but must not be used by another organization"),
  responses(
    (status = 200, description = "Updated identity metadata", body = OrganizationDocument, content_type = "application/ld+json"),
    (status = 400, description = "Invalid organization id or malformed JSON", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 401, description = "Missing, invalid or expired token, or untrusted issuer", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 403, description = "Root identity user who is not an administrator", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 404, description = "Unknown organization", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 409, description = "`identifier` already used by another organization", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 415, description = "Body is not `application/ld+json`", body = ProblemDetails, content_type = "application/problem+json"),
    (status = 422, description = "Invalid document", body = ProblemDetails, content_type = "application/problem+json"),
  )
)]
pub(crate) async fn update_organization(
  State(state): State<AppState>,
  Path(id): Path<String>,
  headers: HeaderMap,
  document: Result<JsonLd<OrganizationDocument>, AppError>,
) -> AppResult<JsonLd<OrganizationDocument>> {
  let id = parse_id(&id)?;
  let issuers = list_trusted_issuers(&state, id).await?;
  let identity = state
    .authenticator()
    .authenticate_writer(&headers, id, issuers)
    .await?;
  // Authenticate before reporting any problem with the body.
  let JsonLd(document) = document?;
  let org = Organization::try_from(document)?;

  let repository = state.repository().clone();
  let saved = org.clone();
  let iri = blocking(move || repository.update_organization(id, &saved)).await?;
  tracing::info!(%id, identifier = %org.identifier, by = identity.name(), "organization updated");
  Ok(JsonLd(org.into_document(iri)))
}
