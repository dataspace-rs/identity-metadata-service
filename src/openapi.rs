//! OpenAPI description of the API (generated with `utoipa`) and Swagger UI.

use std::sync::LazyLock;

use axum::http::header;
use axum::response::{Html, IntoResponse};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::routes;

#[derive(OpenApi)]
#[openapi(
  info(
    title = "Identity Metadata Service",
    description = "Publishes the public identity metadata of organizations as JSON-LD \
      (schema.org `Organization`), with an OASIS ebCore Party Id (ISO 6523) as `identifier`.\n\n\
      Write endpoints require an OAuth 2.0 bearer token of a trusted issuer: the root identity \
      for `/admin`, and the organization's trusted issuers (or the root identity) to update an \
      organization. Tokens are validated by token introspection (RFC 7662) when the service has \
      a client at the issuer, or else as JWTs signed with the keys published at the `jwks_uri` \
      of the issuer's OpenID configuration."
  ),
  paths(
    routes::get_organization,
    routes::update_organization,
    routes::list_organizations,
    routes::create_organization,
    routes::delete_organization,
    routes::list_issuers,
    routes::register_issuer,
    routes::unregister_issuer,
    routes::health,
  ),
  modifiers(&BearerSecurity),
  tags(
    (name = "organizations", description = "Public identity metadata of organizations"),
    (name = "administration", description = "Management of organizations and their trusted issuers, by the root identity"),
    (name = "health", description = "Service health"),
  )
)]
pub struct ApiDoc;

/// Name of the bearer token security scheme referenced by the paths (`security(("bearer_token" = []))`).
const BEARER: &str = "bearer_token";

struct BearerSecurity;

impl Modify for BearerSecurity {
  fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
    openapi
      .components
      .get_or_insert_with(Default::default)
      .add_security_scheme(
        BEARER,
        SecurityScheme::Http(
          HttpBuilder::new()
            .scheme(HttpAuthScheme::Bearer)
            .description(Some(
              "OAuth 2.0 access token issued by a trusted identity provider: JWT, or opaque for \
               providers validating tokens by introspection",
            ))
            .build(),
        ),
      );
  }
}

static OPENAPI_JSON: LazyLock<String> = LazyLock::new(|| {
  ApiDoc::openapi()
    .to_pretty_json()
    .expect("serializable OpenAPI document")
});

pub async fn openapi_json() -> impl IntoResponse {
  (
    [(header::CONTENT_TYPE, "application/json")],
    OPENAPI_JSON.as_str(),
  )
}

/// Swagger UI, loaded from a pinned `swagger-ui-dist` release with subresource integrity.
pub async fn swagger_ui() -> Html<&'static str> {
  Html(
    r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Identity Metadata Service API</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css"
    integrity="sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn" crossorigin="anonymous">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"
    integrity="sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep" crossorigin="anonymous"></script>
  <script>
    window.ui = SwaggerUIBundle({ url: "openapi.json", dom_id: "#swagger-ui" });
  </script>
</body>
</html>
"##,
  )
}
