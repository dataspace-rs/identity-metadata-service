use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
pub use identity_metadata_commons::ProblemDetails;

/// Errors returned by the HTTP API, rendered as RFC 9457 problem details.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
  #[error("{0}")]
  BadRequest(String),
  #[error("{0}")]
  Unauthorized(String),
  #[error("{0}")]
  Forbidden(String),
  #[error("{0}")]
  NotFound(String),
  #[error("{0}")]
  Conflict(String),
  #[error("{0}")]
  UnsupportedMediaType(String),
  #[error("{0}")]
  Unprocessable(String),
  #[error("{0}")]
  BadGateway(String),
  #[error(transparent)]
  Storage(#[from] oxigraph::store::StorageError),
  #[error("{0}")]
  Internal(String),
}

impl AppError {
  fn status(&self) -> StatusCode {
    match self {
      Self::BadRequest(_) => StatusCode::BAD_REQUEST,
      Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
      Self::Forbidden(_) => StatusCode::FORBIDDEN,
      Self::NotFound(_) => StatusCode::NOT_FOUND,
      Self::Conflict(_) => StatusCode::CONFLICT,
      Self::UnsupportedMediaType(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
      Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
      Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
      Self::Storage(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    let status = self.status();
    let detail = if status.is_server_error() {
      tracing::error!(error = %self, "request failed");
      "internal server error".to_owned()
    } else {
      self.to_string()
    };
    let body = ProblemDetails {
      kind: "about:blank".into(),
      title: status.canonical_reason().unwrap_or_default().into(),
      status: status.as_u16(),
      detail,
    };
    let mut response = (
      status,
      [(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
      )],
      serde_json::to_string(&body).unwrap_or_default(),
    )
      .into_response();
    if status == StatusCode::UNAUTHORIZED {
      response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
  }
}

pub type AppResult<T> = Result<T, AppError>;
