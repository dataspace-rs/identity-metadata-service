pub mod auth;
pub mod config;
pub mod error;
pub mod model;
pub mod openapi;
mod routes;
pub mod store;

use std::sync::Arc;

use axum::Router;
use oxigraph::store::Store;

use crate::auth::Authenticator;
use crate::config::Config;
use crate::error::{AppError, AppResult};
use crate::store::Repository;

#[derive(Clone)]
pub struct AppState {
  inner: Arc<Inner>,
}

struct Inner {
  repository: Repository,
  authenticator: Authenticator,
}

impl AppState {
  pub fn new(config: &Config, store: Store) -> Self {
    Self {
      inner: Arc::new(Inner {
        repository: Repository::new(store, &config.public_base_url),
        authenticator: Authenticator::new(config),
      }),
    }
  }

  fn repository(&self) -> &Repository {
    &self.inner.repository
  }

  fn authenticator(&self) -> &Authenticator {
    &self.inner.authenticator
  }
}

pub fn app(state: AppState) -> Router {
  routes::router(state)
}

/// Runs blocking storage operations outside of the async runtime.
pub(crate) async fn blocking<T: Send + 'static>(
  f: impl FnOnce() -> AppResult<T> + Send + 'static,
) -> AppResult<T> {
  tokio::task::spawn_blocking(f)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
}
