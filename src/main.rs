use identity_metadata_service::config::Config;
use identity_metadata_service::{AppState, app};
use oxigraph::store::Store;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  tracing_subscriber::fmt()
    .with_env_filter(
      EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,tower_http=info")),
    )
    .init();

  let config = Config::load();
  let store = match &config.data_dir {
    Some(dir) => Store::open(dir)?,
    None => {
      tracing::warn!("no data directory configured: using a volatile in-memory store");
      Store::new()?
    }
  };

  let listener = tokio::net::TcpListener::bind(config.bind).await?;
  tracing::info!(
      address = %config.bind,
      base_url = %config.public_base_url,
      root_issuer = %config.root.issuer,
      "listening"
  );
  let router = app(AppState::new(&config, store));
  axum::serve(listener, router)
    .with_graceful_shutdown(async {
      let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
  Ok(())
}
