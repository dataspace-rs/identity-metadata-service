use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Args, CommandFactory, Parser};
use oauth2::ClientSecret;
use url::Url;

/// Server publishing the public identity metadata of organizations.
///
/// Every option can also be set with the environment variable shown in its description.
#[derive(Debug, Clone, Parser)]
#[command(version, about)]
pub struct Config {
  /// Address the HTTP server listens on.
  #[arg(long, env = "IMS_BIND", default_value = "0.0.0.0:8080")]
  pub bind: SocketAddr,
  /// Directory of the RocksDB-backed Oxigraph store; in-memory store when absent.
  #[arg(long, env = "IMS_DATA_DIR")]
  pub data_dir: Option<PathBuf>,
  /// Public base URL of the service, used to mint the `@id` of the records.
  /// It is part of the stored IRIs, so it must remain stable.
  #[arg(
    long,
    env = "IMS_PUBLIC_BASE_URL",
    default_value = "http://localhost:8080",
    value_parser = parse_base_url
  )]
  pub public_base_url: Url,
  #[command(flatten)]
  pub root: RootIdentity,
  /// Allows plain http providers (for local development and tests only).
  #[arg(long, env = "IMS_ALLOW_INSECURE_ISSUERS")]
  pub allow_insecure_issuers: bool,
}

/// The root identity: users of this OpenID provider manage organizations and their
/// trusted issuers.
#[derive(Debug, Clone, Args)]
pub struct RootIdentity {
  /// OpenID issuer URL of the root identity, base of the discovery document.
  #[arg(long = "root-issuer", value_name = "URL", env = "IMS_ROOT_ISSUER")]
  pub issuer: String,
  /// OAuth 2.0 client of this service at the root issuer, to validate tokens by introspection.
  /// Without client, JWT access tokens are verified with the keys of the issuer (`jwks_uri`).
  #[arg(long = "root-client-id", value_name = "ID", env = "IMS_ROOT_CLIENT_ID")]
  pub client_id: Option<String>,
  /// Secret of the OAuth 2.0 client at the root issuer; required with `--root-client-id`.
  #[arg(
    long = "root-client-secret",
    value_name = "SECRET",
    env = "IMS_ROOT_CLIENT_SECRET",
    hide_env_values = true,
    value_parser = parse_secret
  )]
  pub client_secret: Option<ClientSecret>,
  /// Audience the tokens of the root issuer must be intended for (`aud` claim); not checked
  /// when absent.
  #[arg(
    long = "root-audience",
    value_name = "AUDIENCE",
    env = "IMS_ROOT_AUDIENCE"
  )]
  pub audience: Option<String>,
  /// Comma-separated subjects (`sub`) or clients (`client_id`) allowed to administer;
  /// anyone when empty.
  #[arg(
    long = "root-admins",
    value_name = "ADMIN",
    env = "IMS_ROOT_ADMINS",
    value_delimiter = ','
  )]
  pub admins: Vec<String>,
}

impl Config {
  /// Parses the command line arguments and environment variables, exiting with a usage error
  /// when they are invalid.
  pub fn load() -> Self {
    Self::parse().validated().unwrap_or_else(|message| {
      Self::command()
        .error(ErrorKind::ValueValidation, message)
        .exit()
    })
  }

  /// Checks the constraints between options and normalizes the list of administrators.
  fn validated(mut self) -> Result<Self, String> {
    match Url::parse(&self.root.issuer).map(|url| url.scheme().to_owned()) {
      Ok(scheme) if scheme == "https" || (scheme == "http" && self.allow_insecure_issuers) => {}
      _ => {
        return Err(
          "--root-issuer must be an https URL (or http with --allow-insecure-issuers)".into(),
        );
      }
    }
    if self.root.client_id.is_some() != self.root.client_secret.is_some() {
      return Err("--root-client-id and --root-client-secret must be set together".into());
    }
    self.root.admins = std::mem::take(&mut self.root.admins)
      .into_iter()
      .map(|admin| admin.trim().to_owned())
      .filter(|admin| !admin.is_empty())
      .collect();
    Ok(self)
  }
}

fn parse_base_url(value: &str) -> Result<Url, url::ParseError> {
  let mut url = Url::parse(value)?;
  if !url.path().ends_with('/') {
    url.set_path(&format!("{}/", url.path()));
  }
  Ok(url)
}

fn parse_secret(value: &str) -> Result<ClientSecret, Infallible> {
  Ok(ClientSecret::new(value.to_owned()))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_arguments() {
    let config = Config::try_parse_from([
      "identity-metadata-service",
      "--root-issuer=https://login.example.com",
      "--root-client-id=ims",
      "--root-client-secret=s3cret",
      "--root-admins=alice, bob",
      "--public-base-url=https://ims.example/base",
    ])
    .unwrap()
    .validated()
    .unwrap();
    assert_eq!(config.bind, "0.0.0.0:8080".parse().unwrap());
    assert_eq!(config.public_base_url.as_str(), "https://ims.example/base/");
    assert_eq!(
      config.root.client_secret.as_ref().unwrap().secret(),
      "s3cret"
    );
    assert_eq!(config.root.admins, ["alice", "bob"]);
    assert!(!config.allow_insecure_issuers);
  }

  #[test]
  fn rejects_insecure_root_issuer() {
    let parse = |args: &[&str]| {
      Config::try_parse_from(
        [
          "identity-metadata-service",
          "--root-issuer=http://login.example.com",
          "--root-client-id=ims",
          "--root-client-secret=s3cret",
        ]
        .iter()
        .chain(args),
      )
      .unwrap()
      .validated()
    };
    assert!(parse(&[]).is_err());
    assert!(parse(&["--allow-insecure-issuers"]).is_ok());
  }

  #[test]
  fn root_client_is_optional() {
    let parse = |args: &[&str]| {
      Config::try_parse_from(
        [
          "identity-metadata-service",
          "--root-issuer=https://login.example.com",
        ]
        .iter()
        .chain(args),
      )
      .unwrap()
      .validated()
    };
    let config = parse(&[]).unwrap();
    assert!(config.root.client_id.is_none() && config.root.client_secret.is_none());
    assert!(parse(&["--root-client-id=ims"]).is_err());
    assert!(parse(&["--root-client-secret=s3cret"]).is_err());
    assert_eq!(
      parse(&["--root-audience=ims-api"])
        .unwrap()
        .root
        .audience
        .as_deref(),
      Some("ims-api")
    );
  }

  #[test]
  fn requires_root_identity() {
    assert!(Config::try_parse_from(["identity-metadata-service"]).is_err());
  }

  #[test]
  fn verifies_command() {
    Config::command().debug_assert();
  }
}
