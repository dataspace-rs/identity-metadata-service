# Identity Metadata Service

HTTP service (axum) publishing the public identity metadata of organizations as
JSON-LD ([schema.org `Organization`](https://schema.org/Organization)), stored in an
[Oxigraph](https://github.com/oxigraph/oxigraph) RDF store.

## Model

```json
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "identifier": "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0002:552100554",
  "name": "ACME",
  "legalName": "ACME SAS",
  "logo": "https://acme.example/logo.png",
  "location": {
    "@type": "Place",
    "name": "Head office",
    "address": { "@type": "PostalAddress", "addressLocality": "Paris", "addressCountry": "FR" }
  }
}
```

- `identifier` (required, unique among organizations): an [OASIS ebCore Party Id Type](https://docs.oasis-open.org/ebcore/PartyIdType/v1.0/)
  URN built on ISO 6523: `urn:oasis:names:tc:ebcore:partyid-type:iso6523:<ICD>:<id>`.
  The ICD must be 4 digits and the id 1–35 characters (`A-Z a-z 0-9 - . _ ~`).
  Check digits are verified for SIRENE (`0002`, SIREN or SIRET), SIRET (`0009`) and GLN (`0088`);
  DUNS (`0060`) must be 9 digits.
- `name` (required), `legalName`, `logo` (absolute http(s) URL).
- `location`: text, `PostalAddress` or `Place` (with `name` and/or an `address` given as text or `PostalAddress`).
- `@id` is assigned by the server: `<IMS_PUBLIC_BASE_URL>/organizations/<id>`, where `id` is a
  UUID generated when the organization is registered. It is returned in the `Location` header and
  the body of the registration response, and never changes.

Request bodies must be `application/ld+json` (or `application/json`) compacted with the
`https://schema.org` context; unknown properties are rejected.

## API

| Method | Path | Bearer token |
|---|---|---|
| `GET` | `/organizations/{id}` | none (public) |
| `PUT` | `/organizations/{id}` | from a trusted issuer of the organization, or an administrator |
| `GET`, `POST` | `/admin/organizations` | administrator (list, register with initial metadata) |
| `DELETE` | `/admin/organizations/{id}` | administrator |
| `GET`, `POST` | `/admin/organizations/{id}/issuers` | administrator |
| `DELETE` | `/admin/organizations/{id}/issuers/{issuerId}` | administrator |
| `GET` | `/health` | none |
| `GET` | `/openapi.json` | none (OpenAPI 3.1 description) |
| `GET` | `/swagger-ui` | none (Swagger UI) |

Errors are returned as `application/problem+json`.

The OpenAPI description is generated from the code with [`utoipa`](https://crates.io/crates/utoipa).
Swagger UI loads a pinned `swagger-ui-dist` release from the jsDelivr CDN (with subresource
integrity), so the browser viewing it needs access to `cdn.jsdelivr.net`.

## Authentication

The service does not issue tokens: clients obtain OAuth 2.0 access tokens from an identity provider
and send them as `Authorization: Bearer <token>`. Every provider is an OpenID provider: its
[OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) document
(`<issuer>/.well-known/openid-configuration`) tells how to validate its tokens, in one of two ways:

- **Introspection**, when the service has an OAuth 2.0 client (id and secret) at the provider:
  each token (JWT or opaque) is checked with
  [OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662) (using the
  [`oauth2`](https://crates.io/crates/oauth2) crate) at its `introspection_endpoint`. The token
  must be `active`, not expired, and its `iss` (when returned) must be the provider.
- **JWKS**, without client: only JWT access tokens are accepted. Their signature is verified
  (using [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken), asymmetric algorithms only)
  with the signing keys published at the provider's `jwks_uri`; `iss` must be the provider, `exp`
  is required and checked with `nbf` (60 s of leeway). Keys are cached for 5 minutes, and fetched
  again (at most every 30 s) when a token names an unknown `kid`, to follow key rotations.
  Revoked tokens remain valid until they expire.

An **audience** can be set for each provider (`--root-audience` for the root identity, `audience`
when registering an issuer): its tokens must then name it in their `aud` claim (a string or one
of a list), in both modes. Without audience, the tokens of a trusted provider are accepted
whatever application they were issued for, so setting one is recommended, especially in JWKS
mode.

Two kinds of providers are trusted:

- **Root identity** (`IMS_ROOT_ISSUER`): its tokens (restricted to the subjects or clients listed in
  `IMS_ROOT_ADMINS` when set) register and delete organizations, manage their trusted issuers, and
  may update any organization.
- **Trusted issuers of an organization**: their tokens may update that organization only.

Each organization holds exactly one record, its own identity metadata, addressed by its UUID; its
ebCore Party Id (`identifier`) is a property of the record and may be changed by an update, as
long as no other organization uses it. JWT access tokens are only validated by the issuer named by
their `iss` claim; opaque tokens are tried against each trusted provider validating tokens by
introspection, in turn (the organization's issuers, then the root).

An administrator registers an organization, then its provider, with or without client:

```sh
curl -i -X POST $URL/admin/organizations -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/ld+json' -d @acme.jsonld
# Location: <IMS_PUBLIC_BASE_URL>/organizations/6f1c2b9e-3d4a-4e8b-9c1f-2a7d5e8b4c3a

# JWKS
curl -X POST $URL/admin/organizations/6f1c2b9e-3d4a-4e8b-9c1f-2a7d5e8b4c3a/issuers \
  -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"issuer": "https://login.example.com/realms/acme", "audience": "identity-metadata-service"}'

# Introspection
curl -X POST $URL/admin/organizations/6f1c2b9e-3d4a-4e8b-9c1f-2a7d5e8b4c3a/issuers \
  -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"issuer": "https://login.example.com/realms/acme", "clientId": "ims", "clientSecret": "…"}'
```

The provider is checked at registration (introspection endpoint, or a key set with at least one
signing key). The response tells the `tokenValidation` method (`introspection` or `jwks`); the
client secret is stored but never returned. Unregistering an issuer (or deleting the organization)
immediately revokes the write access of its tokens.

## Configuration

Options are passed as command line arguments or environment variables (arguments take
precedence); `identity-metadata-service --help` lists them.

| Argument | Variable | Default | |
|---|---|---|---|
| `--root-issuer` | `IMS_ROOT_ISSUER` | — (required) | OpenID issuer URL of the root identity |
| `--root-client-id` | `IMS_ROOT_CLIENT_ID` | none: JWKS | OAuth 2.0 client of this service at the root issuer, to validate tokens by introspection |
| `--root-client-secret` | `IMS_ROOT_CLIENT_SECRET` | none | its secret, required with the client id (prefer the variable) |
| `--root-audience` | `IMS_ROOT_AUDIENCE` | not checked | audience (`aud`) the root identity's tokens must be intended for |
| `--root-admins` | `IMS_ROOT_ADMINS` | anyone | comma-separated subjects (`sub`) or clients (`client_id`) allowed to administer |
| `--bind` | `IMS_BIND` | `0.0.0.0:8080` | listen address |
| `--data-dir` | `IMS_DATA_DIR` | in-memory | RocksDB directory of the Oxigraph store |
| `--public-base-url` | `IMS_PUBLIC_BASE_URL` | `http://localhost:8080` | base of the record IRIs; keep it stable |
| `--allow-insecure-issuers` | `IMS_ALLOW_INSECURE_ISSUERS` | `false` | allow `http://` providers (development only) |

A variable set to an empty value is rejected: unset it instead.

## Storage layout

- `urn:identity-metadata-service:system` graph: registered organizations and their trusted issuers.
- One named graph per organization, named by its `@id`, holding its schema.org triples
  (`<@id>#location` / `<@id>#address` for nested nodes). Updates replace the graph atomically.

## Docker

```sh
docker run -p 8080:8080 -v ims-data:/data \
  -e IMS_ROOT_ISSUER=https://login.example.com/realms/platform \
  -e IMS_ROOT_AUDIENCE=identity-metadata-service \
  -e IMS_PUBLIC_BASE_URL=https://metadata.example.com \
  ghcr.io/dataspace-rs/identity-metadata-service:latest
```

The image runs as a non-root user, listens on port 8080 and stores the Oxigraph database in the
`/data` volume (`IMS_DATA_DIR`). It is built by the `Docker` workflow and published to the GitHub
Container Registry: `latest` (and `sha-<commit>`) from `main`, and the tag name for git tags
(plus `1.2.3` and `1.2` for a `v1.2.3` tag). Pull requests only build it.

## Development

The `CI` workflow checks, on every push and pull request:

| Check | Command |
|---|---|
| Format | `cargo fmt --all --check` |
| Lints | `cargo clippy --locked --all-targets --all-features` (warnings denied) |
| Tests | `cargo test --locked --all-targets` and `cargo test --locked --doc` |
| Documentation | `cargo doc --locked --no-deps --document-private-items` (warnings denied) |
| Minimum Rust version | `cargo check --locked --all-targets` with the `rust-version` of `Cargo.toml` (1.89) |
| Dependencies | `cargo deny check` (advisories, licenses, sources; see `deny.toml`) |
| Unused dependencies | `cargo machete` |

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project by you, as defined in the Apache-2.0 license, shall be licensed as above, without any
additional terms or conditions.
