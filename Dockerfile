# syntax=docker/dockerfile:1

# ---- build ----
FROM rust:1-bookworm AS build
WORKDIR /src

# RocksDB (oxrocksdb-sys) is compiled from source with the C++ toolchain of the image, and its
# bindings are generated with bindgen, which needs libclang.
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
 && cp target/release/identity-metadata-service /usr/local/bin/ \
 && mkdir /data

# ---- runtime ----
# Distroless image with glibc and libstdc++ (needed by RocksDB), running as a non-root user.
# TLS uses rustls with bundled root certificates: no CA bundle or OpenSSL is needed.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=build /usr/local/bin/identity-metadata-service /usr/local/bin/identity-metadata-service
COPY --from=build --chown=nonroot:nonroot /data /data

ENV IMS_BIND=0.0.0.0:8080 \
    IMS_DATA_DIR=/data \
    RUST_LOG=info,tower_http=info
VOLUME ["/data"]
EXPOSE 8080
USER nonroot

ENTRYPOINT ["/usr/local/bin/identity-metadata-service"]
