# syntax=docker/dockerfile:1.7

FROM rust:1.91-bookworm AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 relay \
    && useradd --uid 10001 --gid relay --no-create-home --shell /usr/sbin/nologin relay

COPY --from=builder /build/target/release/uniclipboard-relay /usr/local/bin/uniclipboard-relay

USER relay:relay
ENV UC_RELAY_BIND=0.0.0.0:3340
EXPOSE 3340

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent --show-error http://127.0.0.1:3340/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/uniclipboard-relay"]
