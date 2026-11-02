# syntax=docker/dockerfile:1.7
FROM golang:1.26-bookworm AS builder
WORKDIR /build
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download
COPY gateway/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /gateway .

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 relay \
    && useradd --uid 10001 --gid relay --no-create-home --shell /usr/sbin/nologin relay
COPY --from=builder /gateway /usr/local/bin/uniclipboard-gateway
USER relay:relay
EXPOSE 3340
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/uniclipboard-gateway", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/uniclipboard-gateway"]
