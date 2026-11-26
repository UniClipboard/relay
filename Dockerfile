# SPDX-License-Identifier: AGPL-3.0-only
# syntax=docker/dockerfile:1.7

FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/hyper-relay ./cmd/hyper-relay

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/hyper-relay /hyper-relay

ENV HYPER_ADDR=:8080

EXPOSE 8080

USER 65532:65532

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/hyper-relay", "healthcheck"]

ENTRYPOINT ["/hyper-relay"]
