# Egret Nest Dashboard - single static binary, distroless runtime.
# Builder Go version must satisfy go.mod (go 1.26); bump the two together.
# Base images are digest-pinned (tag kept in the comment for readability);
# Renovate (.github/renovate.json5) bumps both the tag comment and the @sha256.
FROM golang:1.26.10@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS build
WORKDIR /src
# No wildcard on go.sum: a missing checksum file must hard-fail, not silently
# skip the `go mod verify` below.
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
# CGO off: modernc.org/sqlite is pure Go, so the binary is fully static.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /egret-nest ./cmd/egret-nest

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.source="https://github.com/NX1X/Egret-Nest-Dashboard" \
      org.opencontainers.image.description="Egret Nest Dashboard - self-hosted CI/CD egress telemetry" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /egret-nest /egret-nest
# Persist the SQLite db under /data (mount a volume here).
ENV EGRET_NEST_DB=/data/egret-nest.db
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/egret-nest"]
