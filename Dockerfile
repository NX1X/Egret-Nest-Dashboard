# Egret Nest Dashboard — single static binary, distroless runtime.
# Builder Go version must satisfy go.mod (go 1.25); bump the two together.
# Base images are digest-pinned (tag kept in the comment for readability);
# Renovate (.github/renovate.json5) bumps both the tag comment and the @sha256.
FROM golang:1.25.12@sha256:9669c2ed28435af1b8989acb9fd5235346a912016cc8b152b694a9a91dced0a6 AS build
WORKDIR /src
# No wildcard on go.sum: a missing checksum file must hard-fail, not silently
# skip the `go mod verify` below.
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
# CGO off: modernc.org/sqlite is pure Go, so the binary is fully static.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" -o /egret-nest ./cmd/egret-nest

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
LABEL org.opencontainers.image.source="https://github.com/NX1X/Egret-Nest-Dashboard" \
      org.opencontainers.image.description="Egret Nest Dashboard — self-hosted CI/CD egress telemetry" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /egret-nest /egret-nest
# Persist the SQLite db under /data (mount a volume here).
ENV EGRET_NEST_DB=/data/egret-nest.db
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/egret-nest"]
