# syntax=docker/dockerfile:1
# Defaults let the legacy (non-BuildKit) builder work; buildx overrides them.
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM golang:1.27.4 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/docker-socket-secure-proxy ./cmd/docker-socket-secure-proxy

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="docker-socket-secure-proxy" \
      org.opencontainers.image.description="Read-only Docker socket proxy that redacts env vars and secrets from API responses" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="BSD-3-Clause"
COPY --from=build /out/docker-socket-secure-proxy /docker-socket-secure-proxy
# Runs as nonroot (65532). The container needs access to the docker.sock group,
# e.g. `group_add: ["<gid of docker.sock>"]` in compose or `--group-add`.
USER 65532:65532
# Default port 2375; override at runtime with -e PORT=... (HEALTHCHECK follows it).
EXPOSE 2375
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/docker-socket-secure-proxy", "--healthcheck"]
ENTRYPOINT ["/docker-socket-secure-proxy"]
