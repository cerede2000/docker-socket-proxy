# =========================
# Stage 1 : build Go binary
# =========================
FROM golang:1.23-alpine AS build

ARG APP_VERSION="dev"
ARG APP_GIT_SHA="unknown"

# On désactive les modules pour un projet simple sans go.mod
ENV GO111MODULE=off \
    CGO_ENABLED=0

WORKDIR /src

# On copie juste le dossier src/
COPY src/ ./src

# Build du binaire
RUN go build -trimpath \
    -ldflags="-s -w -X main.version=${APP_VERSION} -X main.gitSha=${APP_GIT_SHA}" \
    -o /out/docker-socket-proxy ./src

# =========================
# Stage 2 : image finale
# =========================
#FROM alpine:3.20 si debug
FROM gcr.io/distroless/base-debian12

COPY --from=build /out/docker-socket-proxy /usr/local/bin/docker-socket-proxy

ENV DOCKER_SOCKET_PATH=/var/run/docker.sock \
    PROXY_PORT=2375

EXPOSE 2375

# Healthcheck intégré : teste le serveur Go + accès Docker via /version
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/docker-socket-proxy", "healthcheck"]

ENTRYPOINT ["docker-socket-proxy"]
