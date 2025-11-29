# ============================
#  Stage 1 : Build Go binary
# ============================
FROM golang:1.23-alpine AS builder

# Variables de build (injectées par GitHub Actions ou autres)
ARG APP_VERSION="dev"
ARG APP_GIT_SHA="unknown"

# On veut un build statique, propre, reproductible
ENV CGO_ENABLED=0 \
    GOOS=linux

WORKDIR /src

# Code source
COPY . .

# Build du binaire
# Si ton main.go n'est pas à la racine, adapte le dernier argument (ex: ./cmd/proxy)
RUN go build -trimpath \
    -ldflags="-s -w -X 'main.version=${APP_VERSION}' -X 'main.gitSha=${APP_GIT_SHA}'" \
    -o /out/docker-socket-proxy ./src

# ============================
#  Stage 2 : Runtime léger
# ============================
FROM alpine:3.20

# Certificats CA si un jour tu dialogues en HTTPS (API externes, etc.)
RUN apk add --no-cache ca-certificates && update-ca-certificates

# Création d'un user non-root
RUN adduser -D -H -u 1000 socketproxy

USER socketproxy

# Variables runtime par défaut
ENV DOCKER_SOCKET_PATH="/var/run/docker.sock" \
    PROXY_PORT="2375"

# Copie du binaire depuis le stage builder
COPY --from=builder /out/docker-socket-proxy /usr/local/bin/docker-socket-proxy

# Healthcheck par défaut : appelle /healthz du proxy
# Alpine embarque busybox, donc wget est disponible par défaut
HEALTHCHECK --interval=5s --timeout=2s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PROXY_PORT}/healthz" >/dev/null 2>&1 || exit 1

EXPOSE 2375

ENTRYPOINT ["/usr/local/bin/docker-socket-proxy"]
CMD []
