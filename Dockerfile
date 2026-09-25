FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build

ARG APP_VERSION="dev"
ARG APP_GIT_SHA="unknown"
ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0

# binutils fournit readelf, utilisé plus bas pour vérifier que le binaire est
# bien statique. Sans cette garantie, une image scratch ne démarrerait pas.
RUN apk add --no-cache binutils

WORKDIR /src

COPY go.mod go.sum ./
COPY src/ ./src

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X main.version=${APP_VERSION} -X main.gitSha=${APP_GIT_SHA}" \
    -o /out/docker-socket-proxy ./src

# Un binaire lié dynamiquement porte une section .interp nommant son chargeur.
# L'absence de cette section est la preuve qu'aucun interpréteur n'est requis,
# et donc que l'image finale peut se passer de toute bibliothèque système.
RUN test -z "$(readelf -x .interp /out/docker-socket-proxy 2>/dev/null)"

FROM scratch

# scratch ne définit aucune variable : les chemins absolus ci-dessous évitent
# de dépendre d'un PATH hérité.
COPY --from=build --chown=65532:65532 /out/docker-socket-proxy /usr/local/bin/docker-socket-proxy

ENV DOCKER_SOCKET_PATH=/var/run/docker.sock \
    PROXY_PORT=2375 \
    PATH=/usr/local/bin

EXPOSE 2375

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/docker-socket-proxy", "healthcheck"]

# 65532 est l'UID nonroot conventionnel des images distroless. scratch n'a pas
# de /etc/passwd : l'UID numérique suffit au moteur.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/docker-socket-proxy"]
