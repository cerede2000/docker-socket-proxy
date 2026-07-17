FROM golang:1.26.5-alpine3.24 AS build

ARG APP_VERSION="dev"
ARG APP_GIT_SHA="unknown"

ENV CGO_ENABLED=0

WORKDIR /src

COPY go.mod ./
COPY src/ ./src

RUN go build -trimpath \
    -ldflags="-s -w -X main.version=${APP_VERSION} -X main.gitSha=${APP_GIT_SHA}" \
    -o /out/docker-socket-proxy ./src

FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build --chown=nonroot:nonroot /out/docker-socket-proxy /usr/local/bin/docker-socket-proxy

ENV DOCKER_SOCKET_PATH=/var/run/docker.sock \
    PROXY_PORT=2375

EXPOSE 2375

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["docker-socket-proxy", "healthcheck"]

USER nonroot:nonroot

ENTRYPOINT ["docker-socket-proxy"]
