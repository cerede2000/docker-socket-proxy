FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build

ARG APP_VERSION="dev"
ARG APP_GIT_SHA="unknown"
ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0

WORKDIR /src

COPY go.mod go.sum ./
COPY src/ ./src

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X main.version=${APP_VERSION} -X main.gitSha=${APP_GIT_SHA}" \
    -o /out/docker-socket-proxy ./src

FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=build --chown=nonroot:nonroot /out/docker-socket-proxy /usr/local/bin/docker-socket-proxy

ENV DOCKER_SOCKET_PATH=/var/run/docker.sock \
    PROXY_PORT=2375

EXPOSE 2375

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["docker-socket-proxy", "healthcheck"]

USER nonroot:nonroot

ENTRYPOINT ["docker-socket-proxy"]
