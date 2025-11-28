# Dockerfile (à la racine du repo cerede2000/docker-socket-proxy)
FROM haproxy:3.0-alpine

# Infos de build injectées par GitHub Actions
ARG VERSION="dev"
ARG GIT_SHA="unknown"

ENV APP_VERSION="${VERSION}" \
    APP_GIT_SHA="${GIT_SHA}"

# Tous les fichiers à copier sont dans ./src
COPY src/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD []
