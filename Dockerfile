# Dockerfile (racine du repo cerede2000/docker-socket-proxy)
FROM haproxy:3.0-alpine

# Infos de build injectées par GitHub Actions
ARG VERSION="dev"
ARG GIT_SHA="unknown"

ENV APP_VERSION="${VERSION}" \
    APP_GIT_SHA="${GIT_SHA}"

# On copie l'entrypoint depuis src/ et on lui met directement les droits d'exécution
COPY --chmod=755 src/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD []
