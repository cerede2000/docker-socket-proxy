# docker-socket-proxy

Proxy HTTP minimaliste devant le socket Docker. Les clients sont associés à un profil par leur adresse IP et les droits Docker sont refusés par défaut.

## Image de développement

```text
ghcr.io/cerede2000/docker-socket-proxy:dev
```

L'image est publiée pour `linux/amd64` et `linux/arm64` après validation des tests. Elle utilise un binaire Go statique dans Distroless Debian 13 et s'exécute sans privilèges par défaut.

## Configuration

| Variable | Défaut | Description |
| --- | --- | --- |
| `DOCKER_SOCKET_PATH` | `/var/run/docker.sock` | Chemin du socket Docker |
| `PROXY_PORT` | `2375` | Port d'écoute et port utilisé par le healthcheck |
| `PROXY_LISTEN` | vide | Adresse d'écoute complète, prioritaire sur `PROXY_PORT` |
| `SOCKETPROXY_PROFILE_FILE` | `/config/profiles.yml` | Fichier de profils |
| `DISCOVER_INTERVAL` | `30s` | Intervalle de redécouverte |
| `EVENT_DEBOUNCE_DELAY` | `100ms` | Temporisation des événements Docker |

Les options `--listen`, `--socket`, `--profiles`, `--discover-interval` et `--debounce-delay` restent disponibles et sont prioritaires sur l'environnement. Si `--listen` change le port, `PROXY_PORT` doit être renseigné avec le même port pour le healthcheck.

Le compte effectif doit pouvoir lire le socket Docker. Le fichier Compose fournit un exemple avec un UID/GID hôte explicite ; adaptez `user` au propriétaire et au groupe du socket de votre machine.

## Développement

```bash
go test -race ./...
go vet ./...
```
