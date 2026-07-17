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

## Portée et règles par conteneur

Les noms de conteneurs sont exacts et correspondent au nom Docker sans le préfixe `/` (par exemple `container_name: dockman` devient `dockman`). La portée détermine l'accès normal ; `container_rules` ajoute des exceptions par nom.

### Tous les conteneurs — comportement historique

`all` est la valeur par défaut. Le profil conserve les droits Docker qui lui sont accordés sur tous les conteneurs.

```yaml
portainer:
  containers: true
  images: true
  networks: true
  post: true
  allow_start: true
  allow_stop: true
  allow_restart: true
  container_scope: all
```

### Allowlist — agir seulement sur certaines cibles

Les conteneurs absents de `allowed_containers` sont invisibles et inaccessibles.

```yaml
traefik-manager:
  containers: true
  post: true
  allow_start: true
  allow_stop: true
  allow_restart: true
  container_scope: allowlist
  allowed_containers:
    - traefik
```

### Blacklist — profil large avec cibles masquées

Les conteneurs de `blocked_containers` sont invisibles et toute opération les visant est refusée.

```yaml
dockhand:
  containers: true
  events: true
  post: true
  allow_start: true
  allow_stop: true
  allow_restart: true
  container_scope: blacklist
  blocked_containers:
    - docker-socket-proxy
```

### Règle `deny` — masquer une cible, quelle que soit la portée

`container_rules` est prioritaire sur `container_scope`. Cette variante est utile avec `all`, ou pour rendre la règle plus explicite.

```yaml
operator:
  containers: true
  container_scope: all
  container_rules:
    - name: docker-socket-proxy
      access: deny
```

### Règle `readonly` — voir sans pouvoir agir

Une cible en lecture seule reste visible dans les listes et événements. Seules les API de consultation suivantes sont admises : `inspect`, `logs`, `stats`, `top` et `changes`. Les opérations de modification, les exec, les archives et l'attach sont refusés.

```yaml
dockhand:
  containers: true
  events: true
  post: true
  allow_start: true
  allow_stop: true
  allow_restart: true
  container_scope: blacklist
  blocked_containers:
    - docker-socket-proxy
  container_rules:
    - name: dockman
      access: readonly
```

Dans cet exemple, Dockhand peut consulter les logs et statistiques de `dockman`, mais pas le redémarrer ; `docker-socket-proxy` reste entièrement masqué. Les conteneurs non cités conservent les droits du profil.

Une même cible ne peut pas figurer à la fois dans `blocked_containers` et `container_rules`. Les valeurs autorisées pour `access` sont exclusivement `deny` et `readonly`.

Pour toute portée active (`allowlist`, `blacklist`, ou au moins une `container_rules`), les opérations globales de conteneurs (`create` et `prune`) sont refusées. Les règles sont appliquées aussi aux listes de conteneurs et au flux d'événements.

## Développement

```bash
go test -race ./...
go vet ./...
```
