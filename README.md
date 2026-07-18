# docker-socket-proxy

Proxy HTTP minimaliste et sécurisé devant le socket Docker. Les clients sont associés à un profil par leur adresse IP, découverte depuis leurs labels Docker ; tout accès qui n'est pas explicitement accordé est refusé.

Le projet permet de limiter les familles d'API Docker, puis de restreindre les opérations à certains conteneurs. Il évite ainsi de monter directement `/var/run/docker.sock` dans une application.

## Images de production

```text
cerede2000/docker-socket-proxy:latest
ghcr.io/cerede2000/docker-socket-proxy:latest
```

La première référence est publiée sur [Docker Hub](https://hub.docker.com/r/cerede2000/docker-socket-proxy) ; la seconde sur GitHub Container Registry. Les deux images sont multi-architecture (`linux/amd64` et `linux/arm64`), construites avec Go et exécutées sans privilèges dans Distroless Debian 13. Chaque mise à jour de `main` validée par la CI les publie avec le tag `latest`.

## Principes de sécurité

- Aucun droit n'est accordé implicitement.
- Seuls les conteneurs portant `socketproxy.role` (ou l'alias `socketproxy.service`) et correspondant à un profil sont autorisés.
- Le proxy ne retient que les IP partagées avec ses propres réseaux Docker.
- Les listes, les événements et les opérations ciblant un conteneur respectent la même portée.
- Le cache interne nom / ID de conteneur évite une requête Docker supplémentaire pour les vérifications usuelles.

## Démarrage rapide

Créez un fichier `profiles.yml`, puis lancez le proxy. Le montage du socket est en lecture seule : les requêtes Docker restent possibles via l'API Unix, mais le fichier socket ne peut pas être remplacé depuis le conteneur.

```yaml
services:
  docker-socket-proxy:
    image: ghcr.io/cerede2000/docker-socket-proxy:latest
    container_name: docker-socket-proxy
    user: "1000:998" # adapter à l'UID:GID pouvant lire le socket sur l'hôte
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./profiles.yml:/config/profiles.yml:ro
    networks:
      - socketproxy
    restart: unless-stopped

networks:
  socketproxy:
    internal: true
```

Le compte configuré avec `user` doit avoir accès au socket Docker de l'hôte. Vérifiez son UID et son GID avec `stat -c '%u:%g' /var/run/docker.sock` sous Linux, puis adaptez la valeur. Sur certaines installations, il est préférable de construire une image dérivée qui crée un groupe portant le GID réel du socket.

## Associer un client à un profil

Ajoutez l'un des deux labels suivants au conteneur client :

```yaml
labels:
  socketproxy.role: mon-profil
  # ou : socketproxy.service: mon-profil
```

Le profil est rechargé automatiquement lorsque `profiles.yml` est modifié. La découverte des IP intervient au démarrage, lors des événements Docker pertinents, et périodiquement.

## Exemple complet : Traefik et Traefik Manager

Cet exemple sépare les rôles : Traefik peut lire les informations nécessaires au provider Docker ; Traefik Manager peut seulement consulter et redémarrer le conteneur `traefik`. Il ne peut ni agir sur les autres conteneurs ni lancer d'exec.

`compose.yml` :

```yaml
services:
  docker-socket-proxy:
    image: ghcr.io/cerede2000/docker-socket-proxy:latest
    container_name: docker-socket-proxy
    user: "1000:998" # à adapter à l'hôte
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./profiles.yml:/config/profiles.yml:ro
    networks: [socketproxy]
    restart: unless-stopped

  traefik:
    image: traefik:v3
    container_name: traefik
    command:
      - --providers.docker=true
      - --providers.docker.endpoint=tcp://docker-socket-proxy:2375
      - --providers.docker.exposedbydefault=false
    labels:
      socketproxy.role: traefik
    networks: [socketproxy, frontend]
    restart: unless-stopped

  traefik-manager:
    image: ghcr.io/chr0nzz/traefik-manager:latest
    container_name: traefik-manager
    environment:
      DOCKER_HOST: tcp://docker-socket-proxy:2375
      RESTART_METHOD: proxy
      TRAEFIK_CONTAINER: traefik
    labels:
      socketproxy.role: traefik-manager
    networks: [socketproxy, frontend]
    restart: unless-stopped

networks:
  socketproxy:
    internal: true
  frontend:
    external: true
```

`profiles.yml` :

```yaml
traefik:
  ping: true
  version: true
  containers: true
  networks: true
  events: true
  session: true

traefik-manager:
  ping: true
  version: true
  containers: true
  post: true
  allow_restart: true
  container_scope: allowlist
  allowed_containers:
    - traefik
```

`container_name: traefik` et `allowed_containers: [traefik]` doivent correspondre exactement. Le profil `traefik-manager` ne permet pas `start` ou `stop` : seul `POST /containers/traefik/restart` est admis.

## Configuration du proxy

| Variable | Défaut | Description |
| --- | --- | --- |
| `DOCKER_SOCKET_PATH` | `/var/run/docker.sock` | Chemin du socket Docker à joindre |
| `PROXY_PORT` | `2375` | Port d'écoute et port du healthcheck intégré |
| `PROXY_LISTEN` | — | Adresse d'écoute complète ; prioritaire sur `PROXY_PORT` |
| `SOCKETPROXY_PROFILE_FILE` | `/config/profiles.yml` | Fichier YAML des profils |
| `DISCOVER_INTERVAL` | `30s` | Période de redécouverte des conteneurs ; durée Go (`15s`) ou nombre de secondes (`15`) |
| `EVENT_DEBOUNCE_DELAY` | `100ms` | Délai de regroupement des événements Docker ; durée Go ou nombre de millisecondes |

Les arguments suivants sont disponibles et prioritaires sur les variables correspondantes : `--listen`, `--socket`, `--profiles`, `--discover-interval` et `--debounce-delay`.

Le healthcheck appelle `http://127.0.0.1:$PROXY_PORT/version`. Si `--listen` ou `PROXY_LISTEN` utilise un autre port, renseignez `PROXY_PORT` avec ce même port.

### Options de ligne de commande par profil

Les profils peuvent aussi être définis dans la commande du conteneur. Le format est `--<profil>.<option>=<valeur>` ou `--proxy-<profil>.<option>=<valeur>`.

```yaml
command:
  - --traefik.ping=1
  - --traefik.containers=1
  - --traefik-manager.container_scope=allowlist
  - --traefik-manager.allowed_containers=traefik
```

Les listes CLI acceptent des noms séparés par des virgules. `container_rule` accepte `nom:deny` ou `nom:readonly`. Le YAML reste préférable pour les configurations maintenues dans le temps.

## Référence des profils

Chaque famille est désactivée par défaut. Une valeur YAML booléenne (`true`/`false`) est recommandée.

| Option | Famille d'API Docker autorisée |
| --- | --- |
| `ping` | `/_ping` |
| `version` | `/version` |
| `info` | `/info` |
| `events` ou `event` | `/events` |
| `auth` | `/auth` |
| `build` | `/build` |
| `commit` | `/commit` |
| `configs` | `/configs` |
| `containers` | `/containers` |
| `distribution` | `/distribution` |
| `exec` | `/exec` |
| `images` | `/images` |
| `networks` | `/networks` |
| `nodes` | `/nodes` |
| `plugins` | `/plugins` |
| `secrets` | `/secrets` |
| `services` | `/services` |
| `session` | `/session` |
| `swarm` | `/swarm` |
| `system` | `/system` |
| `tasks` | `/tasks` |
| `volumes` | `/volumes` |

Les écritures (`POST`, `PUT`, `PATCH`, `DELETE`) restent interdites même lorsqu'une famille est activée, sauf si `post: true` est ajouté. Pour les opérations de conteneur, `post` doit être complété explicitement par `allow_start`, `allow_stop` et/ou `allow_restart` selon le besoin. `allow_restarts` est accepté comme alias de `allow_restart`.

`apirewrite` force une version d'API Docker pour un profil, par exemple `apirewrite: "1.53"`.

## Portée des conteneurs

Les noms sont les noms Docker sans le préfixe `/`. Les règles s'appliquent aux listes, événements, inspections, logs, statistiques, exec, opérations réseau et actions ciblées.

### Accès large : `all`

`all` est la valeur par défaut. Le profil conserve ses droits sur tous les conteneurs ; utilisez une règle `deny` pour retirer une cible critique.

```yaml
portainer:
  ping: true
  version: true
  containers: true
  images: true
  networks: true
  post: true
  allow_start: true
  allow_stop: true
  allow_restart: true
  container_scope: all
  container_rules:
    - name: docker-socket-proxy
      access: deny
```

### Accès minimal : `allowlist`

Les conteneurs absents de `allowed_containers` sont invisibles et inaccessibles.

```yaml
traefik-manager:
  containers: true
  post: true
  allow_restart: true
  container_scope: allowlist
  allowed_containers:
    - traefik
```

### Accès large avec exclusions : `blacklist`

Les conteneurs de `blocked_containers` sont invisibles et toute opération les visant est refusée.

```yaml
dockhand:
  ping: true
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

### Exceptions par conteneur : `container_rules`

`container_rules` est prioritaire sur la portée. `deny` masque totalement la cible. `readonly` laisse visibles les listes et événements et autorise uniquement `inspect`, `logs`, `stats`, `top` et `changes` ; les actions, `exec`, les archives et `attach` sont refusés.

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

Une cible ne peut pas figurer à la fois dans `blocked_containers` et `container_rules`. Les valeurs d'accès admises sont `deny` et `readonly`. `container_scope: all` ne peut pas contenir de liste blanche ou noire ; `allowlist` ne peut pas contenir `blocked_containers` et `blacklist` ne peut pas contenir `allowed_containers`.

Lorsqu'une portée est active (`allowlist`, `blacklist` ou une règle nominative), les opérations globales `create` et `prune` sont refusées afin de ne pas contourner la restriction par conteneur.

## Exploitation

Le proxy écrit dans ses journaux la découverte des rôles et les refus. Un client sans rôle, avec un rôle inconnu, ou ne partageant aucun réseau avec le proxy reçoit `403 Forbidden`.

## Développement

```bash
go test -race ./...
go vet ./...
```
