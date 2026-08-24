# docker-socket-proxy

**English** | [Français](README.fr.md)

[![Docker Scout report](https://img.shields.io/badge/Docker%20Scout-view%20report-2496ED?logo=docker&logoColor=white)](https://scout.docker.com/reports/org/cerede2000/images/host/hub.docker.com/repo/cerede2000%2Fdocker-socket-proxy)

A minimal, security-focused HTTP proxy in front of the Docker socket. Client containers are assigned a profile from their Docker labels and shared network IP addresses; access is denied unless it is explicitly granted.

Instead of mounting `/var/run/docker.sock` directly into an application, grant the Docker API families it needs and, when necessary, restrict those permissions to a precise set of target containers.

## Production images

```text
cerede2000/docker-socket-proxy:latest
ghcr.io/cerede2000/docker-socket-proxy:latest
```

Docker Hub is the primary registry; GitHub Container Registry is also available. Both images support `linux/amd64` and `linux/arm64`, are built with Go, and run unprivileged on `distroless/static-debian13:nonroot`.

`latest` follows `main`. A Git release `vX.Y.Z` additionally publishes immutable `X.Y.Z` and `X.Y` tags to both registries.

The `integration` branch publishes only the mutable `integration` tag. It never replaces `latest` or a release tag.

## Upgrade notes

The next release tightens several permissions and may require profile changes. Container inspection needs `allow_inspect: true`; creating exec sessions needs both `exec: true` and `post: true`; and scoped profiles cannot perform global image, volume, or network writes. Unknown CLI profile options are rejected so that a typo cannot silently produce an unintended policy.

Review the complete migration checklist in [CHANGELOG.md](CHANGELOG.md) before moving an existing deployment from `1.1.2` or an older image. Test with the `integration` tag first, then use the immutable release tag when it is published.

The published image is continuously analysed by [Docker Scout](https://scout.docker.com/reports/org/cerede2000/images/host/hub.docker.com/repo/cerede2000%2Fdocker-socket-proxy). The live report is linked rather than hard-coded here, so its result always reflects current image and vulnerability data.

## Why this proxy is different

Most Docker socket proxies only filter Docker API endpoint families. This project adds two complementary layers:

1. A **client** receives permissions through a profile, discovered from its Docker label (`socketproxy.role`).
2. Permissions are then scoped to the **target** container: all containers, an allowlist, a blacklist, or explicit `deny` and `readonly` exceptions.

This lets an operator such as Portainer retain broad access where it is genuinely needed, while Traefik Manager can inspect and restart only `traefik`. A cached container-name / ID mapping keeps normal scoped checks fast and is applied consistently to lists, events, and direct requests.

## Security model

- No permission is granted implicitly.
- Only containers with `socketproxy.role` (or the `socketproxy.service` alias) that match a configured profile can access the proxy.
- The proxy only keeps client IP addresses shared with its own Docker networks.
- Container lists, events, and targeted operations obey the same target scope.
- The internal name / ID cache avoids an additional Docker request for usual authorization checks.
- The local `/version` health check is accepted without a profile only from the loopback interface. Do not use host networking or publish port `2375`.
- For scoped profiles, non-container Docker events are intentionally omitted because they cannot be tied safely to an authorized container.

## Quick start

Create `profiles.yml`, then start the proxy. The `:ro` socket mount only prevents replacement of the Unix socket file; it does **not** make Docker API calls read-only. The proxy policy is the security boundary.

```yaml
services:
  docker-socket-proxy:
    image: cerede2000/docker-socket-proxy:latest
    container_name: docker-socket-proxy
    user: "1000:998" # adapt to an UID:GID allowed to read the host socket
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

The configured account must be able to access the host Docker socket. On Linux, inspect it with `stat -c '%u:%g' /var/run/docker.sock`, then adapt `user`. On some hosts, a derived image that creates a group with the socket's real GID is preferable.

## Assign a client to a profile

Add either label to the client container:

```yaml
labels:
  socketproxy.role: my-profile
  # or: socketproxy.service: my-profile
```

Profiles are reloaded automatically after a `profiles.yml` change. Client IP discovery occurs at startup, after relevant Docker events, and periodically.

## Full example: Traefik and Traefik Manager

Traefik receives only the read access required by its Docker provider. Traefik Manager can inspect and restart **only** the `traefik` container; it cannot affect other containers or create an exec session.

`compose.yml`:

```yaml
services:
  docker-socket-proxy:
    image: cerede2000/docker-socket-proxy:latest
    container_name: docker-socket-proxy
    user: "1000:998" # adapt to the host
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    tmpfs: [/tmp]
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

`profiles.yml`:

```yaml
traefik:
  ping: true
  version: true
  containers: true
  allow_inspect: true
  networks: true
  events: true
  session: true

traefik-manager:
  ping: true
  version: true
  containers: true
  allow_inspect: true
  post: true
  allow_restart: true
  container_scope: allowlist
  allowed_containers:
    - traefik
```

`container_name: traefik` and `allowed_containers: [traefik]` must match exactly. The `traefik-manager` profile grants neither `start` nor `stop`: only `POST /containers/traefik/restart` is allowed.

## Proxy configuration

| Variable | Default | Description |
| --- | --- | --- |
| `DOCKER_SOCKET_PATH` | `/var/run/docker.sock` | Docker Unix socket path |
| `PROXY_PORT` | `2375` | Listen port and built-in healthcheck port |
| `PROXY_LISTEN` | — | Full listen address; takes precedence over `PROXY_PORT` |
| `SOCKETPROXY_PROFILE_FILE` | `/config/profiles.yml` | YAML profile file |
| `DISCOVER_INTERVAL` | `30s` | Container rediscovery interval; Go duration (`15s`) or seconds (`15`) |
| `EVENT_DEBOUNCE_DELAY` | `100ms` | Docker event debounce delay; Go duration or milliseconds |

The equivalent flags take precedence over environment variables: `--listen`, `--socket`, `--profiles`, `--discover-interval`, and `--debounce-delay`.

The healthcheck calls `http://127.0.0.1:$PROXY_PORT/version`. If `--listen` or `PROXY_LISTEN` uses another port, set `PROXY_PORT` to that same port.

### Profile options on the command line

Profiles can also be defined in the container command. Use `--<profile>.<option>=<value>` or `--proxy-<profile>.<option>=<value>`.

```yaml
command:
  - --traefik.ping=1
  - --traefik.containers=1
  - --traefik-manager.container_scope=allowlist
  - --traefik-manager.allowed_containers=traefik
```

CLI lists use comma-separated names. `container_rule` accepts `name:deny` or `name:readonly`. YAML is generally easier to maintain for long-lived configurations.

## Profile reference

Every API family is disabled by default. YAML booleans (`true` / `false`) are recommended.

| Option | Docker API family |
| --- | --- |
| `ping` | `/_ping` |
| `version` | `/version` |
| `info` | `/info` |
| `events` or `event` | `/events` |
| `auth` | `/auth` |
| `build` | `/build` |
| `commit` | `/commit` |
| `configs` | `/configs` |
| `containers` | `/containers` (general family; sensitive sub-routes remain separately gated) |
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

Generic write methods (`POST`, `PUT`, `PATCH`, `DELETE`) remain forbidden even if a family is enabled, unless `post: true` is set. Narrow container lifecycle permissions are independent from that broad switch and can be granted while `post: false`.

| Container option | Route | Requires `post` |
| --- | --- | --- |
| `allow_archive` | `/containers/{id}/archive` | GET/HEAD: no; PUT: yes |
| `allow_changes` | `/containers/{id}/changes` | no |
| `allow_export` | `/containers/{id}/export` | no |
| `allow_inspect` | `/containers/{id}/json` | no |
| `allow_logs` | `/containers/{id}/logs` | no |
| `allow_top` | `/containers/{id}/top` | no |
| `allow_start` | `/containers/{id}/start` | no |
| `allow_stop` | `/containers/{id}/stop` | no |
| `allow_restart` | `/containers/{id}/restart` | no |
| `allow_pause` | `/containers/{id}/pause` | no |
| `allow_unpause` | `/containers/{id}/unpause` | no |
| `allow_kill` | `/containers/{id}/kill` | no |

All these options default to `false`. `allow_restarts` remains an alias for `allow_restart`; unlike LinuxServer's grouped switch, it deliberately does not silently grant `stop` or `kill`. Grant those operations explicitly when required.

Creating an exec session with `POST /containers/{id}/exec` requires all three explicit grants: `containers: true`, `exec: true`, and `post: true`. `allow_all` never enables `exec`.

`GET /containers/{id}/stats` deliberately remains part of the general `containers` read permission. It exposes runtime telemetry, follows the configured container scope, and has no independent `allow_stats` switch.

`allow_all: true` is a grouped but scoped convenience shortcut for every `allow_*` option in the table. It is deliberately **not** a global Docker permission: it does not enable `containers`, `exec`, `post`, any other API family, or bypass container scopes. Archive upload and other generic writes therefore still require `post: true`. Treat it as a high-impact permission: `export` can read the complete container filesystem and archive reads can disclose arbitrary files inside the selected container.

Minimal lifecycle-only example:

```yaml
container-operator:
  ping: true
  version: true
  containers: true
  post: false
  allow_start: true
  allow_stop: true
  allow_restart: true
  allow_pause: true
  allow_unpause: true
```

Complete targeted container controls, without enabling unrelated Docker API families:

```yaml
container-manager:
  containers: true
  post: true
  allow_all: true
```

`apirewrite` forces a Docker API version for a profile, for example `apirewrite: "1.53"`.

## Container scope

Names are Docker container names without the `/` prefix. Scope rules apply to lists, events, inspect, logs, stats, exec, network operations, and targeted actions.

### Scope limits

Container scope applies only where a Docker request can be tied to a container. For a scoped profile, global container operations (`create`, `prune`) and destructive image, volume, or non-targeted network writes are denied. Read access to the `images`, `volumes`, and global `networks` families is not filtered per container. Avoid granting these families together with `post: true` unless the client genuinely administers the whole host.

### Broad access: `all`

`all` is the default. The profile keeps its rights over every container; add a `deny` rule to remove a critical target.

```yaml
portainer:
  ping: true
  version: true
  containers: true
  allow_inspect: true
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

### Minimum access: `allowlist`

Containers absent from `allowed_containers` are hidden and inaccessible.

```yaml
traefik-manager:
  containers: true
  allow_inspect: true
  post: true
  allow_restart: true
  container_scope: allowlist
  allowed_containers: [traefik]
```

### Broad access with exclusions: `blacklist`

Containers in `blocked_containers` are hidden and every operation targeting them is rejected.

```yaml
dockhand:
  ping: true
  containers: true
  allow_inspect: true
  events: true
  post: true
  allow_start: true
  allow_stop: true
  allow_restart: true
  container_scope: blacklist
  blocked_containers: [docker-socket-proxy]
```

### Per-container exceptions: `container_rules`

`container_rules` takes precedence over the scope. `deny` fully hides the target. `readonly` keeps it visible in lists and events, and permits only `inspect`, `logs`, `stats`, `top`, and `changes`; actions, exec, archives, and attach remain forbidden.

```yaml
dockhand:
  containers: true
  allow_inspect: true
  events: true
  post: true
  allow_start: true
  allow_stop: true
  allow_restart: true
  container_scope: blacklist
  blocked_containers: [docker-socket-proxy]
  container_rules:
    - name: dockman
      access: readonly
```

A target cannot appear in both `blocked_containers` and `container_rules`. Valid access values are `deny` and `readonly`. `container_scope: all` cannot contain an allowlist or blacklist; `allowlist` cannot contain `blocked_containers`; `blacklist` cannot contain `allowed_containers`.

When any scope is active (`allowlist`, `blacklist`, or a named rule), global `create` and `prune` operations are rejected so they cannot bypass the target restriction.

## Network and TLS

The proxy is designed for **local Docker Engine communication**:

```text
Docker client -- private HTTP --> docker-socket-proxy -- Unix socket --> dockerd
```

- The proxy-to-Docker connection uses `DOCKER_SOCKET_PATH` (default `/var/run/docker.sock`). It does not cross a network, therefore does not use TLS, certificates, or a certificate authority (CA).
- The proxy does not make outgoing HTTPS connections and does not support a remote Docker Engine configured through `DOCKER_HOST=tcp://…`.
- Port `2375` intentionally uses plain HTTP. It must be reachable **only** on an internal Docker network shared with authorized clients. Do not add `ports:`, expose it through Traefik or a load balancer, or publish it to the Internet.
- `internal: true` reduces exposure, but every container attached to that network remains a potential client. Attach only the proxy and services that actually need Docker API access.

This is the same model used by the Tecnativa and LinuxServer socket proxies: network isolation and API filtering replace TLS termination for a port that must never be published. If you need cross-host access, deploy a local proxy per host rather than extending this port; client/profile association relies on local Docker networks.

`distroless/static-debian13:nonroot` fits this design. The Go binary is built with `CGO_ENABLED=0`, with no dependency on `glibc`, OpenSSL, or a CA store. Adding CA certificates would not strengthen this configuration; they would only become useful if a future feature introduced outgoing HTTPS or mTLS.

## Operations

The proxy logs profile discovery and denials. A client with no role, an unknown role, or no shared network with the proxy receives `403 Forbidden`.

## Development

```bash
go test -race ./...
go vet ./...
```

## License

Licensed under the [MIT License](LICENSE).
