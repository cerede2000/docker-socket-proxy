# Changelog

All notable changes are documented here. Release tags use semantic versioning.

## 1.3.1 - 2026-10-15

### Security

- Go moves to 1.27.2, which closes the thirteen standard library advisories published on 2026-10-08. Nine of them are reachable from this code: five in the HTTP/2 server and transport (`GO-2026-6603`, `GO-2026-6610`, `GO-2026-6611`, `GO-2026-6612`, `GO-2026-6617`), two connection desynchronizations around `CONNECT` in the HTTP/1 server and client (`GO-2026-6613`, `GO-2026-6605`), a memory limit bypass when parsing MIME headers (`GO-2026-6608`) and a malformed ECH extension reference in `crypto/tls` (`GO-2026-6607`). The two desynchronizations carry the most weight here: a proxy stands between a client and the daemon, which is the position where a desynchronized connection becomes request smuggling.
- The vulnerability audit now runs with the Go toolchain the Dockerfile pins, instead of the latest patch of the line declared in `go.mod`. Reading `check-latest` made the gate scan a toolchain that was never shipped, so it reported a clean image while the published one still carried 1.27.1; the advisories were surfaced by the registry rather than by the audit.

### Changed

- Staticcheck moves to 2026.2.2, the first release that reads the export data format of Go 1.27.2.
- The test job takes its toolchain from the same Dockerfile pin. `go 1.27` in `go.mod` resolved to whichever patch was current, so Go moved on its own under a pinned linter: 1.27.2 changed the export data format, 2026.2.1 could no longer read it, and every open pull request failed at once — including the one bumping the image, which is why the fix sat unmerged. The toolchain now only moves with a reviewed change.
- `actions/checkout` moves to 7.0.1, `actions/setup-go` to 7.0.0, `actions/upload-artifact` to 7.0.2 and `github/codeql-action` to 4.38.3.
- Dependabot targets `integration` rather than the default branch, and opens one grouped pull request per ecosystem instead of one per dependency.

## 1.3.0 - 2026-09-25

### Added

- A unix socket frontend: `PROXY_LISTEN_UNIX` / `--listen-unix` binds a socket to a single profile, so the socket path and its file permissions carry the client identity instead of its IP address. `PROXY_LISTEN=off` disables the TCP frontend entirely.
- An end-to-end suite (`e2e/run.sh`, also run in CI) exercises label discovery, container scope, name-to-ID rewriting, response filtering and the unix socket frontend against a real Docker daemon.

### Changed

- Global writes are now refused according to what the scope describes, instead of whenever any scope is set. An `allowlist` lists the profile's whole world, so `containers/create`, `containers/prune` and image, volume or non-targeted network writes stay denied. A `blacklist`, or a `container_rules` exception over `all`, covers everything but its named targets: those writes are allowed again, since refusing creation contradicted the deletion the same profile already permitted.
- The runtime image is now `scratch` instead of `distroless/static-debian13`: it carries the binary and nothing else, so no distribution package remains to patch. The process still runs as UID 65532. There is no `/etc/passwd`, so a compose file must name its user numerically (`user: "65532:65532"`); a name such as `nonroot` no longer resolves.
- The build cross-compiles instead of emulating the target architecture, and fails if the binary ever gains a dynamic interpreter. Go moves to 1.27.1.
- Unit coverage rises from 46% to 83%; discovery, the event loop, profile reloading and the healthcheck were previously untested.

### Security

- A scheduled `Security` workflow runs CodeQL and `govulncheck` weekly, so a vulnerability published against unchanged code is reported instead of waiting for the next push.
- Every GitHub Action is pinned by commit SHA rather than by a movable tag.

### Migration

- Coming from `1.2.0`, no profile change is required: the scope change only widens what a `blacklist` or `container_rules` profile may do, and the unix socket frontend is opt-in. Replace a `user:` given by name with its numeric UID and GID.
- Coming from `1.1.x` or older, follow the `1.2.0` migration notes below as well.

## 1.2.0 - 2026-08-24

### Security

- Container inspection now requires `allow_inspect: true` in addition to `containers: true`.
- Creating an exec session with `POST /containers/{id}/exec` now requires both `exec: true` and `post: true`.
- Scoped profiles can no longer perform global image, volume, or network writes because those operations cannot be tied safely to an authorized target container.
- Uploading an archive with `PUT /containers/{id}/archive` requires both `allow_archive: true` and `post: true`.

### Migration

- Add `allow_inspect: true` to every existing profile that calls `GET /containers/{id}/json`.
- Add `exec: true` to every profile that creates exec sessions; `post: true` alone is no longer sufficient.
- Use an unscoped, explicitly privileged profile only when a client genuinely needs global image, volume, or network writes.
- Unknown CLI profile options are rejected during startup rather than being silently ignored. Correct any reported typo before restarting.

Review and apply the migration notes before upgrading, then pin the immutable `1.2.0` tag instead of relying on `latest`.

## 1.1.2

- Previous stable release. See the Git history for its detailed changes.
