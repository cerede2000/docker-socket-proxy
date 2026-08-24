# Changelog

All notable changes are documented here. Release tags use semantic versioning.

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
