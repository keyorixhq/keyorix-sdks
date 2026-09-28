# Changelog

All notable changes to the Python SDK are documented here.

## v0.3.0 (unreleased)

### Added

- `ForbiddenError` (403) and `NotFoundError` (404), alongside the existing
  `AuthError` (401) — every request path now raises a typed error
  `isinstance()` can distinguish, instead of one generic `KeyorixError` for
  everything.
- `Client` constructor parameter `ca_file` — path to a PEM file of trusted
  CA certificate(s), for servers using a private/internal CA. No effect on
  plain `http://` (loopback-only) connections.

### Fixed

- **`Secret`/`Project`/`Environment` wire field reads updated to snake_case**
  (`id`, `name`, `project_id`, `created_at`, `description`, `type`), matching
  the server's current response shape since keyorixhq/keyorix#2098 and #2128
  (both merged 2026-09-26). `dict.get(key, default)` was the worst-case
  failure mode of any SDK here — every field of these three types silently
  fell back to its default (`0`/`""`) on `main`, not even a `KeyError`.
  Proven red without this fix / green with it via
  `python/test_keyorix_contract.py` against a real server built from
  keyorix `main`.

### Breaking

- **`get_secret`/`list_secrets` (environment-only) removed.** An environment
  name is only unique within one project, not globally — scoping by
  environment name alone could silently resolve to another project's
  same-named secret. Both now always raise `KeyorixError` without ever
  contacting the server (no silent fallback to the old, unscoped behavior).
  Use the new scoped methods instead.

### Added

- `Client.list_secrets_scoped(project, environment)` and
  `Client.get_secret_scoped(name, project, environment)`, scoped to a
  project + environment via `project_id`/`environment_id` — not the
  `environment` (name) query parameter the server has rejected with 400
  since keyorix [#2013](https://github.com/keyorixhq/keyorix/pull/2013).
  `project`/`environment` accept either a name (resolved to an ID via the
  server and cached on the `Client`) or a numeric ID (no resolution round
  trip).
- `AmbiguousSecretError`, raised by `get_secret_scoped` when a name matches
  more than one secret in scope (`.ids` lists every match) — it never
  guesses which one was meant.

See keyorixhq/keyorix-sdks#35 for the finding this closes.

## v0.2.1 and earlier

Not tracked in this file — see git history.
