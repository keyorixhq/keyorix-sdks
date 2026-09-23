# Changelog

All notable changes to the Python SDK are documented here.

## v0.3.0 (unreleased)

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
