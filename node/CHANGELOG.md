# Changelog

All notable changes to the Node.js SDK are documented here.

## v0.3.0 (unreleased)

### Fixed

- **`Secret`/`Project`/`Environment` wire field reads updated to snake_case**
  (`id`, `name`, `project_id`, `created_at`, `description`, `type`), matching
  the server's current response shape since keyorixhq/keyorix#2098 and #2128
  (both merged 2026-09-26). Unlike Go, Node has no case-insensitive fallback
  at all — every field of these three types came back `undefined` on
  `main`, silently, with no exception anywhere. Proven red without this fix
  / green with it via `node/contract-test.js` against a real server built
  from keyorix `main`.

### Breaking

- **`getSecret`/`listSecrets` (environment-only) removed.** An environment
  name is only unique within one project, not globally — scoping by
  environment name alone could silently resolve to another project's
  same-named secret. Both now always throw `KeyorixError` without ever
  contacting the server (no silent fallback to the old, unscoped behavior).
  Use the new scoped methods instead.

### Added

- `Client.listSecretsScoped(project, environment)` and
  `Client.getSecretScoped(name, project, environment)`, scoped to a
  project + environment via `project_id`/`environment_id` — not the
  `environment` (name) query parameter the server has rejected with 400
  since keyorix [#2013](https://github.com/keyorixhq/keyorix/pull/2013).
  `project`/`environment` accept either a name (resolved to an ID via the
  server and cached on the `Client`) or a numeric ID (no resolution round
  trip).
- `AmbiguousSecretError`, thrown by `getSecretScoped` when a name matches
  more than one secret in scope (`.ids` lists every match) — it never
  guesses which one was meant.

See keyorixhq/keyorix-sdks#35 for the finding this closes.

## v0.2.1 and earlier

Not tracked in this file — see git history.
