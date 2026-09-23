# Changelog

All notable changes to the Java SDK are documented here.

## v0.3.0 (unreleased)

### Breaking

- **`getSecret`/`listSecrets` (environment-only) removed.** An environment
  name is only unique within one project, not globally — scoping by
  environment name alone could silently resolve to another project's
  same-named secret. Both now always throw `KeyorixException` without ever
  contacting the server (no silent fallback to the old, unscoped behavior).
  Use the new scoped methods instead.

### Added

- `KeyorixClient.listSecretsScoped`/`getSecretScoped`, each with a
  `(String projectName, String environmentName)` overload (resolved to IDs
  via the server and cached on the client) and a `(long projectId, long
  environmentId)` overload (no resolution round trip). Scoped via
  `project_id`/`environment_id` — not the `environment` (name) query
  parameter the server has rejected with 400 since keyorix
  [#2013](https://github.com/keyorixhq/keyorix/pull/2013).
- `listProjects()` and `listEnvironments(long projectId)`, exposing the
  project/environment catalog this client now resolves against (already
  present in the Go/Python/Node SDKs).
- `AmbiguousSecretException`, thrown by `getSecretScoped` when a name
  matches more than one secret in scope (`getIds()` lists every match) — it
  never guesses which one was meant.
- `Project` and `Environment` model classes.

See keyorixhq/keyorix-sdks#35 for the finding this closes.

## v0.2.1 and earlier

Not tracked in this file — see git history.
