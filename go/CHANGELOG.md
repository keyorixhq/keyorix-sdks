# Changelog

All notable changes to the Go SDK are documented here.

## v0.3.0 (unreleased)

### Breaking

- **`GetSecret`/`ListSecrets` (environment-only) removed.** An environment
  name is only unique within one project, not globally — scoping by
  environment name alone could silently resolve to another project's
  same-named secret. Both now always return an error without ever
  contacting the server (no silent fallback to the old, unscoped behavior).
  Use the new scoped methods instead.

### Added

- `Client.ListSecretsScoped(ctx, project, environment)` and
  `Client.GetSecretScoped(ctx, name, project, environment)`, scoped to a
  project + environment via `project_id`/`environment_id` — not the
  `environment` (name) query parameter the server has rejected with 400
  since keyorix v[#2013](https://github.com/keyorixhq/keyorix/pull/2013).
- `ProjectByName`/`ProjectByID` and `EnvironmentByName`/`EnvironmentByID`
  constructors for `ProjectRef`/`EnvironmentRef`. A name-based ref is
  resolved to an ID via the server and cached on the `Client` for its
  lifetime; an ID-based ref skips resolution entirely.
- `SecretNotFoundError` and `AmbiguousSecretError`, returned by
  `GetSecretScoped` when a name matches zero or more than one secret in
  scope, respectively. `GetSecretScoped` never guesses which match was
  meant — `AmbiguousSecretError.IDs` lists every match.

See keyorixhq/keyorix-sdks#35 for the finding this closes.

## v0.2.1 and earlier

Not tracked in this file — see git history.
