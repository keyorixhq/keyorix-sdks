# Changelog

All notable changes to the Java SDK are documented here.

## Unreleased

### Fixed

- A secret value (or any string the SDK reads) containing JSON string escapes
  now comes back exactly as stored. `JsonParser` returned the raw escaped text,
  so `line1\nline2 "q"` arrived as `line1\\nline2 \\"q\\"`, and a value ending
  in a backslash was cut at the wrong quote. It now decodes `\" \\ \/ \b \f \n
  \r \t` and `\uXXXX` (surrogate pairs included); a malformed escape throws
  `IllegalArgumentException` instead of returning an altered value.

### Added

- `login` on an account with a second factor (MFA, the server default) now throws/raises/returns a typed MFA-required error carrying the challenge id and the available methods, instead of a generic "no token in login response". Complete it with the new `verifyMfa`/`verify_mfa`/`VerifyMFA` (TOTP or recovery code). Node, Python and Java: the new type extends the auth error `login` already threw, so existing handlers keep working.
- `KeyorixException.getErrorCode()` carries the server's stable error code, and a value read the secret's own state refuses (server ERRMAP-1) is typed: 409 `SecretExpired` / `SecretSuspended` / `SecretMaxReadsExhausted` throws `SecretUnavailableException`; a read outside the secret's access schedule stays `ForbiddenException` (code `SecretAccessOutsideSchedule`) with an accurate message. Messages are local, never the server's body.
- `Secret.getPurgeAt()` and `KeyorixClient.listDeletedSecrets(projectId)`
  (`GET /api/v1/projects/{id}/secrets/deleted`): the restore deadline of a
  soft-deleted secret. Needs server v0.96.0+.

## v0.3.0 (unreleased)

### Documentation and tests

- README: the quickstart now shows its `Secret`/`List` imports, and the
  exception list includes `ForbiddenException` and `NotFoundException` (what
  `getSecretIn`/`getSecretByRef` throw for a missing secret).
- Contract test: a fresh machine-identity token now expects `listProjects()`
  to succeed with an empty list (keyorix #2780) and `GET /projects/{id}` to
  be 403; a bad token still gives `AuthException`.

### Added

- `KeyorixClient.getSecretByRef(ref)` (`GET /api/v1/secrets/value?ref=project/environment/name`)
  and `KeyorixClient.getSecretIn(project, environment, name)` (a thin
  wrapper that builds the ref). Both resolve and authorize in a single
  round trip and need no project/environment-list permission, unlike
  `getSecretScoped` — the shape a machine token scoped to exactly one
  project needs. Errors map through the existing `mapError`
  (`AuthException`/`ForbiddenException`/`NotFoundException`/generic
  `KeyorixException`), reusing the typed exceptions added below rather
  than a second exception hierarchy.

### Fixed

- **`listSecretsScoped` silently truncated at the server's default page
  size (20).** It never sent `page`/`page_size` at all, so a
  project+environment with more than 20 secrets lost the rest with no
  error. Now follows every page the server reports (`total_pages`) at
  `page_size=100`.

### Added

- `ForbiddenException` (403) and `NotFoundException` (404), alongside the
  existing `AuthException` (401) — every request path now throws a typed
  exception callers can catch specifically, instead of one generic
  `KeyorixException` for everything.
- `KeyorixClient(baseUrl, token, timeout, caCertPath)` constructor overload
  — trusts a private/internal CA (PEM), for servers whose certificate isn't
  signed by a CA in the JVM's default trust store.

### Fixed

- **`Secret`/`Project`/`Environment` wire field lookups updated to
  snake_case** (`id`, `name`, `project_id`, `created_at`, `description`,
  `type`), matching the server's current response shape since
  keyorixhq/keyorix#2098 and #2128 (both merged 2026-09-26).
  `JsonParser`'s exact-string key lookups had no case tolerance at all —
  every field of these three types silently came back as its Java default
  (`0`/`null`) on `main`. Proven red without this fix / green with it via
  `java/src/test/java/com/keyorix/ContractTest.java` against a real server
  built from keyorix `main`.

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
