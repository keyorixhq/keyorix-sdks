# Changelog

All notable changes to the Go SDK are documented here.

## Unreleased

### Added

- `CreateSecret(ctx, project, environment, name, value, opts...)` creates a secret (`POST /api/v1/secrets`) in a project+environment given by name or ID and returns its metadata. A taken name returns the new `*SecretAlreadyExistsError` (unwraps to `*APIError`). The value never appears in an error's text and is stripped from `APIError.Body` if the server echoes it.
- `login` on an account with a second factor (MFA, the server default) now throws/raises/returns a typed MFA-required error carrying the challenge id and the available methods, instead of a generic "no token in login response". Complete it with the new `verifyMfa`/`verify_mfa`/`VerifyMFA` (TOTP or recovery code). Node, Python and Java: the new type extends the auth error `login` already threw, so existing handlers keep working.
- `APIError.Code` carries the server's stable error code, and a value read the secret's own state refuses (server ERRMAP-1) is typed: 409 `SecretExpired` / `SecretSuspended` / `SecretMaxReadsExhausted` returns `*SecretUnavailableError` (unwraps to `*APIError`); a read outside the secret's access schedule stays `*ForbiddenError` (Code `SecretAccessOutsideSchedule`) with an accurate message. Error text is local, never the server's body. Against an older server these reads still return the generic `*APIError` (500).

### Documentation and tests

- README: new Errors section (`AuthError`, `ForbiddenError`, `NotFoundError`,
  `SecretNotFoundError`, `AmbiguousSecretError`) and the Go requirement now
  matches `go.mod` (1.26.2, was documented as 1.21+).
- Contract test: a fresh machine-identity token now expects `ListProjects` to
  succeed with an empty list (keyorix #2780) and `GET /projects/{id}` to be
  403; a bad token still gives `*AuthError`.
- `Secret.PurgeAt` (`*time.Time`) and `Client.ListDeletedSecrets(ctx, project)`
  (`GET /api/v1/projects/{id}/secrets/deleted`): the restore deadline of a
  soft-deleted secret. Needs server v0.96.0+.

## v0.3.0 — 2026-10-02

### Added

- `Client.GetSecretByRef(ctx, ref)` (`GET /api/v1/secrets/value?ref=project/environment/name`)
  and `Client.GetSecretIn(ctx, project, environment, name)` (a thin wrapper
  that builds the ref). Both resolve and authorize in a single round trip and
  need no project/environment-list permission, unlike `GetSecretScoped` —
  the shape a machine token scoped to exactly one project needs. Errors map
  through the existing `errorForResponse` (`AuthError`/`ForbiddenError`/
  `NotFoundError`/generic `*APIError`), reusing the typed errors added below
  rather than a second error set.

### Fixed

- **`ListSecretsScoped` silently truncated at the server's default page size
  (20).** It never sent `page`/`page_size` at all, so a project+environment
  with more than 20 secrets lost the rest with no error. Now follows every
  page the server reports (`total_pages`) at `page_size=100`.

### Added

- `AuthError` (401), `ForbiddenError` (403), and `NotFoundError` (404) —
  every request path now returns a typed error `errors.As` can distinguish,
  instead of one generic `*APIError` for everything. All three unwrap to
  `*APIError`, so existing `errors.As(&apiErr)` callers keep working
  unchanged. Also fixes an inconsistency in `ListSecretsScoped`, which used
  to return a bare, untyped `fmt.Errorf` on 401 instead of `*APIError`.

### Fixed

- **`Secret`/`Project`/`Environment` wire field tags updated to snake_case**
  (`id`, `name`, `project_id`, `created_at`, `description`, `type`), matching
  the server's current response shape since keyorixhq/keyorix#2098 and #2128
  (both merged 2026-09-26). `encoding/json`'s case-insensitive fallback had
  been silently masking single-word fields (`ID`↔`id`) but not multi-word
  ones — `ProjectID`/`CreatedAt` were both zeroing out silently on `main`.
  Proven red without this fix / green with it via `go/contract_test.go`
  against a real server built from keyorix `main`.

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
