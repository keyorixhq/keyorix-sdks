# SDK / server compatibility

All four SDKs in this repo (`go/`, `node/`, `python/`, `java/`) release
together at one `vX.Y.Z` tag and cover the same server API surface: login,
health, `ListProjects`/`CreateProject`, `ListEnvironments`,
`ListSecretsScoped`/`GetSecretScoped` (read-only for secret values — none of
the four SDKs can create/update/delete a secret). See each language's own
README `## API` section for its exact method signatures, and ADR-072 in the
[`keyorix`](https://github.com/keyorixhq/keyorix) repo for why the four are
consolidated here.

## What "compatible" means

Compatibility is enforced by [`.github/workflows/contract.yml`](.github/workflows/contract.yml),
not asserted by hand: every push/PR builds `keyorix-server` from the ref in
[`.keyorix-server-ref`](.keyorix-server-ref) (currently `main` — a moving
target, deliberately: see that workflow's own header comment for why a fixed
release tag would miss exactly the drift this exists to catch) and runs each
SDK's contract test suite against it —
`go/contract_test.go`, `node/contract-test.js`,
`python/test_keyorix_contract.py`,
`java/src/test/java/com/keyorix/ContractTest.java`. Each covers the SDK's
full public surface: health, list/create project, list environments,
list/get a secret's value — against a freshly self-bootstrapped server, not
a shared fixture. A row below is "known-compatible" only for a version pair
where that suite was actually green; it is not a promise about versions that
weren't tested.

## Known-compatible versions

| SDK version | Server ref tested | Server commit | Date verified | Result |
|---|---|---|---|---|
| 0.3.0 (go/node/python/java, unreleased) | `main` | `60cb69e2` | 2026-09-25 | Green — full contract suite (see table below) |
| 0.3.0 (go/node/python/java, unreleased) | `main` | `c5be894d` | 2026-09-28 | Green, after landing keyorixhq/keyorix-sdks#39-#41 (see Session K report) — see "What changed" below |
| unreleased + MFA error + `purgeAt` (go/node/python/java) | `main` | - | - | `purgeAt` contract test runs in CI against the SQLite contract server (`security.require_mfa: false`); the MFA login error is covered by mock-server unit tests, not the contract suites |

### Minimum server version

| Feature | Minimum keyorix server |
|---|---|
| Everything in the 0.3.0 rows above | as before (not re-derived here) |
| `MFARequiredError`/`verify_mfa` — the `POST /auth/login` → `mfa_required` + `mfa_challenge`, `POST /auth/mfa/verify` flow (TOTP and recovery codes) | v0.4.0 (ADR-034). The `totp_available`/`webauthn_available` flags are read as false when an older server omits them. |
| `purgeAt` / `listDeletedSecrets` (`GET /api/v1/projects/{id}/secrets/deleted`, `purge_at`) | v0.96.0 (keyorix #3021, RETENTION-1). On an older server the call fails with the server's own 404/403 and `purgeAt` stays empty. |

The MFA tag floor comes from `git tag --contains` of the commit that added
`server/http/handlers/mfa.go`; the `purgeAt` floor from the same check on
#3021. Neither is exercised against those old releases by CI (the contract job
builds `main`).

No `vX.Y.Z` tag has been cut for this repo yet (see BACKLOG.md and the
NEEDS ANDREI at the end of this file); the rows above reflect the
pre-release `0.3.0` state committed to `go.mod`/`package.json`/
`pyproject.toml`/`pom.xml` today. Add a row here on every release, not on
every commit — this table tracks release-to-release compatibility, not a
running log (the CI job itself is the running log; see its own history
for per-commit results).

### What changed between the two 0.3.0 rows above

The 2026-09-28 verification is not a re-run of the same claim — it follows
a real, live break found and fixed in between (Session K, this repo's PRs
#39-#41):

- keyorix PRs #2098/#2128 (both merged 2026-09-26, after the first row's
  verification date) migrated `Secret`/`Project`/`Environment` wire JSON
  to snake_case. All four SDKs were broken on `main` until PR #39 fixed
  the field mappings — confirmed red without the fix, green with it, all
  four languages independently (keyorix-sdks#39).
- Every request path across all four SDKs now returns/throws a typed
  `AuthError`/`ForbiddenError`/`NotFoundError` (401/403/404) instead of
  one generic error type (keyorix-sdks#40).
- Node and Python can now be pointed at a server using a private/internal
  CA (`opts.ca` / `ca_file`); Go already supported this via
  `WithHTTPClient` (keyorix-sdks#40).
- PAT auth and machine-identity-token auth are now exercised live against
  a real server in every contract test, not just documented as expected
  to work — confirming the server presents all three token types
  (session/PAT/machine) identically (keyorix-sdks#41).
- Fixed two real bugs surfaced by adding a genuine timeout-behavior test
  (not just asserting the configured value): Node's `timeout` option was
  silently decorative (no `'timeout'` handler aborted the request);
  Python's real timeout raised a bare, undocumented `TimeoutError` that
  bypassed every `except URLError` handler (keyorix-sdks#41).

## Per-endpoint coverage (as of the verification above)

| Endpoint | Go | Node | Python | Java |
|---|---|---|---|---|
| `POST /auth/login` (incl. the `mfa_required` response → typed MFA error) | ✅ | ✅ | ✅ | ✅ |
| `POST /auth/mfa/verify` (TOTP / recovery code) | ✅ | ✅ | ✅ | ✅ |
| `GET /health` | ✅ | ✅ | ✅ | ✅ |
| `GET /api/v1/projects` | ✅ | ✅ | ✅ | ✅ |
| `POST /api/v1/projects` (create) | ✅ | ✅ | ✅ | ✅ |
| `GET /api/v1/projects/{id}/environments` | ✅ | ✅ | ✅ | ✅ |
| `GET /api/v1/secrets` (list, scoped) | ✅ | ✅ | ✅ | ✅ |
| `GET /api/v1/secrets/{id}?include_value=true` | ✅ | ✅ | ✅ | ✅ |
| `GET /api/v1/projects/{id}/secrets/deleted` (`purge_at`) | ✅ | ✅ | ✅ | ✅ |

The SDKS track's 2026-09-25 inventory (see the `keyorix` repo's
`~/proj/prompts/reports/SDKS.md` track report) found Java without
`createProject`; it was added afterwards, so all four languages now cover the
same endpoints.

This repo calls 9 of `server/http/handlers/openapi.yaml`'s 126+ documented
paths (ADR-072 recorded a 4/126 baseline in 2026-08-04 before
`ListProjects`/`CreateProject`/`ListEnvironments` were added). Generating
SDK clients directly from the OpenAPI spec — ADR-072's own recorded
follow-on — would close this gap in one step rather than hand-adding
endpoints one at a time; not done here.

## Auth methods (verified live, Session K)

None of these are separate SDK API calls — the server accepts all three
identically via `Authorization: Bearer <token>`, dispatched by prefix
(`server/middleware/auth.go`). Verified by constructing the SDK client
directly with each token type against a real server and confirming the
expected outcome, not just read from server source:

| Auth method | Go | Node | Python | Java |
|---|---|---|---|---|
| Session token (from `login`/`Login`) | ✅ | ✅ | ✅ | ✅ |
| Personal access token (PAT) | ✅ | ✅ | ✅ | ✅ |
| Machine identity token | ✅ | ✅ | ✅ | ✅ |
| MFA (TOTP / recovery code) second step during login | ✅ `*MFARequiredError` + `VerifyMFA` | ✅ `MFARequiredError` + `verifyMfa` / `login(.., { mfaCode })` | ✅ `MFARequiredError` + `verify_mfa` / `login(.., mfa_code=)` | ✅ `MFARequiredException` + `verifyMfa` / `login(.., mfaCode)` |
| Passkey (WebAuthn) second factor | not supported | not supported | not supported | not supported |

A fresh machine identity holds no roles by default — the "machine identity
token" row verifies the token *authenticates*, which is the correct proof that
the token is recognized as valid, distinct from being authorized for a
specific action. The server's rule for a caller with zero grants (decided
2026-10-17):

- **list routes** (`ListProjects`, ...) are filtered by permission: an empty
  `200` with no items, not an error;
- **single-object reads** (`GET /projects/{id}`) are `403` /
  `ForbiddenError`;
- **a bad or expired token** is `401` / `AuthError`.

The contract suites in all four SDKs assert all three.

Login returns `mfa_required: true` plus a single-use `mfa_challenge` when an
account has TOTP/passkey enrolled; every SDK now surfaces that as a typed error
carrying the challenge (previously Go reported "no token in login response" and
the others a generic auth error) and completes it with a TOTP or recovery code.
The CI contract server runs with `security.require_mfa: false`, so the contract
suites do not exercise MFA login; the typed error and the verify step are
covered by mock-server unit tests in each SDK. Passkey accounts get the typed
error with `webauthnAvailable` set, but the passkey ceremony itself is not
implemented. The server confines a session that still owes MFA enrolment
(`security.require_mfa`, on by default since ADR-112) to the enrolment endpoints
with `403 MFAEnrollmentRequired`; that is a different state from an enrolled
account's login challenge, and the SDKs map it to `ForbiddenError` as before.

## Release status

**NEEDS ANDREI**: no `vX.Y.Z` tag or GitHub release has ever been cut for
this repo (zero tags, zero releases, confirmed via the GitHub API) despite
ADR-072 designating `v0.3.0` as this repo's first release almost two
months ago (2026-08-04). Everything a release needs is otherwise ready:
`go.mod`/`package.json`/`pyproject.toml`/`pom.xml` all agree on `0.3.0`,
every CHANGELOG.md carries a populated "v0.3.0 (unreleased)" section, and
this file's compatibility table is current as of the commit landing this
paragraph. Publishing to npm/PyPI additionally remains blocked on the
defensive package-name registration ADR-072 itself flagged as a
prerequisite (`@keyorixhq` npm scope, `keyorix` on PyPI) — not performed
by this session, per this session's own instruction not to publish.
Cutting the tag (`git tag v0.3.0 && git tag go/v0.3.0`, both pushed) and
completing that registration are the two remaining human actions.
