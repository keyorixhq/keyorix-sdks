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
| `POST /auth/login` | ✅ | ✅ | ✅ | ✅ |
| `GET /health` | ✅ | ✅ | ✅ | ✅ |
| `GET /api/v1/projects` | ✅ | ✅ | ✅ | ✅ |
| `POST /api/v1/projects` (create) | ✅ | ✅ | ✅ | ❌ not implemented |
| `GET /api/v1/projects/{id}/environments` | ✅ | ✅ | ✅ | ✅ |
| `GET /api/v1/secrets` (list, scoped) | ✅ | ✅ | ✅ | ✅ |
| `GET /api/v1/secrets/{id}?include_value=true` | ✅ | ✅ | ✅ | ✅ |

The Java SDK's missing `createProject` is a real feature gap versus the
other three (found during the SDKS track's 2026-09-25 inventory, not a
defect in existing code) — out of scope to add here since it's new
functionality, not a fix to something broken. See the `keyorix` repo's
`~/proj/prompts/reports/SDKS.md` track report for the full inventory this
table summarizes.

This repo calls 7 of `server/http/handlers/openapi.yaml`'s 126+ documented
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
| MFA step-up during login | not implemented in any SDK | not implemented in any SDK | not implemented in any SDK | not implemented in any SDK |

A fresh machine identity holds no roles by default — the "machine identity
token" row verifies the token *authenticates* (rejected with
403/`ForbiddenError`, not 401/`AuthError`), which is the correct proof that
the token is recognized as valid, distinct from being authorized for a
specific action. MFA is a real, documented gap (login returns
`mfa_required: true` when an account has TOTP/passkey enrolled; no SDK
handles that response) — not exercised by the bootstrap-seeded admin used
in these tests, and out of scope for this pass.

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
