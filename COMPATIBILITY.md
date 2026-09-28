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

No `vX.Y.Z` tag has been cut for this repo yet (see BACKLOG.md); the row
above reflects the pre-release `0.3.0` state committed to `go.mod`/
`package.json`/`pyproject.toml`/`pom.xml` today. Add a row here on every
release, not on every commit — this table tracks release-to-release
compatibility, not a running log (the CI job itself is the running log; see
its own history for per-commit results).

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
