# Keyorix SDKs Backlog

Working list of upcoming and deferred work. Newest decisions at the top of
each section. For architectural rationale see the `keyorix` repo's ADRs
(`docs/adr-072-sdk-consolidation.md` and successors).

## In progress / next

- **NEEDS ANDREI: cut the first `v0.3.0` release.** No `vX.Y.Z` tag or
  GitHub release has ever been cut for this repo (zero tags, zero
  releases) despite ADR-072 designating `v0.3.0` as this repo's first
  release on 2026-08-04 — see COMPATIBILITY.md's "Release status" section
  for the full detail. Everything else is release-ready as of Session K
  (2026-09-28): manifests agree on `0.3.0`, CHANGELOGs are current,
  compatibility matrix verified live. Publishing to npm/PyPI additionally
  needs the defensive package-name registration ADR-072 flagged
  (`@keyorixhq` npm scope, `keyorix` on PyPI) — not done by any session to
  date. Two remaining actions, both requiring Andrei: cut+push the tags
  (`v0.3.0`, `go/v0.3.0`), and complete the registration before publishing.

## Done

- **All four SDKs: Session K fixes (snake_case wire break, typed errors,
  private-CA TLS, PAT/machine-token auth verified live, 2 real timeout
  bugs).** 2026-09-28. keyorix-sdks#39-#42. keyorix PRs #2098/#2128
  (merged 2026-09-26) migrated `Secret`/`Project`/`Environment` wire JSON
  to snake_case, breaking all four SDKs on `main`; fixed and
  red/green-proofed per language (#39). Added `AuthError`/
  `ForbiddenError`/`NotFoundError` (401/403/404) across all four, and
  private-CA support for Node/Python (Go already had it) — verified
  end-to-end against a real throwaway-cert TLS server, not just plumbed
  through (#40). Extended every contract test to actually construct the
  SDK client with a real PAT and a real machine identity token against a
  live server (not just read from server source) — found and fixed two
  real bugs doing it: Node's `timeout` option was silently decorative (no
  handler ever aborted the request), and Python's real timeout leaked a
  bare `TimeoutError` past every `except URLError` handler (#41). Led
  every README with a machine identity token instead of password login,
  matching the auth-parity finding above (#42). Full detail: `keyorix`
  repo's `~/proj/prompts/reports/SESSION-K.md`.

- **All four SDKs: contract tests against a real keyorix-server + CI wiring.**
  Added 2026-09-25 (keyorix repo's SDKS track). Each language now has a
  self-contained contract test (`go/contract_test.go`,
  `node/contract-test.js`, `python/test_keyorix_contract.py`,
  `java/src/test/java/com/keyorix/ContractTest.java`) that bootstraps its own
  admin session against a real, freshly-built keyorix-server (not a mock) and
  exercises the SDK's full public surface — health, list/create project,
  list environments, list/get a secret's value — asserting the exact wire
  shapes the SDK parses. All four were green against `keyorixhq/keyorix`
  main @ `60cb69e2` (2026-09-25) — no PascalCase/snake_case parsing breakage
  found on the endpoints these SDKs currently call (contrary to the initial
  concern that #2088/#2098 had already broken them: #2088 only touched
  audit/access-log endpoints the SDKs don't call, and #2098 — the actual
  SecretNode snake_case migration — was still an open, unmerged PR as of
  this date, not yet on main). Wired into CI via
  `.github/workflows/contract.yml` (new, unconditional job in `ci.yml`'s
  gate) against the ref in `.keyorix-server-ref` (currently `main`, a
  deliberate moving-target choice — see that workflow's header comment).
  This is the tripwire that's meant to catch #2098 (or #2113's gRPC share
  expiry, once an SDK covers gRPC) the moment either actually merges, rather
  than a customer discovering a silently-empty field. See
  `COMPATIBILITY.md` (new) for the resulting version/endpoint matrix and the
  `keyorix` repo's `~/proj/prompts/reports/SDKS.md` track report for the
  full inventory. Found, not fixed (out of scope — new functionality, not a
  defect): the Java SDK has no `createProject` method, unlike the other
  three languages.

- **All four SDKs: errors embed the raw server response body verbatim.**
  Found during ADR-072's Phase 7 supply-chain audit. On any non-2xx
  response — including the get-secret-value call specifically — every
  SDK's shared request-error path embedded the server's raw response body
  into the thrown error/exception message (`go/keyorix.go`,
  `node/keyorix.js`, `python/keyorix.py`, `java/KeyorixClient.java` all
  did this identically): an unconditional trust-and-relay of upstream
  content into a client-facing error that every SDK's own README
  quick-start passes straight to `log.Fatal(err)` / `console.error` /
  equivalent. Fixed: the exception/error message is now generic
  (`"server returned <status>"`), following the Go MCP server's
  `genericReadError` precedent (`internal/mcp/tools.go` in the `keyorix`
  repo). The raw status code and body remain available to callers who
  explicitly opt in — `APIError.Body`/`StatusCode` (Go),
  `response_body`/`status_code` (Python), `responseBody`/`statusCode`
  (Node), `getResponseBody()`/`getStatusCode()` (Java) — for their own
  (redacted) logging. See `fix/sdk-error-body-redaction`.

- **All four SDKs: restrict URL schemes on the caller-supplied server URL.**
  Found during ADR-072's Phase 7 supply-chain audit (4 Medium bandit B310
  findings on Python's `urllib.request.urlopen`). Fixed: `server_url`/
  `serverUrl`/`baseUrl` is now validated at client-construction/login time
  in all four SDKs — `https://` is required, with `http://` permitted only
  for localhost/loopback, matching the `keyorix` repo's Go MCP server
  `KEYORIX_URL` precedent (`docs/mcp.md`'s "HTTPS enforced" section).
  Go's `New()` and Java's `KeyorixClient`/`Keyorix.login()` constructors
  now return/throw on an invalid scheme (a breaking API change, acceptable
  pre-1.0). See `fix/sdk-url-scheme-restriction`.
