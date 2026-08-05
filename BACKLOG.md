# Keyorix SDKs Backlog

Working list of upcoming and deferred work. Newest decisions at the top of
each section. For architectural rationale see the `keyorix` repo's ADRs
(`docs/adr-072-sdk-consolidation.md` and successors).

## In progress / next

- **All four SDKs: errors embed the raw server response body verbatim.**
  Also found during Phase 7. On any non-2xx response — including the
  get-secret-value call specifically — every SDK's shared request-error
  path embeds the server's raw response body into the thrown
  error/exception message (`go/keyorix.go`, `node/keyorix.js`,
  `python/keyorix.py`, `java/KeyorixClient.java` all do this identically).
  Low practical risk today (a *failed* request didn't return the secret
  value itself), but it's an unconditional trust-and-relay of upstream
  content into a client-facing error that every SDK's own README
  quick-start passes straight to `log.Fatal(err)` / `console.error` /
  equivalent — exactly the path that lands in application logs and stack
  traces. This is the concrete candidate for the generation ADR's required
  redaction test; the Go MCP server's `genericReadError`
  (`internal/mcp/tools.go` in the `keyorix` repo) is the in-house
  precedent to follow — a generic client-facing message, with the real
  detail logged separately for an operator, not echoed back verbatim. Not
  implemented here — backlog entry only.

## Done

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
