# Keyorix SDKs Backlog

Working list of upcoming and deferred work. Newest decisions at the top of
each section. For architectural rationale see the `keyorix` repo's ADRs
(`docs/adr-072-sdk-consolidation.md` and successors).

## In progress / next

## Done

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
