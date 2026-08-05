# Keyorix SDKs Backlog

Working list of upcoming and deferred work. Newest decisions at the top of
each section. For architectural rationale see the `keyorix` repo's ADRs
(`docs/adr-072-sdk-consolidation.md` and successors).

## In progress / next

- **All four SDKs: restrict URL schemes on the caller-supplied server URL.**
  Found during ADR-072's Phase 7 supply-chain audit. `python/keyorix.py`
  calls `urllib.request.urlopen` on `server_url` with no scheme
  restriction, producing 4 Medium bandit findings (B310) currently
  suppressed by `continue-on-error: true` in `python.yml`. In a general
  library this is a Medium; in a secrets client it is the difference
  between reaching the vault and silently reading a local file or reaching
  an unintended host, whenever `server_url` originates from an env var or
  config an attacker can influence. Reachable schemes include `file://`
  and `ftp://`. Fix: allow `https://` only, with `http://` permitted
  solely for explicit localhost/loopback — matching the pattern the Go MCP
  server's `KEYORIX_URL` validation already establishes in the `keyorix`
  repo (`docs/mcp.md`'s "HTTPS enforced" section). This is a per-language
  HTTP client concern, not Python-specific — the other three SDKs
  (`go/keyorix.go`, `node/keyorix.js`, `java/KeyorixClient.java`) all
  build their request URL from the same kind of caller-supplied base URL
  and need the same audit, not just Python's. Not implemented here —
  backlog entry only.

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
