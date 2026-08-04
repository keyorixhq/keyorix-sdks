# Keyorix SDKs

Official client libraries for [Keyorix](https://github.com/keyorixhq/keyorix), a
lightweight on-premise secrets manager. Each language lives in its own
subdirectory with its own README, tests, and release artifact; this repo keeps
all four versioned, licensed, and released together rather than as four
independently-drifting repos (see
[ADR-072](https://github.com/keyorixhq/keyorix/blob/main/docs/adr-072-sdk-consolidation.md)
in the main repo).

| Language | |
|---|---|
| Go | [`go/`](go/README.md) |
| Node.js | [`node/`](node/README.md) |
| Python | [`python/`](python/README.md) |
| Java | [`java/`](java/README.md) |

SDK versions track the Keyorix HTTP API contract, not the server's own release
version. That contract —
[`server/http/handlers/openapi.yaml`](https://github.com/keyorixhq/keyorix/blob/main/server/http/handlers/openapi.yaml)
in [`keyorixhq/keyorix`](https://github.com/keyorixhq/keyorix) — is authoritative;
each SDK's own README documents what subset of it that language currently covers.
