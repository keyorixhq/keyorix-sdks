# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | ✅ Security fixes |
| Older releases | ❌ Upgrade to latest |

Pre-1.0. SDK versions track the Keyorix API contract, not the server's own
version — see
[ADR-072](https://github.com/keyorixhq/keyorix/blob/main/docs/adr-072-sdk-consolidation.md).

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

- Email: **security@keyorix.com**
- Or use GitHub's private vulnerability reporting on this repository

We acknowledge within **48 hours** and provide an initial assessment within
**7 days**. Please include: a description, reproduction steps, and the
affected SDK language + version.

We follow coordinated disclosure: we'll agree a disclosure timeline with you,
credit you in the advisory unless you prefer otherwise, and publish a fix and
advisory together. As an EU vendor we operate under the EU Cyber Resilience
Act reporting regime for actively exploited vulnerabilities.

## Scope

These are thin HTTP clients for the [Keyorix](https://github.com/keyorixhq/keyorix)
API — they hold no secret values beyond what a caller explicitly requests and
receives, and enforce no access control of their own (that happens server-side).
The server's own threat model and security controls (encryption at rest, audit
logging, RBAC) live in the main [`keyorix`](https://github.com/keyorixhq/keyorix)
repo's [SECURITY.md](https://github.com/keyorixhq/keyorix/blob/main/SECURITY.md).
