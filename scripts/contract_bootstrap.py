#!/usr/bin/env python3
"""Bootstrap the contract-test server for the SDK contract suites.

keyorix main enforces MFA by default (security.require_mfa, ADR-112): a
password-only session is confined to MFA enrolment, so the SDKs' own
password login can no longer authenticate the contract tests. This script
does the one-time setup with security.require_mfa left ON:

  1. POST /system/init       -- claim the bootstrap token, create the admin
  2. POST /auth/login        -- password step; gets a setup-only session
  3. POST /auth/mfa/enroll   -- begin TOTP enrolment, receive the seed
  4. POST /auth/mfa/activate -- confirm with a code computed from that seed
  5. POST /auth/login        -- password step again; now an MFA challenge
  6. POST /auth/mfa/verify   -- complete it with a fresh TOTP code
  7. POST /api/v1/auth/tokens -- mint a short-lived PAT from the MFA session

It then creates the fixtures the MFA-login and secret-read-refusal contract tests
need, all through the API with MFA left on:

  * one MFA-enrolled account per SDK (contract-mfa-go/-node/-python/-java), each
    with its own TOTP seed exported as KEYORIX_CONTRACT_MFA_SEED_<LANG> -- the
    server burns a TOTP step per account, so the suites cannot share one seed;
  * one secret per state the server refuses a value read for, in default /
    development: contract-refused-suspended, -expired, -max-reads, -schedule.

The PAT is written to --env-file as KEYORIX_CONTRACT_ADMIN_TOKEN=<token>; every
SDK contract suite reads it from the environment. It is never printed. Under
GitHub Actions it is also registered with ::add-mask::.

The TOTP seed lives only in this process (test-only helper, RFC 6238:
HMAC-SHA1, 30 s step, 6 digits -- what the server validates). The PAT is
unscoped on purpose: the suites create projects, secrets, machine identities
and further PATs, and a scoped PAT cannot mint PATs. It expires in 24 h and
belongs to a throwaway CI account.

Usage:
  KEYORIX_CONTRACT_SERVER_URL=http://localhost:18790 \\
  KEYORIX_CONTRACT_BOOTSTRAP_TOKEN=... \\
  python3 scripts/contract_bootstrap.py --env-file "$GITHUB_ENV"
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

ADMIN_USER = "contract-admin"
ADMIN_EMAIL = "contract-admin@example.com"
ADMIN_PASSWORD = "ContractTestPassw0rd!"  # throwaway CI account, not a secret
TOTP_PERIOD = 30

# One MFA account per SDK suite (username contract-mfa-<lang>, this password).
MFA_LANGS = ("go", "node", "python", "java")
MFA_USER_PASSWORD = "ContractMfaUserPassw0rd!"  # throwaway CI account, not a secret

# Secrets the refusal contract tests read; the names are part of the contract
# with the four suites. The value must never appear in a refused response.
REFUSAL_VALUE = "contract-refusal-value-must-not-leak"
REFUSAL_SECRETS = {
    "suspended": "contract-refused-suspended",
    "expired": "contract-refused-expired",
    "max_reads": "contract-refused-max-reads",
    "schedule": "contract-refused-schedule",
}


def totp(seed_b32, step):
    """RFC 6238 code (HMAC-SHA1, 6 digits) for the given time step."""
    key = base64.b32decode(seed_b32.upper() + "=" * (-len(seed_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return "%06d" % (value % 1_000_000)


def call(base, method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - operator-supplied test server
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        return err.code, {}


def secret_id(resp):
    return resp["data"]["id"]


def must(status, what, ok=(200, 201, 204)):
    if status not in ok:
        # Status only: response bodies can carry tokens or challenges.
        sys.exit("contract bootstrap: %s failed with HTTP %d" % (what, status))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--env-file", required=True,
                        help="file to append KEYORIX_CONTRACT_ADMIN_TOKEN=<pat> to (GITHUB_ENV in CI)")
    args = parser.parse_args()
    base = os.environ.get("KEYORIX_CONTRACT_SERVER_URL", "").rstrip("/")
    bootstrap = os.environ.get("KEYORIX_CONTRACT_BOOTSTRAP_TOKEN", "")
    if not base or not bootstrap:
        sys.exit("KEYORIX_CONTRACT_SERVER_URL and KEYORIX_CONTRACT_BOOTSTRAP_TOKEN must be set")

    status, _ = call(base, "POST", "/system/init", {
        "username": ADMIN_USER, "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD, "bootstrap_token": bootstrap,
    })
    must(status, "POST /system/init")

    # Password step. On a fresh server the admin has no second factor yet, so
    # this is a setup-only session that may only reach the MFA enrolment routes.
    status, resp = call(base, "POST", "/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    must(status, "password login")
    session = resp.get("data", {}).get("token", "")
    if not session:
        sys.exit("contract bootstrap: the admin already has MFA enabled (server was bootstrapped before); "
                 "start from a fresh server")

    status, resp = call(base, "POST", "/api/v1/auth/mfa/enroll", {}, session)
    must(status, "MFA enrol")
    seed = resp["data"]["secret"]

    # Activation burns the matched time step (anti-replay), so activate with the
    # current step and verify the login with the next one (inside the server's
    # +-1 step window).
    step = int(time.time()) // TOTP_PERIOD
    status, _ = call(base, "POST", "/api/v1/auth/mfa/activate",
                     {"code": totp(seed, step), "password": ADMIN_PASSWORD}, session)
    must(status, "MFA activate")

    status, resp = call(base, "POST", "/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    must(status, "password login after MFA enrolment")
    challenge = resp.get("data", {}).get("mfa_challenge", "")
    if not resp.get("data", {}).get("mfa_required") or not challenge:
        sys.exit("contract bootstrap: expected an MFA challenge after enrolment")

    status, resp = call(base, "POST", "/auth/mfa/verify",
                        {"mfa_challenge": challenge, "code": totp(seed, step + 1)})
    must(status, "MFA verify")
    mfa_session = resp.get("data", {}).get("token", "")
    if not mfa_session:
        sys.exit("contract bootstrap: MFA verify returned no session")

    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 24 * 3600))
    status, resp = call(base, "POST", "/api/v1/auth/tokens",
                        {"name": "contract-ci-admin", "expires_at": expires}, mfa_session)
    must(status, "PAT mint")
    pat = resp["data"]["token"]

    export(args.env_file, "KEYORIX_CONTRACT_ADMIN_TOKEN", pat)
    print("contract bootstrap: admin enrolled in MFA, PAT written to " + args.env_file)

    # One MFA-enrolled account per SDK for the "password login -> MFARequired ->
    # TOTP -> session" contract tests. Each SDK gets its own account because the
    # server burns a TOTP time step per account once it is used (anti-replay), so
    # four suites sharing one seed would collide inside the same 30 s window.
    for lang in MFA_LANGS:
        seed = enrol_mfa_user(base, pat, "contract-mfa-" + lang)
        export(args.env_file, "KEYORIX_CONTRACT_MFA_SEED_" + lang.upper(), seed)
    print("contract bootstrap: %d MFA test accounts enrolled" % len(MFA_LANGS))

    seed_refusal_fixtures(base, pat)
    print("contract bootstrap: secret-read refusal fixtures created")


def export(env_file, name, value):
    """Append NAME=value to env_file (GITHUB_ENV in CI), masked, never printed."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("::add-mask::" + value)
    fd = os.open(env_file, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a") as out:
        out.write(name + "=" + value + "\n")


def enrol_mfa_user(base, admin_token, username):
    """Create a user with the shared test password, enrol TOTP through the real
    flow (setup-only session -> enrol -> activate) and return the seed. MFA stays
    on for the account: its next password login is an MFA challenge."""
    status, _ = call(base, "POST", "/api/v1/users", {
        "username": username, "email": username + "@example.com",
        "display_name": username, "password": MFA_USER_PASSWORD,
    }, admin_token)
    must(status, "create user " + username)
    status, resp = call(base, "POST", "/auth/login", {"username": username, "password": MFA_USER_PASSWORD})
    must(status, "password login " + username)
    session = resp.get("data", {}).get("token", "")
    if not session:
        sys.exit("contract bootstrap: %s already has MFA enabled; start from a fresh server" % username)
    status, resp = call(base, "POST", "/api/v1/auth/mfa/enroll", {}, session)
    must(status, "MFA enrol " + username)
    seed = resp["data"]["secret"]
    status, _ = call(base, "POST", "/api/v1/auth/mfa/activate",
                     {"code": totp(seed, int(time.time()) // TOTP_PERIOD), "password": MFA_USER_PASSWORD}, session)
    must(status, "MFA activate " + username)
    return seed


def closed_days():
    """ISO weekdays other than today and tomorrow (UTC): a schedule built from
    them stays closed for the whole run even across midnight."""
    now = time.gmtime()
    today = now.tm_wday + 1
    tomorrow = today % 7 + 1
    return ",".join(str(d) for d in range(1, 8) if d not in (today, tomorrow))


def seed_refusal_fixtures(base, admin_token):
    """Create, through the API, one secret per state the server refuses a value
    read for (SecretSuspended, SecretExpired, SecretMaxReadsExhausted,
    SecretAccessOutsideSchedule) in the 'default' project's 'development'
    environment. The suites only read them (refused reads change nothing), so all
    four share them."""
    status, resp = call(base, "GET", "/api/v1/projects", None, admin_token)
    must(status, "list projects")
    project = next(p for p in resp["data"]["projects"] if p["name"] == "default")
    status, resp = call(base, "GET", "/api/v1/projects/%d/environments" % project["id"], None, admin_token)
    must(status, "list environments")
    env = next(e for e in resp["data"]["environments"] if e["name"] == "development")

    def create(name, **extra):
        body = {"name": name, "value": REFUSAL_VALUE, "type": "generic",
                "project_id": project["id"], "environment_id": env["id"]}
        body.update(extra)
        status, resp = call(base, "POST", "/api/v1/secrets", body, admin_token)
        must(status, "create secret " + name)
        return secret_id(resp)

    suspended = create(REFUSAL_SECRETS["suspended"])
    status, _ = call(base, "POST", "/api/v1/secrets/%d/suspend" % suspended, {"reason": "contract fixture"}, admin_token)
    must(status, "suspend secret")

    # Expires in 2 s; the sleep at the end of this function lets it lapse.
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 2))
    create(REFUSAL_SECRETS["expired"], expiration=expires)

    # max_reads=1: spend the one permitted read now; every later read is refused.
    max_reads = create(REFUSAL_SECRETS["max_reads"], max_reads=1)
    status, _ = call(base, "GET", "/api/v1/secrets/%d?include_value=true" % max_reads, None, admin_token)
    must(status, "spend the one permitted read")

    scheduled = create(REFUSAL_SECRETS["schedule"])
    status, _ = call(base, "PUT", "/api/v1/secrets/%d/schedule" % scheduled, {
        "allowed_days": closed_days(), "start_hour": 0, "end_hour": 24, "timezone": "UTC",
    }, admin_token)
    must(status, "set access schedule")

    time.sleep(3)


if __name__ == "__main__":
    main()
