"""Contract test: exercises this SDK's public API against a REAL, running
keyorix-server -- not a mock -- to prove the SDK's wire-format assumptions
(dict keys read via data.get(...), envelope shapes) still match the actual
API on keyorixhq/keyorix's main branch. Every case here is green on main
today (verified against a local keyorix-server built from main,
2026-09-25); its purpose is to go RED the moment a server-side change (e.g.
a wire-format migration to snake_case for a type this SDK parses) lands
without a matching SDK update.

Self-contained: bootstraps its own fresh admin account via /system/init, so
CI can run it against a bare `go run ./server` + SQLite, no Docker/Postgres
fixture required (see .github/workflows/contract.yml).

Skipped unless KEYORIX_CONTRACT_SERVER_URL is set.
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import time
import unittest
import urllib.error
import urllib.request

import keyorix

SERVER_URL = os.environ.get("KEYORIX_CONTRACT_SERVER_URL", "")
BOOTSTRAP_TOKEN = os.environ.get("KEYORIX_CONTRACT_BOOTSTRAP_TOKEN", "")


def _post_json(path, body, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{SERVER_URL}{path}",
        data=json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _seed_admin_session():
    status, body = _post_json(
        "/system/init",
        {
            "username": "contract-admin",
            "email": "contract-admin@example.com",
            "password": "ContractTestPassw0rd!",
            "bootstrap_token": BOOTSTRAP_TOKEN,
        },
    )
    if status >= 300:
        raise RuntimeError(f"POST /system/init: unexpected status {status}: {body!r}")
    return keyorix.login(SERVER_URL, "contract-admin", "ContractTestPassw0rd!")


def _seed_secret(token, project_id, environment_id, name, value):
    status, body = _post_json(
        "/api/v1/secrets",
        {"name": name, "value": value, "project_id": project_id, "environment_id": environment_id, "type": "generic"},
        token,
    )
    if status >= 300:
        raise RuntimeError(f"POST /api/v1/secrets: unexpected status {status}: {body!r}")


def _create_pat(admin_token, name):
    """Mints a personal access token for the caller identified by
    admin_token, via raw HTTP (PAT issuance is not part of this SDK's
    public surface)."""
    status, body = _post_json("/api/v1/auth/tokens", {"name": name}, admin_token)
    if status >= 300:
        raise RuntimeError(f"POST /api/v1/auth/tokens: unexpected status {status}: {body!r}")
    token = json.loads(body).get("data", {}).get("token")
    if not token:
        raise RuntimeError("create-PAT response had no token")
    return token


def _create_machine_token(admin_token, project_id):
    """Creates a fresh machine identity in project_id and issues it a
    token, via raw HTTP (neither is part of this SDK's public surface). A
    brand-new machine identity holds no roles, so this token authenticates
    but is not authorized for anything yet -- exactly the shape needed to
    prove authentication succeeds independently of authorization."""
    status, body = _post_json(
        f"/api/v1/projects/{project_id}/machine-identities",
        {"name": f"contract-test-machine-{time.time_ns()}", "identity_type": "service"},
        admin_token,
    )
    if status >= 300:
        raise RuntimeError(f"POST machine-identities: unexpected status {status}: {body!r}")
    machine_id = json.loads(body).get("data", {}).get("machine_identity", {}).get("id")
    if not machine_id:
        raise RuntimeError("create-machine-identity response had no id")

    status, body = _post_json(
        f"/api/v1/projects/{project_id}/machine-identities/{machine_id}/tokens",
        {"name": "contract-test-machine-token"},
        admin_token,
    )
    if status >= 300:
        raise RuntimeError(f"POST machine-identities tokens: unexpected status {status}: {body!r}")
    token = json.loads(body).get("data", {}).get("token")
    if not token:
        raise RuntimeError("issue-machine-token response had no token")
    return token


def _totp_code(base32_secret, at):
    """RFC 6238 code (HMAC-SHA1, 6 digits, 30s step) for a base32 secret."""
    secret = base32_secret.strip().replace(" ", "").upper()
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(at // 30)), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[off:off + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def _enrol_mfa_user(admin_token):
    """Creates a fresh user via the admin session and enrols TOTP MFA for it
    (raw HTTP: neither is part of this SDK's public surface). Returns
    (username, password, base32 totp secret)."""
    username = f"mfa-user-{time.time_ns()}"
    password = "MfaUserPassw0rd!"
    status, body = _post_json(
        "/api/v1/users",
        {"username": username, "email": f"{username}@example.com", "display_name": "MFA contract user", "password": password},
        admin_token,
    )
    if status >= 300:
        raise RuntimeError(f"POST /api/v1/users: unexpected status {status}: {body!r}")
    user_token = keyorix.login(SERVER_URL, username, password)
    status, body = _post_json("/api/v1/auth/mfa/enroll", {}, user_token)
    if status >= 300:
        raise RuntimeError(f"POST mfa/enroll: unexpected status {status}: {body!r}")
    secret = json.loads(body)["data"]["secret"]
    status, body = _post_json(
        "/api/v1/auth/mfa/activate", {"code": _totp_code(secret, time.time()), "password": password}, user_token
    )
    if status >= 300:
        raise RuntimeError(f"POST mfa/activate: unexpected status {status}: {body!r}")
    return username, password, secret


@unittest.skipUnless(SERVER_URL, "KEYORIX_CONTRACT_SERVER_URL not set -- skipping contract test (needs a real keyorix-server)")
class TestContractFullClientSurface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BOOTSTRAP_TOKEN:
            raise RuntimeError("KEYORIX_CONTRACT_BOOTSTRAP_TOKEN must be set alongside KEYORIX_CONTRACT_SERVER_URL")
        cls.token = _seed_admin_session()
        cls.client = keyorix.Client(SERVER_URL, cls.token)

    def test_health(self):
        self.assertTrue(self.client.health())

    def test_list_projects_finds_default(self):
        projects = self.client.list_projects()
        default = next((p for p in projects if p.name == "default"), None)
        self.assertIsNotNone(default, "expected a 'default' project")

    def test_list_environments_returns_seeded_trio(self):
        projects = self.client.list_projects()
        default = next(p for p in projects if p.name == "default")
        envs = self.client.list_environments(default.id)
        names = sorted(e.name for e in envs)
        self.assertEqual(names, ["development", "production", "staging"])
        for e in envs:
            self.assertEqual(e.project_id, default.id)

    def test_create_project_round_trips(self):
        name = f"contract-test-project-{time.time_ns()}"
        p = self.client.create_project(name, "created by the Python SDK contract test")
        self.assertEqual(p.name, name)
        self.assertEqual(p.description, "created by the Python SDK contract test")
        self.assertGreater(p.id, 0)

    def test_secret_round_trips_value(self):
        projects = self.client.list_projects()
        default = next(p for p in projects if p.name == "default")
        envs = self.client.list_environments(default.id)
        dev_env = next(e for e in envs if e.name == "development")

        secret_name = f"contract-test-secret-{time.time_ns()}"
        secret_value = "contract-test-value-do-not-use"
        _seed_secret(self.token, default.id, dev_env.id, secret_name, secret_value)

        secrets = self.client.list_secrets_scoped(default.id, dev_env.id)
        found = next((s for s in secrets if s.name == secret_name), None)
        self.assertIsNotNone(found, f"expected to find seeded secret {secret_name!r}")
        self.assertEqual(found.project_id, default.id)

        value = self.client.get_secret_scoped(secret_name, default.id, dev_env.id)
        self.assertEqual(value, secret_value)

    def test_pat_auth_works_transparently(self):
        pat = _create_pat(self.token, "contract-test-pat")
        pat_client = keyorix.Client(SERVER_URL, pat)
        try:
            pat_client.list_projects()
        except keyorix.KeyorixError as e:
            self.fail(f"Client with a PAT: {e} (expected success -- a PAT presents identically to a session token)")

    def test_machine_token_auth_works_transparently(self):
        projects = self.client.list_projects()
        default = next(p for p in projects if p.name == "default")
        machine_token = _create_machine_token(self.token, default.id)
        machine_client = keyorix.Client(SERVER_URL, machine_token)
        # A brand-new machine identity holds no roles, so this must
        # authenticate (not AuthError) even though it can't yet be
        # authorized for anything (ForbiddenError) -- proving the token is
        # recognized as valid, distinct from being permitted.
        with self.assertRaises(keyorix.ForbiddenError):
            machine_client.list_projects()

    def test_timeout_is_enforced_against_a_slow_server(self):
        import http.server
        import threading

        class _SlowHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                time.sleep(0.2)
                body = b'{"data":{"projects":[]}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        httpd = http.server.HTTPServer(("localhost", 0), _SlowHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            slow_client = keyorix.Client(f"http://localhost:{httpd.server_address[1]}", "tok", timeout=0.01)
            with self.assertRaises(keyorix.KeyorixError):
                slow_client.list_projects()
        finally:
            httpd.shutdown()


@unittest.skipUnless(SERVER_URL, "KEYORIX_CONTRACT_SERVER_URL not set -- skipping contract test (needs a real keyorix-server)")
class TestContractMFALogin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BOOTSTRAP_TOKEN:
            raise RuntimeError("KEYORIX_CONTRACT_BOOTSTRAP_TOKEN must be set alongside KEYORIX_CONTRACT_SERVER_URL")
        admin_token = _seed_admin_session()
        cls.username, cls.password, cls.secret = _enrol_mfa_user(admin_token)

    def test_mfa_login_flow(self):
        # One test, two password logins: the server's per-IP login budget is
        # shared with the other SDKs' contract tests on the same server.
        with self.assertRaises(keyorix.MFARequiredError) as cm:
            keyorix.login(SERVER_URL, self.username, self.password)
        self.assertTrue(cm.exception.challenge)
        self.assertTrue(cm.exception.totp_available)
        with self.assertRaises(keyorix.AuthError):
            keyorix.verify_mfa(SERVER_URL, cm.exception.challenge, "000000")

        # Next 30s step: the code used at activation is single-use.
        code = _totp_code(self.secret, time.time() + 30)
        token = keyorix.login(SERVER_URL, self.username, self.password, mfa_code=code)
        self.assertTrue(keyorix.Client(SERVER_URL, token).health())


if __name__ == "__main__":
    unittest.main()
