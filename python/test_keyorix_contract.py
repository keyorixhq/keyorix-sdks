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

import json
import os
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


def _get(path, token):
    req = urllib.request.Request(
        f"{SERVER_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
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

    def test_create_secret_reads_back(self):
        name = f"contract-create-{time.time_ns()}"
        value = "contract-create-value-do-not-use"
        created = self.client.create_secret(
            "default", "development", name, value, description="created by the Python SDK contract test"
        )
        self.assertGreater(created.id, 0)
        self.assertEqual((created.name, created.type), (name, "generic"))
        self.assertEqual(self.client.get_secret_scoped(name, "default", "development"), value)
        listed = self.client.list_secrets_scoped("default", "development")
        self.assertIn(created.id, [s.id for s in listed])

    def test_create_secret_duplicate_name_is_typed(self):
        name = f"contract-create-dup-{time.time_ns()}"
        value = "contract-create-value-do-not-use"
        self.client.create_secret("default", "development", name, value)
        with self.assertRaises(keyorix.SecretAlreadyExistsError) as ctx:
            self.client.create_secret("default", "development", name, value)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertNotIn(value, str(ctx.exception))
        self.assertNotIn(value, ctx.exception.response_body or "")

    def test_create_secret_unauthenticated_is_auth_error(self):
        default = next(p for p in self.client.list_projects() if p.name == "default")
        env = next(e for e in self.client.list_environments(default.id) if e.name == "development")
        for bad_token in ("not-a-valid-token", ""):
            bad = keyorix.Client(SERVER_URL, bad_token)
            # By ID, so the 401 comes from POST /api/v1/secrets itself and not
            # from the project lookup a by-name call does first.
            with self.assertRaises(keyorix.AuthError, msg=f"token {bad_token!r}"):
                bad.create_secret(default.id, env.id, "contract-create-anon", "v")

    def test_deleted_secret_exposes_purge_at(self):
        projects = self.client.list_projects()
        default = next(p for p in projects if p.name == "default")
        envs = self.client.list_environments(default.id)
        dev_env = next(e for e in envs if e.name == "development")

        name = f"contract-purge-{time.time_ns()}"
        _seed_secret(self.token, default.id, dev_env.id, name, "v")
        live = next(s for s in self.client.list_secrets_scoped(default.id, dev_env.id) if s.name == name)
        self.assertEqual(live.purge_at, "", "a live secret has no purge_at")

        # DELETE is not part of this SDK's public surface: raw HTTP.
        req = urllib.request.Request(
            f"{SERVER_URL}/api/v1/secrets/{live.id}", headers={"Authorization": f"Bearer {self.token}"}, method="DELETE"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            self.assertEqual(resp.status, 204)

        deleted = next((s for s in self.client.list_deleted_secrets(default.id) if s.id == live.id), None)
        self.assertIsNotNone(deleted, "soft-deleted secret missing from list_deleted_secrets")
        self.assertTrue(deleted.purge_at, "soft-deleted secret has no purge_at")
        import datetime

        purge = datetime.datetime.fromisoformat(deleted.purge_at.replace("Z", "+00:00"))
        days = (purge - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 86400
        self.assertTrue(29 < days < 31, f"purge_at {deleted.purge_at} is not ~30 days out (retention_days=30)")

    def test_pat_auth_works_transparently(self):
        pat = _create_pat(self.token, "contract-test-pat")
        pat_client = keyorix.Client(SERVER_URL, pat)
        try:
            pat_client.list_projects()
        except keyorix.KeyorixError as e:
            self.fail(f"Client with a PAT: {e} (expected success -- a PAT presents identically to a session token)")

    def test_list_projects_succeeds_with_empty_list_for_zero_grant_token(self):
        projects = self.client.list_projects()
        default = next(p for p in projects if p.name == "default")
        machine_token = _create_machine_token(self.token, default.id)
        machine_client = keyorix.Client(SERVER_URL, machine_token)
        # A brand-new machine identity holds no roles. List routes are
        # filtered by permission, so it authenticates and gets an EMPTY 200
        # (not AuthError, not ForbiddenError).
        self.assertEqual(machine_client.list_projects(), [])

    def test_get_project_with_zero_grant_token_is_forbidden(self):
        projects = self.client.list_projects()
        default = next(p for p in projects if p.name == "default")
        machine_token = _create_machine_token(self.token, default.id)
        status, _ = _get(f"/api/v1/projects/{default.id}", machine_token)
        self.assertEqual(status, 403, "GET /projects/{id} with a zero-grant token must be forbidden (403)")

    def test_list_projects_with_bad_token_is_unauthorized(self):
        bad_client = keyorix.Client(SERVER_URL, "not-a-valid-token")
        with self.assertRaises(keyorix.AuthError):
            bad_client.list_projects()

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


if __name__ == "__main__":
    unittest.main()
