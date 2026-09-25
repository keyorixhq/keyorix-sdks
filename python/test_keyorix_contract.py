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


if __name__ == "__main__":
    unittest.main()
