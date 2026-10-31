"""Contract test for update_secret / delete_secret against a REAL, running
keyorix-server (see test_keyorix_contract.py for what these tests are for and
how the server is started). Update writes a new version whose value is
readable; delete is a soft delete (gone from a get, listed in the deleted
listing with the purge date the delete returned).

Skipped unless KEYORIX_CONTRACT_SERVER_URL is set. CI runs only
test_keyorix_contract (contract.yml), which imports ContractUpdateDeleteTests.
"""

import json
import os
import time
import unittest
from datetime import datetime, timezone

import keyorix

SERVER_URL = os.environ.get("KEYORIX_CONTRACT_SERVER_URL", "")


def _parse_rfc3339(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


@unittest.skipUnless(SERVER_URL, "KEYORIX_CONTRACT_SERVER_URL not set -- skipping contract test (needs a real keyorix-server)")
class ContractUpdateDeleteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Imported here, not at module level: test_keyorix_contract imports this
        # module so that CI runs it.
        import test_keyorix_contract as base

        cls.base = base
        if not base.BOOTSTRAP_TOKEN:
            raise RuntimeError("KEYORIX_CONTRACT_BOOTSTRAP_TOKEN must be set alongside KEYORIX_CONTRACT_SERVER_URL")
        cls.admin_token = base._seed_admin_session()
        cls.client = keyorix.Client(SERVER_URL, cls.admin_token)

    def _version_numbers(self, secret_id):
        status, body = self.base._get(f"/api/v1/secrets/{secret_id}/versions", self.admin_token)
        self.assertEqual(status, 200)
        return [v["VersionNumber"] for v in json.loads(body)["data"]["versions"]]

    def test_update_then_delete(self):
        c = self.client
        project = next(p for p in c.list_projects() if p.name == "default")
        env = next(e for e in c.list_environments(project.id) if e.name == "development")

        name = f"contract-upd-del-{time.time_ns()}"
        self.base._seed_secret(self.admin_token, project.id, env.id, name, "value-one")
        secret_id = next(s.id for s in c.list_secrets_scoped(project.id, env.id) if s.name == name)
        self.assertEqual(len(self._version_numbers(secret_id)), 1, "a fresh secret has exactly one version")

        # update: new version, new value readable
        updated = c.update_secret(project.id, env.id, name, "value-two")
        self.assertEqual((updated.id, updated.name), (secret_id, name))
        self.assertEqual(c.get_secret_scoped(name, project.id, env.id), "value-two")
        versions = self._version_numbers(secret_id)
        self.assertEqual((len(versions), versions[0]), (2, 2), versions)

        c.update_secret_by_id(secret_id, "value-three")
        self.assertEqual(c.get_secret_scoped(name, project.id, env.id), "value-three")
        versions = self._version_numbers(secret_id)
        self.assertEqual((len(versions), versions[0]), (3, 3), versions)

        # A rotated value with quotes, backslashes, a newline and a tab reads back byte for byte.
        tricky = 'line1\nline2 "quoted" back\\slash\ttab é ends-with-backslash\\'
        c.update_secret_by_id(secret_id, tricky)
        self.assertEqual(c.get_secret_scoped(name, project.id, env.id), tricky)

        # 403: a zero-grant machine token may neither update nor delete
        machine = keyorix.Client(SERVER_URL, self.base._create_machine_token(self.admin_token, project.id))
        with self.assertRaises(keyorix.ForbiddenError):
            machine.update_secret_by_id(secret_id, "attacker-value")
        with self.assertRaises(keyorix.ForbiddenError):
            machine.delete_secret_by_id(secret_id)
        self.assertEqual(c.get_secret_scoped(name, project.id, env.id), tricky, "refused calls changed nothing")

        # delete: soft delete with a purge date
        purge_at = c.delete_secret(project.id, env.id, name)
        self.assertIsNotNone(purge_at, "the server sends Keyorix-Purge-At")
        days = (_parse_rfc3339(purge_at) - datetime.now(timezone.utc)).total_seconds() / 86400
        self.assertTrue(29 < days < 31, f"purge date {purge_at} is not ~30 days out")

        with self.assertRaises(keyorix.SecretNotFoundError):
            c.get_secret_scoped(name, project.id, env.id)
        listed = next((s for s in c.list_deleted_secrets(project.id) if s.id == secret_id), None)
        self.assertIsNotNone(listed, "a deleted secret is listed by list_deleted_secrets")
        self.assertLess(abs((_parse_rfc3339(listed.purge_at) - _parse_rfc3339(purge_at)).total_seconds()), 2)

        # 404: a deleted secret can be neither updated nor deleted again
        with self.assertRaises(keyorix.NotFoundError):
            c.update_secret_by_id(secret_id, "late")
        with self.assertRaises(keyorix.NotFoundError):
            c.delete_secret_by_id(secret_id)
        with self.assertRaises(keyorix.SecretNotFoundError):
            c.update_secret(project.id, env.id, name, "late")
        with self.assertRaises(keyorix.SecretNotFoundError):
            c.delete_secret(project.id, env.id, name)


if __name__ == "__main__":
    unittest.main()
