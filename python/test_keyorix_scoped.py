"""Scoped list/get secret tests for keyorix Python SDK.

Mirrors the same two-project test matrix as the Go/Node/Java SDKs: two
projects, each with its own "prod" environment (environment names are unique
per project, not globally) and its own "db-password" secret, plus a
duplicated name to exercise the ambiguous-match case.
"""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import keyorix

PROJECTS = {"proj-a": 10, "proj-b": 20}
ENVIRONMENTS = {10: {"prod": 101}, 20: {"prod": 201}}
SECRETS = {
    (10, 101): [{"ID": 1, "Name": "db-password"}],
    (20, 201): [
        {"ID": 2, "Name": "db-password"},
        {"ID": 3, "Name": "ambiguous-secret"},
        {"ID": 4, "Name": "ambiguous-secret"},
    ],
}
VALUES = {1: "secret-a", 2: "secret-b"}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test output
        pass

    def _json(self, payload, status=200):
        body = json.dumps({"data": payload}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (stdlib method name)
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/api/v1/projects":
            self.server.calls.append("projects")
            self._json({"projects": [{"ID": v, "Name": k} for k, v in PROJECTS.items()]})
            return

        if parsed.path.endswith("/environments"):
            project_id = int(parsed.path.split("/")[4])
            self.server.calls.append(f"environments:{project_id}")
            envs = ENVIRONMENTS.get(project_id, {})
            self._json({"environments": [{"ID": v, "Name": k, "ProjectID": project_id} for k, v in envs.items()]})
            return

        if parsed.path == "/api/v1/secrets":
            pid = int(qs["project_id"][0]) if "project_id" in qs else None
            eid = int(qs["environment_id"][0]) if "environment_id" in qs else None
            secrets = SECRETS.get((pid, eid), [])
            self._json({"secrets": secrets})
            return

        if parsed.path.startswith("/api/v1/secrets/"):
            secret_id = int(parsed.path.rsplit("/", 1)[-1])
            self._json({"value": VALUES.get(secret_id, "")})
            return

        self.send_response(404)
        self.end_headers()


class ScopedTestServer:
    def __enter__(self):
        self._httpd = HTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.calls = []
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._httpd.shutdown()
        self._thread.join()
        self._httpd.server_close()

    @property
    def url(self):
        host, port = self._httpd.server_address
        return f"http://{host}:{port}"

    @property
    def calls(self):
        return self._httpd.calls


class TestListSecretsScoped(unittest.TestCase):
    def test_by_name_resolves_each_project_independently(self):
        with ScopedTestServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            secrets_a = client.list_secrets_scoped("proj-a", "prod")
            secrets_b = client.list_secrets_scoped("proj-b", "prod")
            self.assertEqual([s.id for s in secrets_a], [1])
            self.assertEqual([s.id for s in secrets_b], [2, 3, 4])

    def test_by_id_skips_resolution_round_trips(self):
        with ScopedTestServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            secrets = client.list_secrets_scoped(10, 101)
            self.assertEqual([s.id for s in secrets], [1])
            self.assertNotIn("projects", srv.calls)
            self.assertNotIn("environments:10", srv.calls)

    def test_unknown_project_raises(self):
        with ScopedTestServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            with self.assertRaises(keyorix.KeyorixError):
                client.list_secrets_scoped("ghost", "prod")

    def test_unknown_environment_raises(self):
        with ScopedTestServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            with self.assertRaises(keyorix.KeyorixError):
                client.list_secrets_scoped("proj-a", "ghost")

    def test_project_lookup_is_cached_across_calls(self):
        with ScopedTestServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            client.list_secrets_scoped("proj-a", "prod")
            client.list_secrets_scoped("proj-a", "prod")
            self.assertEqual(srv.calls.count("projects"), 1)


class TestGetSecretScoped(unittest.TestCase):
    def test_proj_a_resolves_its_own_db_password(self):
        with ScopedTestServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            self.assertEqual(client.get_secret_scoped("db-password", "proj-a", "prod"), "secret-a")

    def test_proj_b_resolves_its_own_db_password_not_proj_as(self):
        with ScopedTestServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            self.assertEqual(client.get_secret_scoped("db-password", "proj-b", "prod"), "secret-b")

    def test_missing_name_raises_secret_not_found(self):
        with ScopedTestServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            with self.assertRaises(keyorix.SecretNotFoundError):
                client.get_secret_scoped("does-not-exist", "proj-a", "prod")

    def test_ambiguous_name_raises_with_both_ids(self):
        with ScopedTestServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            with self.assertRaises(keyorix.AmbiguousSecretError) as ctx:
                client.get_secret_scoped("ambiguous-secret", "proj-b", "prod")
            self.assertEqual(ctx.exception.ids, [3, 4])


if __name__ == "__main__":
    unittest.main()
