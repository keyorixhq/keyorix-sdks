"""Tests for get_secret_by_ref/get_secret_in and list_secrets_scoped pagination.

Red/green notes (see reports/SESSION-K.md for the full isolation detail):
get_secret_by_ref/get_secret_in did not exist before this fix (AttributeError
against pre-fix keyorix.py). list_secrets_scoped's pagination follow is a
real behavioral regression fix: before this fix it never sent page/page_size
at all, so a scope with more secrets than the server's default page size
(20) was silently truncated with no error.
"""

import io
import json
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

import keyorix


class _RefHandler(BaseHTTPRequestHandler):
    """Serves ONLY /api/v1/secrets/value -- proving get_secret_by_ref never
    needs /api/v1/secrets or /api/v1/projects the way get_secret_scoped does.
    """

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/api/v1/secrets/value":
            self.send_response(500)
            self.end_headers()
            return
        qs = parse_qs(parsed.query)
        ref = qs.get("ref", [""])[0]
        body = json.dumps({"data": {"value": f"value-for:{ref}"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


class _RefServer:
    def __enter__(self):
        self._httpd = HTTPServer(("127.0.0.1", 0), _RefHandler)
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


class TestGetSecretByRef(unittest.TestCase):
    def test_round_trips_escaped_ref_with_spaces_and_slashes_in_name(self):
        ref = "my project/prod env/path/to/secret"
        with _RefServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            self.assertEqual(client.get_secret_by_ref(ref), f"value-for:{ref}")

    def test_get_secret_in_builds_project_environment_name(self):
        with _RefServer() as srv:
            client = keyorix.Client(srv.url, "tok")
            self.assertEqual(client.get_secret_in("proj", "env", "name"), "value-for:proj/env/name")


class TestGetSecretByRefErrorMapping(unittest.TestCase):
    """Reuses the existing typed 401/403/404 errors from #40 -- no second
    error set."""

    @patch("keyorix.urllib.request.urlopen")
    def test_401_maps_to_auth_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets/value", 401, "Unauthorized", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "tok")
        with self.assertRaises(keyorix.AuthError):
            client.get_secret_by_ref("p/e/n")

    @patch("keyorix.urllib.request.urlopen")
    def test_403_maps_to_forbidden_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets/value", 403, "Forbidden", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "tok")
        with self.assertRaises(keyorix.ForbiddenError):
            client.get_secret_by_ref("p/e/n")

    @patch("keyorix.urllib.request.urlopen")
    def test_404_maps_to_not_found_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets/value", 404, "Not Found", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "tok")
        with self.assertRaises(keyorix.NotFoundError):
            client.get_secret_by_ref("p/e/n")

    @patch("keyorix.urllib.request.urlopen")
    def test_400_does_not_map_to_a_typed_401_403_404_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets/value", 400, "Bad Request", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "tok")
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            client.get_secret_by_ref("not-a-valid-ref")
        self.assertNotIsInstance(ctx.exception, keyorix.AuthError)
        self.assertNotIsInstance(ctx.exception, keyorix.ForbiddenError)
        self.assertNotIsInstance(ctx.exception, keyorix.NotFoundError)
        self.assertEqual(ctx.exception.status_code, 400)


class _PaginatedHandler(BaseHTTPRequestHandler):
    """Serves /api/v1/secrets across 2 pages of 1 secret each."""

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path != "/api/v1/secrets":
            self.send_response(404)
            self.end_headers()
            return
        self.server.calls.append(qs.get("page", [None])[0])
        page = qs.get("page", ["1"])[0]
        secrets = [{"id": 2, "name": "b"}] if page == "2" else [{"id": 1, "name": "a"}]
        body = json.dumps({"data": {"secrets": secrets, "total_pages": 2}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


class TestListSecretsScopedPagination(unittest.TestCase):
    def test_follows_all_pages(self):
        httpd = HTTPServer(("127.0.0.1", 0), _PaginatedHandler)
        httpd.calls = []
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = httpd.server_address
            client = keyorix.Client(f"http://{host}:{port}", "tok")
            secrets = client.list_secrets_scoped(1, 1)
            self.assertEqual([s.id for s in secrets], [1, 2])
            self.assertEqual(httpd.calls, ["1", "2"])
        finally:
            httpd.shutdown()
            thread.join()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
