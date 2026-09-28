"""Unit tests for keyorix Python SDK."""

import io
import unittest
import urllib.error
from unittest.mock import patch
import json
import keyorix


class TestClient(unittest.TestCase):

    def test_client_init(self):
        client = keyorix.Client("http://localhost:8080", "test-token")
        self.assertEqual(client._base, "http://localhost:8080")
        self.assertEqual(client._token, "test-token")
        self.assertEqual(client._timeout, 30)

    def test_client_strips_trailing_slash(self):
        client = keyorix.Client("http://localhost:8080/", "test-token")
        self.assertEqual(client._base, "http://localhost:8080")

    def test_client_custom_timeout(self):
        client = keyorix.Client("http://localhost:8080", "test-token", timeout=10)
        self.assertEqual(client._timeout, 10)

    def test_secret_from_dict(self):
        data = {
            "id": 1,
            "name": "db-password",
            "type": "password",
            "environment_name": "production",
            "project_id": 1,
            "created_at": "2026-04-19T00:00:00Z",
        }
        secret = keyorix.Secret._from_dict(data)
        self.assertEqual(secret.id, 1)
        self.assertEqual(secret.name, "db-password")
        self.assertEqual(secret.type, "password")
        self.assertEqual(secret.environment, "production")
        self.assertEqual(secret.project_id, 1)

    def test_secret_not_found_error(self):
        self.assertTrue(issubclass(keyorix.SecretNotFoundError, keyorix.KeyorixError))

    def test_auth_error(self):
        self.assertTrue(issubclass(keyorix.AuthError, keyorix.KeyorixError))

    def test_client_allows_https(self):
        client = keyorix.Client("https://example.com:8443", "test-token")
        self.assertEqual(client._base, "https://example.com:8443")

    def test_client_allows_loopback_http(self):
        for url in ("http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"):
            keyorix.Client(url, "test-token")

    def test_client_rejects_non_loopback_http(self):
        with self.assertRaises(keyorix.KeyorixError):
            keyorix.Client("http://example.com:8080", "test-token")

    def test_client_rejects_non_http_scheme(self):
        for url in ("file:///etc/passwd", "ftp://example.com"):
            with self.assertRaises(keyorix.KeyorixError):
                keyorix.Client(url, "test-token")

    def test_login_rejects_non_loopback_http(self):
        with self.assertRaises(keyorix.KeyorixError):
            keyorix.login("http://example.com:8080", "user", "pass")

    def test_keyorix_error_message_omits_body(self):
        err = keyorix.KeyorixError(
            "Server returned 500", status_code=500, response_body="internal stack trace here"
        )
        self.assertNotIn("internal stack trace here", str(err))
        self.assertEqual(err.status_code, 500)
        self.assertEqual(err.response_body, "internal stack trace here")

    @patch("keyorix.urllib.request.urlopen")
    def test_request_redacts_body_from_message(self, mock_urlopen):
        raw = "internal: secret_key=super-sensitive-detail"
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 500, "Internal Server Error", {}, io.BytesIO(raw.encode())
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            client._request("GET", "/api/v1/secrets")
        self.assertNotIn(raw, str(ctx.exception))
        self.assertEqual(ctx.exception.response_body, raw)
        self.assertEqual(ctx.exception.status_code, 500)

    # ── Typed error mapping ─────────────────────────────────────────────────────
    # Every request path raises a typed error that isinstance() can
    # distinguish for the three statuses callers most need to branch on,
    # not just one generic KeyorixError.

    @patch("keyorix.urllib.request.urlopen")
    def test_401_maps_to_auth_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 401, "Unauthorized", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.AuthError) as ctx:
            client._request("GET", "/api/v1/secrets")
        self.assertEqual(ctx.exception.status_code, 401)

    @patch("keyorix.urllib.request.urlopen")
    def test_403_maps_to_forbidden_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 403, "Forbidden", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.ForbiddenError) as ctx:
            client._request("GET", "/api/v1/secrets")
        self.assertEqual(ctx.exception.status_code, 403)

    @patch("keyorix.urllib.request.urlopen")
    def test_404_maps_to_not_found_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 404, "Not Found", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.NotFoundError) as ctx:
            client._request("GET", "/api/v1/secrets")
        self.assertEqual(ctx.exception.status_code, 404)

    # ── TLS with a private CA ───────────────────────────────────────────────────
    # Proves the ca_file option actually gets verified against, not just
    # plumbed through and ignored. Uses a throwaway self-signed cert
    # (openssl) as its own private CA. Skipped gracefully if openssl isn't
    # on PATH.

    def test_tls_private_ca(self):
        import http.server
        import shutil
        import ssl as ssl_module
        import subprocess
        import tempfile
        import threading
        import os

        if shutil.which("openssl") is None:
            self.skipTest("openssl not on PATH")

        with tempfile.TemporaryDirectory() as d:
            key_path = os.path.join(d, "key.pem")
            cert_path = os.path.join(d, "cert.pem")
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key_path, "-out", cert_path,
                    "-days", "1", "-subj", "/CN=localhost",
                ],
                check=True, capture_output=True,
            )

            class _Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    body = b'{"status":"healthy"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)

            httpd = http.server.HTTPServer(("localhost", 0), _Handler)
            server_ctx = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert_path, key_path)
            httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                untrusted = keyorix.Client(f"https://localhost:{port}", "tok")
                with self.assertRaises(keyorix.KeyorixError):
                    untrusted.health()

                trusted = keyorix.Client(f"https://localhost:{port}", "tok", ca_file=cert_path)
                self.assertTrue(trusted.health())
            finally:
                httpd.shutdown()

    # ── Deprecated environment-only methods: removed in v0.3.0 ─────────────────

    @patch("keyorix.urllib.request.urlopen")
    def test_list_secrets_deprecated_never_calls_server(self, mock_urlopen):
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            client.list_secrets("production")
        self.assertIn("list_secrets_scoped", str(ctx.exception))
        mock_urlopen.assert_not_called()

    @patch("keyorix.urllib.request.urlopen")
    def test_get_secret_deprecated_never_calls_server(self, mock_urlopen):
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            client.get_secret("db-password", "production")
        self.assertIn("get_secret_scoped", str(ctx.exception))
        mock_urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
