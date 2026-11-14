"""Unit tests for keyorix Python SDK."""

import io
import unittest
import urllib.error
import unittest.mock
from unittest.mock import patch
import json
import keyorix

# python.yml runs only this module; the update/delete cases live in their own
# file and are pulled in here so CI runs them.
from test_update_delete import UpdateDeleteTests  # noqa: F401


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

    @staticmethod
    def _ok(payload):
        resp = unittest.mock.MagicMock()
        resp.read.return_value = json.dumps(payload).encode()
        resp.__enter__.return_value = resp
        return resp

    @patch("keyorix._urlopen")
    def test_login_mfa_challenge_raises_typed_error(self, mock_urlopen):
        mock_urlopen.return_value = self._ok(
            {"data": {"mfa_required": True, "mfa_challenge": "chal-1", "totp_available": True, "webauthn_available": True}}
        )
        with self.assertRaises(keyorix.MFARequiredError) as ctx:
            keyorix.login("http://localhost:8080", "u", "p")
        e = ctx.exception
        self.assertIsInstance(e, keyorix.AuthError)  # backward compatible
        self.assertEqual(e.challenge, "chal-1")
        self.assertEqual(e.methods, ["totp", "webauthn"])
        self.assertNotIn("chal-1", str(e))

    @patch("keyorix._urlopen")
    def test_login_without_token_or_challenge_is_generic_auth_error(self, mock_urlopen):
        mock_urlopen.return_value = self._ok({"data": {}})
        with self.assertRaises(keyorix.AuthError) as ctx:
            keyorix.login("http://localhost:8080", "u", "p")
        self.assertNotIsInstance(ctx.exception, keyorix.MFARequiredError)

    @patch("keyorix._urlopen")
    def test_verify_mfa_returns_session_and_posts_challenge_and_code(self, mock_urlopen):
        mock_urlopen.return_value = self._ok({"data": {"token": "sess"}})
        self.assertEqual(keyorix.verify_mfa("http://localhost:8080", "chal-1", "123456"), "sess")
        req = mock_urlopen.call_args[0][0]
        self.assertTrue(req.full_url.endswith("/auth/mfa/verify"))
        self.assertEqual(json.loads(req.data), {"mfa_challenge": "chal-1", "code": "123456"})

    @patch("keyorix._urlopen")
    def test_verify_mfa_wrong_code_is_auth_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/auth/mfa/verify", 401, "Unauthorized", {}, io.BytesIO(b'{"error":"Unauthorized"}')
        )
        with self.assertRaises(keyorix.AuthError) as ctx:
            keyorix.verify_mfa("http://localhost:8080", "c", "000000")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_keyorix_error_message_omits_body(self):
        err = keyorix.KeyorixError(
            "Server returned 500", status_code=500, response_body="internal stack trace here"
        )
        self.assertNotIn("internal stack trace here", str(err))
        self.assertEqual(err.status_code, 500)
        self.assertEqual(err.response_body, "internal stack trace here")

    @patch("keyorix._urlopen")
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

    @patch("keyorix._urlopen")
    def test_401_maps_to_auth_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 401, "Unauthorized", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.AuthError) as ctx:
            client._request("GET", "/api/v1/secrets")
        self.assertEqual(ctx.exception.status_code, 401)

    @patch("keyorix._urlopen")
    def test_403_maps_to_forbidden_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 403, "Forbidden", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.ForbiddenError) as ctx:
            client._request("GET", "/api/v1/secrets")
        self.assertEqual(ctx.exception.status_code, 403)

    @patch("keyorix._urlopen")
    def test_404_maps_to_not_found_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 404, "Not Found", {}, io.BytesIO(b"")
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.NotFoundError) as ctx:
            client._request("GET", "/api/v1/secrets")
        self.assertEqual(ctx.exception.status_code, 404)

    # A value read the secret's own state refuses (server ERRMAP-1): 409 with a
    # secret-state code is a SecretUnavailableError carrying that code; a
    # schedule refusal stays a ForbiddenError but says what it is. Neither
    # message echoes the server's body.
    @patch("keyorix._urlopen")
    def test_secret_read_refusals(self, mock_urlopen):
        cases = [
            (409, "SecretExpired", keyorix.SecretUnavailableError, "has expired"),
            (409, "SecretSuspended", keyorix.SecretUnavailableError, "is suspended"),
            (409, "SecretMaxReadsExhausted", keyorix.SecretUnavailableError, "maximum number of reads"),
            (403, "SecretAccessOutsideSchedule", keyorix.ForbiddenError, "outside its access schedule"),
        ]
        client = keyorix.Client("http://localhost:8080", "test-token")
        for status, code, exc_type, want in cases:
            with self.subTest(code=code):
                body = json.dumps({"success": False, "code": status, "error": code, "message": "SERVER-TEXT"})
                mock_urlopen.side_effect = urllib.error.HTTPError(
                    "http://localhost:8080/api/v1/secrets/value", status, "x", {}, io.BytesIO(body.encode())
                )
                with self.assertRaises(exc_type) as ctx:
                    client._request("GET", "/api/v1/secrets/value?ref=p/e/n")
                self.assertEqual(ctx.exception.status_code, status)
                self.assertEqual(ctx.exception.code, code)
                self.assertIn(want, str(ctx.exception))
                self.assertNotIn("SERVER-TEXT", str(ctx.exception))

    @patch("keyorix._urlopen")
    def test_unrelated_409_stays_generic(self, mock_urlopen):
        body = json.dumps({"error": "ConflictError", "message": "x"})
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 409, "Conflict", {}, io.BytesIO(body.encode())
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            client._request("GET", "/api/v1/secrets")
        self.assertNotIsInstance(ctx.exception, keyorix.SecretUnavailableError)
        self.assertEqual(ctx.exception.code, "ConflictError")

    # 503 audit_unavailable (real body shape: server/http/handlers/audit_unavailable.go):
    # the write was refused and nothing changed. Typed; any other 503 stays generic.
    @patch("urllib.request.urlopen")
    def test_audit_unavailable_is_typed(self, mock_urlopen):
        body = json.dumps({"success": False, "code": 503, "error": "audit_unavailable", "message": "SERVER-TEXT"})
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 503, "x", {"Retry-After": "5"}, io.BytesIO(body.encode())
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.AuditUnavailableError) as ctx:
            client.create_secret(3, 4, "n", "audit-s3cr3t-not-in-body")
        self.assertIsInstance(ctx.exception, keyorix.KeyorixError)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.code, "audit_unavailable")
        self.assertNotIn("SERVER-TEXT", str(ctx.exception))

    @patch("urllib.request.urlopen")
    def test_other_503_stays_generic(self, mock_urlopen):
        body = json.dumps({"error": "storage_unavailable", "message": "x"})
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://localhost:8080/api/v1/secrets", 503, "x", {}, io.BytesIO(body.encode())
        )
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            client.create_secret(3, 4, "n", "audit-s3cr3t-not-in-body")
        self.assertNotIsInstance(ctx.exception, keyorix.AuditUnavailableError)
        self.assertEqual(ctx.exception.status_code, 503)

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

    @patch("keyorix._urlopen")
    def test_list_secrets_deprecated_never_calls_server(self, mock_urlopen):
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            client.list_secrets("production")
        self.assertIn("list_secrets_scoped", str(ctx.exception))
        mock_urlopen.assert_not_called()

    @patch("keyorix._urlopen")
    def test_get_secret_deprecated_never_calls_server(self, mock_urlopen):
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            client.get_secret("db-password", "production")
        self.assertIn("get_secret_scoped", str(ctx.exception))
        mock_urlopen.assert_not_called()


class _RecordingServer:
    """A throwaway local HTTP server that records every request it receives.

    With redirect_to set it answers every request with that status code and a
    Location header; otherwise it answers 200 with an empty JSON object.
    """

    def __init__(self, status=200, location=None):
        import http.server
        import threading

        self.requests = []
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                outer.requests.append((self.command, self.path, dict(self.headers.items())))
                body = b"{}"
                self.send_response(status)
                if location is not None:
                    self.send_header("Location", location)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_DELETE = _handle

        self._httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self._thread.start()

    def close(self):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


class TestRedirectsAreNotFollowed(unittest.TestCase):
    """A 3xx response is raised as KeyorixError and never followed, so the
    Authorization header cannot reach another origin."""

    TOKEN = "tok-redirect-test"

    def _run(self, code, call, check_status=True):
        sink = _RecordingServer()
        # "localhost" vs "127.0.0.1" on another port: a different origin.
        origin = _RecordingServer(status=code, location=f"http://localhost:{sink.port}/sink")
        self.addCleanup(sink.close)
        self.addCleanup(origin.close)
        client = keyorix.Client(f"http://127.0.0.1:{origin.port}", self.TOKEN)
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            call(client, origin.port)
        if check_status:
            self.assertEqual(ctx.exception.status_code, code)
        self.assertEqual(sink.requests, [], "the redirect target must receive no request")
        self.assertEqual(len(origin.requests), 1)
        self.assertNotIn(self.TOKEN, str(ctx.exception))

    def test_authenticated_get_not_followed(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                self._run(code, lambda c, _p: c.list_projects())

    def test_authenticated_post_not_followed(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                self._run(code, lambda c, _p: c.create_project("p"))

    def test_health_not_followed(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                self._run(code, lambda c, _p: c.health(), check_status=False)

    def test_login_not_followed(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                self._run(code, lambda _c, port: keyorix.login(f"http://127.0.0.1:{port}", "u", "p"))

    def test_same_origin_redirect_not_followed(self):
        origin = _RecordingServer(status=302, location="/elsewhere")
        self.addCleanup(origin.close)
        client = keyorix.Client(f"http://127.0.0.1:{origin.port}", self.TOKEN)
        with self.assertRaises(keyorix.KeyorixError):
            client.list_projects()
        self.assertEqual(len(origin.requests), 1)


class TestServerUrlValidation(unittest.TestCase):
    ACCEPT = [
        "https://example.com",
        "https://example.com:8443",
        "https://example.com:8443/",
        "https://[2001:db8::1]:8443",
        "http://localhost",
        "http://LOCALHOST:8080",
        "http://127.0.0.1:8080",
        "http://127.1.2.3:8080",
        "http://[::1]:8080",
        "https://exämple.com",
    ]
    REJECT = [
        "",
        "example.com",
        "ftp://example.com",
        "file:///etc/passwd",
        "http://example.com",
        "http://localhost.evil.com",
        # userinfo
        "https://user:pw@example.com",
        "https://user@example.com",
        "http://localhost@evil.com",
        "http://evil.com@localhost",
        "http://evil.com\\@localhost",
        "http://localhost\\@evil.com",
        # whitespace and control characters
        "https://exa mple.com",
        "https://example.com\n",
        "https://example.com\r\nHost: evil",
        "https://example.com\t",
        "https://example.com\x00",
        # ports
        "http://127.0.0.1:abc",
        "https://example.com:abc",
        "https://example.com:99999",
        "https://example.com:-1",
        "https://example.com:0",
        "https://example.com:",
        "http://localhost:",
        # IPv6 zone ids and malformed literals
        "http://[::1%25lo]",
        "http://[::1%lo]",
        "https://[fe80::1%25eth0]",
        "http://[::1",
        "http://::1",
        # shorthand loopback forms
        "http://127.1",
        "http://127.1:8080",
        "http://2130706433",
        "http://0x7f.0.0.1",
        "http://0x7f000001",
        "http://017700000001",
        "http://127.0.0.01",
        "http://127.0.1",
        "http://0",
        "http://0.0.0.0",
        "http://ｌｏｃａｌｈｏｓｔ",
    ]

    def test_accepts(self):
        for url in self.ACCEPT:
            with self.subTest(url=url):
                keyorix.Client(url, "tok")

    def test_rejects_client(self):
        for url in self.REJECT:
            with self.subTest(url=url):
                with self.assertRaises(keyorix.KeyorixError):
                    keyorix.Client(url, "tok")

    def test_rejects_login(self):
        for url in self.REJECT:
            with self.subTest(url=url):
                with self.assertRaises(keyorix.KeyorixError):
                    keyorix.login(url, "u", "p")

    def test_non_string_rejected(self):
        for value in (None, 8080, b"https://example.com"):
            with self.subTest(value=value):
                with self.assertRaises(keyorix.KeyorixError):
                    keyorix.Client(value, "tok")

    def test_message_does_not_echo_credentials(self):
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            keyorix.Client("https://user:s3cret@example.com", "tok")
        self.assertNotIn("s3cret", str(ctx.exception))


class TestTokenHandling(unittest.TestCase):
    BAD_TOKENS = [
        "abc\r\nX-Injected: 1",
        "abc\n",
        "abc\r",
        "abc\x00def",
        "abc\tdef",
        "abc\x7fdef",
        "\x1bsecret",
        "töken",
    ]

    def test_bad_token_rejected_at_construction_without_echo(self):
        for token in self.BAD_TOKENS:
            with self.subTest(token=repr(token)):
                with self.assertRaises(keyorix.KeyorixError) as ctx:
                    keyorix.Client("http://localhost:8080", token)
                message = str(ctx.exception)
                self.assertNotIn("abc", message)
                self.assertNotIn("secret", message)
                self.assertNotIn("X-Injected", message)

    def test_non_string_token_rejected(self):
        for token in (None, 123, b"tok"):
            with self.subTest(token=repr(token)):
                with self.assertRaises(keyorix.KeyorixError):
                    keyorix.Client("http://localhost:8080", token)

    def test_normal_tokens_accepted(self):
        for token in ("", "tok", "a.b-c_d~e+f/g=", "kx_" + "A1" * 30):
            with self.subTest(token=token):
                keyorix.Client("http://localhost:8080", token)

    def test_low_level_header_error_is_wrapped_and_redacted(self):
        # Defence in depth: even if a bad value reaches the HTTP layer (here by
        # bypassing the constructor check), the raw header value must not
        # appear in the raised error, and the error is the SDK's own class.
        server = _RecordingServer()
        self.addCleanup(server.close)
        client = keyorix.Client(f"http://127.0.0.1:{server.port}", "tok")
        client._token = "abc\r\nX-Injected: 1"
        calls = (
            lambda: client.list_projects(),
            lambda: client.create_project("p"),
        )
        for call in calls:
            with self.assertRaises(keyorix.KeyorixError) as ctx:
                call()
            message = str(ctx.exception)
            self.assertNotIn("abc", message)
            self.assertNotIn("X-Injected", message)
            self.assertTrue(ctx.exception.__suppress_context__)
        self.assertEqual(server.requests, [])


if __name__ == "__main__":
    unittest.main()
