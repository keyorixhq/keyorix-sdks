"""Unit tests for keyorix Python SDK."""

import io
import unittest
import urllib.error
from unittest.mock import patch, MagicMock
import json
import keyorix


def _mock_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode()
    resp.__enter__.return_value = resp
    return resp


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
            "ID": 1,
            "Name": "db-password",
            "Type": "password",
            "environment_name": "production",
            "ProjectID": 1,
            "CreatedAt": "2026-04-19T00:00:00Z",
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
            client.list_secrets()
        self.assertNotIn(raw, str(ctx.exception))
        self.assertEqual(ctx.exception.response_body, raw)
        self.assertEqual(ctx.exception.status_code, 500)

    @patch("keyorix.urllib.request.urlopen")
    def test_list_secrets_never_sends_environment_query_param_filters_client_side(self, mock_urlopen):
        # keyorix-sdks#35: the server now returns 400 for a bare `environment`
        # name query parameter (keyorix#2013), so list_secrets must never send
        # it, and must instead filter the (unscoped) response client-side by
        # the environment_name field every secret already carries.
        mock_urlopen.return_value = _mock_response({
            "data": {"secrets": [
                {"ID": 1, "Name": "db-pass", "Type": "password", "ProjectID": 1,
                 "environment_name": "production", "CreatedAt": "2026-01-01T00:00:00Z"},
                {"ID": 2, "Name": "api-key", "Type": "generic", "ProjectID": 1,
                 "environment_name": "staging", "CreatedAt": "2026-01-01T00:00:00Z"},
            ]}
        })

        client = keyorix.Client("http://localhost:8080", "test-token")
        secrets = client.list_secrets("production")

        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].name, "db-pass")

        sent_req = mock_urlopen.call_args[0][0]
        self.assertNotIn("environment=", sent_req.full_url)

        mock_urlopen.reset_mock()
        mock_urlopen.return_value = _mock_response({
            "data": {"secrets": [
                {"ID": 1, "Name": "db-pass", "Type": "password", "ProjectID": 1,
                 "environment_name": "production", "CreatedAt": "2026-01-01T00:00:00Z"},
                {"ID": 2, "Name": "api-key", "Type": "generic", "ProjectID": 1,
                 "environment_name": "staging", "CreatedAt": "2026-01-01T00:00:00Z"},
            ]}
        })
        all_secrets = client.list_secrets()
        self.assertEqual(len(all_secrets), 2)

    @patch("keyorix.urllib.request.urlopen")
    def test_list_secrets_in_project_resolves_environment_name_to_id(self, mock_urlopen):
        def side_effect(req, timeout=None):
            if "/environments" in req.full_url:
                return _mock_response({"data": {"environments": [
                    {"ID": 7, "ProjectID": 1, "Name": "production"}
                ]}})
            return _mock_response({"data": {"secrets": [
                {"ID": 42, "Name": "db-pass", "Type": "password", "ProjectID": 1,
                 "environment_name": "production", "CreatedAt": "2026-01-01T00:00:00Z"}
            ]}})
        mock_urlopen.side_effect = side_effect

        client = keyorix.Client("http://localhost:8080", "test-token")
        secrets = client.list_secrets_in_project(1, "production")

        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].name, "db-pass")

        secrets_calls = [c for c in mock_urlopen.call_args_list if "/api/v1/secrets?" in c[0][0].full_url]
        self.assertEqual(len(secrets_calls), 1)
        url = secrets_calls[0][0][0].full_url
        self.assertIn("project_id=1", url)
        self.assertIn("environment_id=7", url)
        self.assertNotIn("environment=production", url)

    @patch("keyorix.urllib.request.urlopen")
    def test_list_secrets_in_project_unknown_environment_raises(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"data": {"environments": []}})
        client = keyorix.Client("http://localhost:8080", "test-token")
        with self.assertRaises(keyorix.KeyorixError):
            client.list_secrets_in_project(1, "nonexistent-env")

    @patch("keyorix.urllib.request.urlopen")
    def test_get_secret_in_project_happy_path(self, mock_urlopen):
        def side_effect(req, timeout=None):
            if "/environments" in req.full_url:
                return _mock_response({"data": {"environments": [
                    {"ID": 7, "ProjectID": 1, "Name": "production"}
                ]}})
            if "include_value=true" in req.full_url:
                return _mock_response({"data": {"value": "s3cr3t"}})
            return _mock_response({"data": {"secrets": [
                {"ID": 42, "Name": "db-pass", "Type": "password", "ProjectID": 1,
                 "environment_name": "production", "CreatedAt": "2026-01-01T00:00:00Z"}
            ]}})
        mock_urlopen.side_effect = side_effect

        client = keyorix.Client("http://localhost:8080", "test-token")
        value = client.get_secret_in_project(1, "db-pass", "production")
        self.assertEqual(value, "s3cr3t")


if __name__ == "__main__":
    unittest.main()
