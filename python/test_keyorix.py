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


if __name__ == "__main__":
    unittest.main()
