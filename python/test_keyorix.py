"""Unit tests for keyorix Python SDK."""

import unittest
from unittest.mock import patch, MagicMock
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


if __name__ == "__main__":
    unittest.main()
