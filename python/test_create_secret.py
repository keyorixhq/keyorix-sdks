"""Unit tests for Client.create_secret (POST /api/v1/secrets)."""

import io
import json
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

import keyorix

VALUE = 'pa"ss\nword-s3cr3t-must-not-leak'
CREATED = {"data": {"id": 7, "name": "db-password", "type": "generic", "project_id": 3, "environment_id": 4}}


def _ok(payload):
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode()
    resp.__enter__.return_value = resp
    return resp


def _http_error(status, body):
    return urllib.error.HTTPError(
        "http://localhost:8080/api/v1/secrets", status, "x", {}, io.BytesIO(body.encode())
    )


class TestCreateSecret(unittest.TestCase):
    def setUp(self):
        self.client = keyorix.Client("http://localhost:8080", "test-token")

    @patch("keyorix.urllib.request.urlopen")
    def test_sends_scoped_body_and_returns_node(self, mock_urlopen):
        mock_urlopen.return_value = _ok(CREATED)
        s = self.client.create_secret(3, 4, "db-password", VALUE, description="note")
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_method(), "POST")
        self.assertTrue(req.full_url.endswith("/api/v1/secrets"))
        self.assertEqual(req.get_header("Authorization"), "Bearer test-token")
        sent = json.loads(req.data)
        self.assertEqual(
            sent,
            {"name": "db-password", "value": VALUE, "project_id": 3, "environment_id": 4,
             "type": "generic", "description": "note"},
        )
        self.assertIsInstance(s, keyorix.Secret)
        self.assertEqual((s.id, s.name, s.type, s.project_id), (7, "db-password", "generic", 3))

    @patch("keyorix.urllib.request.urlopen")
    def test_duplicate_name_is_typed(self, mock_urlopen):
        mock_urlopen.side_effect = _http_error(
            409, json.dumps({"success": False, "error": "ConflictError", "message": "exists", "code": 409})
        )
        with self.assertRaises(keyorix.SecretAlreadyExistsError) as ctx:
            self.client.create_secret(3, 4, "dup", VALUE)
        self.assertIsInstance(ctx.exception, keyorix.KeyorixError)
        self.assertEqual((ctx.exception.status_code, ctx.exception.code), (409, "ConflictError"))

    @patch("keyorix.urllib.request.urlopen")
    def test_unauthenticated_is_auth_error(self, mock_urlopen):
        mock_urlopen.side_effect = _http_error(401, json.dumps({"error": "Unauthorized"}))
        with self.assertRaises(keyorix.AuthError):
            self.client.create_secret(3, 4, "n", VALUE)

    @patch("keyorix.urllib.request.urlopen")
    def test_value_never_appears_in_errors(self, mock_urlopen):
        escaped = json.dumps(VALUE)[1:-1]
        body = json.dumps({"error": "ValidationError", "message": "echo"}) + f" raw={VALUE} esc={escaped}"
        for status in (400, 401, 403, 409, 500):
            mock_urlopen.side_effect = _http_error(status, body)
            with self.assertRaises(keyorix.KeyorixError) as ctx:
                self.client.create_secret(3, 4, "n", VALUE)
            e = ctx.exception
            for text in (str(e), repr(e), e.response_body or "", repr(e.__cause__)):
                self.assertNotIn("s3cr3t-must-not-leak", text, f"status {status}")

    @patch("keyorix.urllib.request.urlopen")
    def test_transport_error_does_not_leak_value(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")
        with self.assertRaises(keyorix.KeyorixError) as ctx:
            self.client.create_secret(3, 4, "n", VALUE)
        self.assertNotIn("s3cr3t-must-not-leak", str(ctx.exception))

    def test_secret_repr_has_no_value_field(self):
        s = keyorix.Secret._from_dict(CREATED["data"])
        self.assertNotIn("value", repr(s).lower().replace("environment", ""))


if __name__ == "__main__":
    unittest.main()
