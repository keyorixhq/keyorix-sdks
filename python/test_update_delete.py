"""Unit tests for update_secret / delete_secret (and their *_by_id primitives)
against a local stub server: request shape, typed errors, and the rule that the
secret value never appears in an error. The behaviour against a real server is
in test_update_delete_contract.py.

CI runs only test_keyorix.py (python.yml), which imports UpdateDeleteTests.
"""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import keyorix

NEW_VALUE = "rotated-value-xyz"


class _Stub:
    """A local HTTP server answering every request with `respond(handler, body)`;
    records each request as (method, path, authorization, body)."""

    def __init__(self, respond):
        self.calls = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode() if length else ""
                stub.calls.append((self.command, self.path, self.headers.get("Authorization"), body))
                respond(self, body)

            do_GET = do_PUT = do_DELETE = _handle

            def log_message(self, *args):
                pass

        self._httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._httpd.server_address[1]}"
        threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._httpd.shutdown()
        self._httpd.server_close()


def _reply(handler, status, body="", headers=None):
    data = body.encode()
    handler.send_response(status)
    for k, v in (headers or {}).items():
        handler.send_header(k, v)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class UpdateDeleteTests(unittest.TestCase):
    def test_update_secret_by_id_sends_put_with_value_and_returns_metadata(self):
        ok = json.dumps({"data": {"id": 7, "name": "db", "type": "generic", "project_id": 3}})
        with _Stub(lambda h, b: _reply(h, 200, ok)) as stub:
            s = keyorix.Client(stub.url, "tok").update_secret_by_id(7, NEW_VALUE)
        method, path, auth, body = stub.calls[0]
        self.assertEqual((method, path, auth), ("PUT", "/api/v1/secrets/7", "Bearer tok"))
        self.assertEqual(json.loads(body), {"value": NEW_VALUE})
        self.assertEqual((s.id, s.name, s.project_id), (7, "db", 3))
        self.assertNotIn(NEW_VALUE, repr(s))

    def test_update_secret_refuses_bad_input_without_a_request(self):
        with _Stub(lambda h, b: _reply(h, 200, "{}")) as stub:
            c = keyorix.Client(stub.url, "tok")
            for bad in ("", None, 42):
                with self.assertRaises(keyorix.KeyorixError, msg=repr(bad)):
                    c.update_secret_by_id(7, bad)
            for bad_id in (0, -1, 1.5, "7", "7/versions", True, None):
                with self.assertRaises(keyorix.KeyorixError, msg=repr(bad_id)):
                    c.delete_secret_by_id(bad_id)
            self.assertEqual(stub.calls, [])

    def test_errors_never_carry_the_value_even_if_the_server_echoes_it(self):
        tricky = 'pa"ss' + NEW_VALUE  # the quote forces a JSON escape
        for status in (400, 403, 404, 409, 500):
            echo = json.dumps({"error": "X", "message": f"bad value {tricky}"})
            with _Stub(lambda h, b, echo=echo, status=status: _reply(h, status, echo)) as stub:
                with self.assertRaises(keyorix.KeyorixError) as ctx:
                    keyorix.Client(stub.url, "tok").update_secret_by_id(7, tricky)
            err = ctx.exception
            everything = f"{err} {err!r} {err.response_body} {err.args}"
            self.assertNotIn(NEW_VALUE, everything, f"status {status}")
            self.assertEqual(err.status_code, status)

    def test_typed_errors_for_update_and_delete(self):
        for status, cls in ((401, keyorix.AuthError), (403, keyorix.ForbiddenError), (404, keyorix.NotFoundError)):
            with _Stub(lambda h, b, status=status: _reply(h, status, "{}")) as stub:
                c = keyorix.Client(stub.url, "tok")
                with self.assertRaises(cls, msg=f"update {status}"):
                    c.update_secret_by_id(1, "v")
                with self.assertRaises(cls, msg=f"delete {status}"):
                    c.delete_secret_by_id(1)

    def test_delete_returns_the_purge_date_when_sent(self):
        with _Stub(lambda h, b: _reply(h, 204, headers={"Keyorix-Purge-At": "2026-11-30T14:56:16Z"})) as stub:
            at = keyorix.Client(stub.url, "tok").delete_secret_by_id(9)
        self.assertEqual(stub.calls[0][:2], ("DELETE", "/api/v1/secrets/9"))
        self.assertEqual(stub.calls[0][3], "")
        self.assertEqual(at, "2026-11-30T14:56:16Z")

    def test_delete_without_a_purge_date_still_succeeds(self):
        with _Stub(lambda h, b: _reply(h, 204)) as stub:
            self.assertIsNone(keyorix.Client(stub.url, "tok").delete_secret_by_id(9))

    def test_names_resolve_to_ids_and_ambiguity_never_writes(self):
        listing = json.dumps(
            {"data": {"secrets": [{"id": 1, "name": "dup"}, {"id": 2, "name": "dup"}, {"id": 3, "name": "solo"}], "total_pages": 1}}
        )

        def respond(h, body):
            if h.command == "GET":
                _reply(h, 200, listing)
            elif h.command == "PUT":
                _reply(h, 200, json.dumps({"data": {"id": 3, "name": "solo"}}))
            else:
                _reply(h, 204)

        with _Stub(respond) as stub:
            c = keyorix.Client(stub.url, "tok")
            self.assertEqual(c.update_secret(1, 1, "solo", "v").id, 3)
            c.delete_secret(1, 1, "solo")
            with self.assertRaises(keyorix.AmbiguousSecretError):
                c.update_secret(1, 1, "dup", "v")
            with self.assertRaises(keyorix.AmbiguousSecretError):
                c.delete_secret(1, 1, "dup")
            with self.assertRaises(keyorix.SecretNotFoundError):
                c.update_secret(1, 1, "ghost", "v")
        writes = [(m, p) for m, p, _, _ in stub.calls if m in ("PUT", "DELETE")]
        self.assertEqual(writes, [("PUT", "/api/v1/secrets/3"), ("DELETE", "/api/v1/secrets/3")])


if __name__ == "__main__":
    unittest.main()
