"""
keyorix — Python client for the Keyorix secrets manager.

Quick start:

    import keyorix

    # Option 1: use a token directly
    client = keyorix.Client("http://your-server:8080", "your-token")

    # Option 2: log in with username/password
    token = keyorix.login("http://your-server:8080", "admin", "password")
    client = keyorix.Client("http://your-server:8080", token)

    # Get a secret
    db_password = client.get_secret("db-password", "production")

    # List secrets
    secrets = client.list_secrets("production")
"""

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


class KeyorixError(Exception):
    """Raised when the Keyorix API returns an error."""

    pass


class AuthError(KeyorixError):
    """Raised on authentication failure."""

    pass


class SecretNotFoundError(KeyorixError):
    """Raised when a secret cannot be found."""

    pass


@dataclass
class Secret:
    """A secret returned by the Keyorix API."""

    id: int
    name: str
    type: str
    environment: str
    namespace: str
    created_at: str

    @classmethod
    def _from_dict(cls, data: dict) -> "Secret":
        return cls(
            id=data.get("ID", 0),
            name=data.get("Name", ""),
            type=data.get("Type", ""),
            environment=data.get("environment_name", ""),
            namespace=data.get("namespace_name", ""),
            created_at=data.get("CreatedAt", ""),
        )


def login(server_url: str, username: str, password: str, timeout: int = 30) -> str:
    """Authenticate with Keyorix and return a session token.

    Args:
        server_url: Base URL of your Keyorix server (e.g. "http://localhost:8080")
        username: Keyorix username
        password: Keyorix password
        timeout: Request timeout in seconds (default 30)

    Returns:
        Session token string

    Raises:
        AuthError: If authentication fails
        KeyorixError: On other errors
    """
    payload = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        f"{server_url.rstrip('/')}/auth/login",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            token = data.get("data", {}).get("token", "")
            if not token:
                raise AuthError("No token in login response")
            return token
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise AuthError(f"Login failed (HTTP {e.code}): {body}") from e
    except urllib.error.URLError as e:
        raise KeyorixError(f"Server unreachable: {e.reason}") from e


class Client:
    """Keyorix API client.

    Args:
        server_url: Base URL of your Keyorix server
        token: Session token (obtain via keyorix.login() or CLI)
        timeout: Request timeout in seconds (default 30)
    """

    def __init__(self, server_url: str, token: str, timeout: int = 30):
        self._base = server_url.rstrip("/")
        self._token = token
        self._timeout = timeout

    def _request(self, method: str, path: str) -> dict:
        req = urllib.request.Request(
            f"{self._base}{path}",
            headers={"Authorization": f"Bearer {self._token}"},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AuthError("Unauthorized — check your token") from e
            body = e.read().decode(errors="replace")
            raise KeyorixError(f"Server returned {e.code}: {body}") from e
        except urllib.error.URLError as e:
            raise KeyorixError(f"Request failed: {e.reason}") from e

    def health(self) -> bool:
        """Check if the server is reachable and healthy.

        Returns:
            True if healthy

        Raises:
            KeyorixError: If server is unreachable or unhealthy
        """
        req = urllib.request.Request(
            f"{self._base}/health",
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.status == 200
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            raise KeyorixError(f"Server unreachable: {e}") from e

    def list_secrets(self, environment: str = "") -> List[Secret]:
        """List secrets visible to the authenticated user.

        Args:
            environment: Filter by environment ("production", "staging", "development").
                         Pass empty string for all environments.

        Returns:
            List of Secret objects
        """
        path = "/api/v1/secrets"
        if environment:
            path += f"?environment={urllib.parse.quote(environment)}"
        data = self._request("GET", path)
        secrets_data = data.get("data", {}).get("secrets", [])
        return [Secret._from_dict(s) for s in secrets_data]

    def get_secret(self, name: str, environment: str = "") -> str:
        """Get the value of a secret by name.

        Args:
            name: Secret name
            environment: Environment to search in ("production", "staging", "development")

        Returns:
            Plaintext secret value

        Raises:
            SecretNotFoundError: If secret is not found
            KeyorixError: On other errors
        """
        secrets = self.list_secrets(environment)
        for secret in secrets:
            if secret.name == name:
                return self._get_secret_value(secret.id)
        env_msg = f" in environment {environment!r}" if environment else ""
        raise SecretNotFoundError(f"Secret {name!r} not found{env_msg}")

    def _get_secret_value(self, secret_id: int) -> str:
        data = self._request("GET", f"/api/v1/secrets/{secret_id}?include_value=true")
        return data.get("data", {}).get("value", "")


# Fix missing import
import urllib.parse
