"""
keyorix — Python client for the Keyorix secrets manager.

Quick start:

    import keyorix

    # Option 1: use a token directly
    client = keyorix.Client("https://your-server:8443", "your-token")

    # Option 2: log in with username/password
    token = keyorix.login("https://your-server:8443", "admin", "password")
    client = keyorix.Client("https://your-server:8443", token)

    # Get a secret
    db_password = client.get_secret("db-password", "production")

    # List secrets
    secrets = client.list_secrets("production")
"""

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


class KeyorixError(Exception):
    """Raised when the Keyorix API returns an error.

    The exception message deliberately omits the raw response body: it's
    server-controlled content that this SDK's own README quick-start passes
    straight to a bare `except ... as e: print(e)`, and an unconditional
    relay into that path is exactly how untrusted content ends up verbatim
    in application logs. Callers who need the body for their own (redacted)
    logging can read the response_body attribute directly.
    """

    def __init__(self, message: str, *, status_code: Optional[int] = None, response_body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


def _is_loopback_host(host: Optional[str]) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_server_url(server_url: str) -> None:
    """Reject any scheme but https; allow http only for localhost/loopback.

    A bearer token and every secret value would otherwise be sent/received
    in cleartext, and an unrestricted scheme (e.g. file://) would let a
    caller-influenced server_url reach something other than an HTTP server
    entirely.
    """
    parsed = urllib.parse.urlsplit(server_url)
    scheme = parsed.scheme.lower()
    if scheme == "https":
        return
    if scheme == "http" and _is_loopback_host(parsed.hostname):
        return
    raise KeyorixError(
        f"server_url {server_url!r} must use https:// "
        "(http:// is only allowed for localhost/loopback)"
    )


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
    project_id: int
    environment: str
    created_at: str

    @classmethod
    def _from_dict(cls, data: dict) -> "Secret":
        return cls(
            id=data.get("ID", 0),
            name=data.get("Name", ""),
            type=data.get("Type", ""),
            project_id=data.get("ProjectID", 0),
            environment=data.get("environment_name", ""),
            created_at=data.get("CreatedAt", ""),
        )


@dataclass
class Project:
    """A Keyorix project."""

    id: int
    name: str
    description: str
    created_at: str

    @classmethod
    def _from_dict(cls, data: dict) -> "Project":
        return cls(
            id=data.get("ID", 0),
            name=data.get("Name", ""),
            description=data.get("Description", ""),
            created_at=data.get("CreatedAt", ""),
        )


@dataclass
class Environment:
    """An environment scoped to a project."""

    id: int
    project_id: int
    name: str

    @classmethod
    def _from_dict(cls, data: dict) -> "Environment":
        return cls(
            id=data.get("ID", 0),
            project_id=data.get("ProjectID", 0),
            name=data.get("Name", ""),
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
    _validate_server_url(server_url)
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
        raise AuthError(f"Login failed (HTTP {e.code})", status_code=e.code, response_body=body) from e
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
        _validate_server_url(server_url)
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
            raise KeyorixError(f"Server returned {e.code}", status_code=e.code, response_body=body) from e
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
        except urllib.error.URLError as e:
            raise KeyorixError(f"Server unreachable: {e}") from e

    def _list_secrets_raw(self, query: dict) -> List[Secret]:
        path = "/api/v1/secrets"
        if query:
            path += f"?{urllib.parse.urlencode(query)}"
        data = self._request("GET", path)
        secrets_data = data.get("data", {}).get("secrets", [])
        return [Secret._from_dict(s) for s in secrets_data]

    def list_secrets(self, environment: str = "") -> List[Secret]:
        """List secrets visible to the authenticated user.

        Args:
            environment: Filter by environment name ("production", "staging",
                         "development"), across every project you can read.
                         Pass empty string for all environments.

        Returns:
            List of Secret objects

        Note:
            An environment name is only unique WITHIN a project, not globally
            -- if two projects both have a "production" environment, this
            filters to secrets in EITHER of them. Use list_secrets_in_project
            to scope to one specific project as well.

            The server only recognizes project_id/environment_id (numeric) as
            real filters -- a bare `environment` name query parameter is
            rejected with 400. This method filters by name CLIENT-SIDE, after
            fetching the caller's full (unscoped) secret list, so the
            environment argument's documented behavior actually works,
            instead of previously being silently ignored server-side.
        """
        secrets = self._list_secrets_raw({})
        if not environment:
            return secrets
        return [s for s in secrets if s.environment == environment]

    def get_secret(self, name: str, environment: str = "") -> str:
        """Get the value of a secret by name.

        Args:
            name: Secret name
            environment: Environment to search in ("production", "staging", "development"),
                         matched across every project you can read -- if the SAME
                         environment name exists in more than one project and both
                         contain a same-named secret, which one is returned is
                         unspecified. Use get_secret_in_project to disambiguate.

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

    def list_secrets_in_project(self, project_id: int, environment: str = "") -> List[Secret]:
        """List secrets in a single project, optionally filtered to one
        environment within it (by name).

        Unlike list_secrets, this resolves environment to the numeric
        environment_id the server actually honors, scoped by project_id -- so
        it never confuses a same-named environment/secret in a different
        project the way name-only filtering can.

        Args:
            project_id: ID of the project to scope to
            environment: Environment name within that project, or empty for all

        Returns:
            List of Secret objects

        Raises:
            KeyorixError: If environment is non-empty and no environment with
                          that name exists in the given project
        """
        query = {"project_id": project_id}
        if environment:
            env_id = None
            for env in self.list_environments(project_id):
                if env.name == environment:
                    env_id = env.id
                    break
            if env_id is None:
                raise KeyorixError(f"environment {environment!r} not found in project {project_id}")
            query["environment_id"] = env_id
        return self._list_secrets_raw(query)

    def get_secret_in_project(self, project_id: int, name: str, environment: str = "") -> str:
        """Get the value of a secret by name, scoped to one project and
        (optionally) one environment within it -- the disambiguated
        counterpart to get_secret for deployments where the same environment
        name (or secret name) recurs across projects.

        Raises:
            SecretNotFoundError: If secret is not found
            KeyorixError: On other errors
        """
        secrets = self.list_secrets_in_project(project_id, environment)
        for secret in secrets:
            if secret.name == name:
                return self._get_secret_value(secret.id)
        env_msg = f", environment {environment!r}" if environment else ""
        raise SecretNotFoundError(f"Secret {name!r} not found in project {project_id}{env_msg}")

    def _get_secret_value(self, secret_id: int) -> str:
        data = self._request("GET", f"/api/v1/secrets/{secret_id}?include_value=true")
        return data.get("data", {}).get("value", "")

    def list_projects(self) -> List["Project"]:
        """List all projects visible to the authenticated user.

        Returns:
            List of Project objects
        """
        data = self._request("GET", "/api/v1/projects")
        return [Project._from_dict(p) for p in data.get("data", {}).get("projects", [])]

    def create_project(self, name: str, description: str = "") -> "Project":
        """Create a new project. Seeds development/staging/production environments.

        Args:
            name: Project name (must be unique)
            description: Optional description

        Returns:
            Created Project object
        """
        payload = json.dumps({"name": name, "description": description}).encode()
        req = urllib.request.Request(
            f"{self._base}/api/v1/projects",
            data=payload,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
                return Project._from_dict(data.get("data", {}))
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise KeyorixError(f"Failed to create project (HTTP {e.code})", status_code=e.code, response_body=body) from e

    def list_environments(self, project_id: int) -> List["Environment"]:
        """List all environments for a project.

        Args:
            project_id: ID of the project

        Returns:
            List of Environment objects
        """
        data = self._request("GET", f"/api/v1/projects/{project_id}/environments")
        return [Environment._from_dict(e) for e in data.get("data", {}).get("environments", [])]
