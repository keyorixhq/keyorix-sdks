"""
keyorix — Python client for the Keyorix secrets manager.

Quick start:

    import keyorix

    # Option 1: use a token directly
    client = keyorix.Client("https://your-server:8443", "your-token")

    # Option 2: log in with username/password
    token = keyorix.login("https://your-server:8443", "admin", "password")
    client = keyorix.Client("https://your-server:8443", token)

    # Get a secret -- scoped to a project + environment, since an environment
    # name is only unique within one project, not globally.
    db_password = client.get_secret_scoped("db-password", "my-project", "production")

    # List secrets
    secrets = client.list_secrets_scoped("my-project", "production")
"""

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Union


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


class AmbiguousSecretError(KeyorixError):
    """Raised when a secret name matches more than one secret within a
    project+environment scope. Never guessed which one was meant — see the
    ids attribute for every matching secret ID.
    """

    def __init__(self, message: str, *, ids: List[int]):
        super().__init__(message)
        self.ids = ids


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
        # Populated lazily by _resolve_project/_resolve_environment and never
        # invalidated for the lifetime of this Client -- a project/environment
        # rename mid-process is expected to be rare enough that a fresh
        # Client is the right way to pick it up, not a cache-expiry policy.
        self._project_cache: Dict[str, int] = {}  # lowercased name -> id
        self._env_cache: Dict[int, Dict[str, int]] = {}  # project id -> lowercased name -> id

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

    def list_secrets(self, environment: str = "") -> List[Secret]:
        """Deprecated: removed in keyorix v0.3.0.

        An environment name is only unique within one project, not globally,
        so scoping by environment alone could silently return secrets from
        every project the caller can read. Always raises without ever
        contacting the server (no silent fallback to the old, unscoped
        behavior) -- use list_secrets_scoped(project, environment) instead.
        """
        raise KeyorixError(
            "list_secrets(environment) was removed in keyorix v0.3.0 (an environment "
            "name is only unique within one project, not globally) -- use "
            "list_secrets_scoped(project, environment) instead"
        )

    def get_secret(self, name: str, environment: str = "") -> str:
        """Deprecated: removed in keyorix v0.3.0.

        An environment name is only unique within one project, not globally,
        so scoping by environment alone could silently resolve to another
        project's same-named secret. Always raises without ever contacting
        the server (no silent fallback to the old, unscoped behavior) -- use
        get_secret_scoped(name, project, environment) instead.
        """
        raise KeyorixError(
            "get_secret(name, environment) was removed in keyorix v0.3.0 (an environment "
            "name is only unique within one project, not globally) -- use "
            "get_secret_scoped(name, project, environment) instead"
        )

    def list_secrets_scoped(self, project: Union[str, int], environment: Union[str, int]) -> List[Secret]:
        """List every secret within one project's environment.

        Args:
            project: Project name (resolved to an ID and cached on this
                     Client) or numeric project ID (no resolution round trip).
            environment: Environment name (resolved within `project`, cached)
                         or numeric environment ID.

        Returns:
            List of Secret objects
        """
        project_id = self._resolve_project(project)
        env_id = self._resolve_environment(project_id, environment)
        path = f"/api/v1/secrets?project_id={project_id}&environment_id={env_id}"
        data = self._request("GET", path)
        secrets_data = data.get("data", {}).get("secrets", [])
        return [Secret._from_dict(s) for s in secrets_data]

    def get_secret_scoped(
        self, name: str, project: Union[str, int], environment: Union[str, int]
    ) -> str:
        """Get the value of the secret named `name` within one project's
        environment. `name` is matched exactly (case-sensitive) among the
        secrets in that scope.

        Args:
            name: Secret name
            project: Project name or numeric ID (see list_secrets_scoped)
            environment: Environment name or numeric ID (see list_secrets_scoped)

        Returns:
            Plaintext secret value

        Raises:
            SecretNotFoundError: If no secret in scope has this name
            AmbiguousSecretError: If more than one secret in scope has this
                                   name -- never guessed; .ids lists every match
            KeyorixError: On other errors
        """
        secrets = self.list_secrets_scoped(project, environment)
        matches = [s for s in secrets if s.name == name]
        if not matches:
            raise SecretNotFoundError(
                f"Secret {name!r} not found in project {project!r}, environment {environment!r}"
            )
        if len(matches) > 1:
            ids = [s.id for s in matches]
            raise AmbiguousSecretError(
                f"Secret {name!r} is ambiguous in project {project!r}, environment "
                f"{environment!r}: matches IDs {ids}",
                ids=ids,
            )
        return self._get_secret_value(matches[0].id)

    def _resolve_project(self, project: Union[str, int]) -> int:
        """Resolve project to an ID. An int resolves with no network call; a
        str is resolved via GET /api/v1/projects and cached (case-insensitive
        match)."""
        if isinstance(project, int):
            return project
        key = project.lower()
        if key in self._project_cache:
            return self._project_cache[key]
        for p in self.list_projects():
            self._project_cache[p.name.lower()] = p.id
        if key not in self._project_cache:
            raise KeyorixError(f"Project {project!r} not found")
        return self._project_cache[key]

    def _resolve_environment(self, project_id: int, environment: Union[str, int]) -> int:
        """Resolve environment to an ID within project_id. An int resolves
        with no network call; a str is resolved via the project-scoped
        environments route and cached (case-insensitive match)."""
        if isinstance(environment, int):
            return environment
        key = environment.lower()
        cached = self._env_cache.get(project_id, {})
        if key in cached:
            return cached[key]
        by_name = self._env_cache.setdefault(project_id, {})
        for e in self.list_environments(project_id):
            by_name[e.name.lower()] = e.id
        if key not in by_name:
            raise KeyorixError(f"Environment {environment!r} not found in project id={project_id}")
        return by_name[key]

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
