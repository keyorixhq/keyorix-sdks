"""
keyorix — Python client for the Keyorix secrets manager.

Quick start, for a machine identity token (the recommended credential for
an unattended application -- see the README):

    import keyorix

    client = keyorix.Client("https://your-server:8443", "your-machine-token")
    db_password = client.get_secret_in("my-project", "production", "db-password")

get_secret_in/get_secret_by_ref resolve and authorize in one round trip and
need no project/environment-list permission. get_secret_scoped/
list_secrets_scoped are the alternative when you already have (or want to
cache) project/environment IDs rather than names.
"""

import ipaddress
import json
import ssl
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

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        code: Optional[str] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body
        # The server's stable error code (the error envelope's "error" field,
        # e.g. "SecretSuspended"), or None when the body carries none.
        self.code = code


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


class MFARequiredError(AuthError):
    """Raised by login() when the password was accepted but the account has a
    second factor, so the server answered with an MFA challenge instead of a
    session. Still an AuthError (login() used to raise a generic AuthError
    here), so existing ``except AuthError`` handlers keep working.

    Complete the login with ``verify_mfa(server_url, e.challenge, code)``.
    ``methods`` lists the second factors the account has ("totp", "webauthn");
    this SDK completes only TOTP or recovery codes, a passkey needs a browser
    ceremony. The challenge is single-use and short-lived.
    """

    def __init__(self, challenge: str, *, totp_available: bool = False, webauthn_available: bool = False):
        super().__init__("Multi-factor authentication required — complete the login with verify_mfa()")
        self.challenge = challenge
        self.totp_available = totp_available
        self.webauthn_available = webauthn_available

    @property
    def methods(self) -> List[str]:
        return [m for m, ok in (("totp", self.totp_available), ("webauthn", self.webauthn_available)) if ok]


class ForbiddenError(KeyorixError):
    """Raised when the server rejects a request as unauthorized for this
    token's permissions (HTTP 403).
    """

    pass


class NotFoundError(KeyorixError):
    """Raised when a requested resource does not exist on the server (HTTP
    404). Distinct from SecretNotFoundError, which is raised by name-based
    resolution before any such request is made.
    """

    pass


# Stable error codes the server sends when a secret's own state refuses a value
# read. A read outside the access schedule is a 403 (ForbiddenError with this
# code); the other three are a 409 (SecretUnavailableError).
CODE_SECRET_ACCESS_OUTSIDE_SCHEDULE = "SecretAccessOutsideSchedule"
CODE_SECRET_EXPIRED = "SecretExpired"
CODE_SECRET_SUSPENDED = "SecretSuspended"
CODE_SECRET_MAX_READS_EXHAUSTED = "SecretMaxReadsExhausted"

_SECRET_UNAVAILABLE_MESSAGES = {
    CODE_SECRET_EXPIRED: "The secret has expired",
    CODE_SECRET_SUSPENDED: "The secret is suspended",
    CODE_SECRET_MAX_READS_EXHAUSTED: "The secret has reached its maximum number of reads",
}


class SecretUnavailableError(KeyorixError):
    """Raised when the token may read the secret but the secret's own state
    refuses the value read (HTTP 409): it has expired, is suspended, or has
    used up its max-reads budget. ``code`` says which; each is reversible by
    an operator.
    """

    pass


def _error_code(body: str) -> Optional[str]:
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
        return parsed["error"]
    return None


def _error_for_response(status_code: int, body: str) -> KeyorixError:
    """Maps a non-2xx HTTP status to a typed error: AuthError (401),
    ForbiddenError (403), NotFoundError (404), SecretUnavailableError (409
    with a secret-state code), or the generic KeyorixError
    for anything else. Every request path raises through this so callers
    can rely on isinstance() matching consistently, regardless of which
    method failed.
    """
    code = _error_code(body)
    if status_code == 401:
        return AuthError("Unauthorized — check your token", status_code=status_code, response_body=body, code=code)
    if status_code == 403:
        message = "Forbidden — token lacks permission for this request"
        if code == CODE_SECRET_ACCESS_OUTSIDE_SCHEDULE:
            message = "Forbidden — the secret is outside its access schedule"
        return ForbiddenError(message, status_code=status_code, response_body=body, code=code)
    if status_code == 404:
        return NotFoundError("Resource not found", status_code=status_code, response_body=body, code=code)
    if status_code == 409 and code in _SECRET_UNAVAILABLE_MESSAGES:
        return SecretUnavailableError(
            _SECRET_UNAVAILABLE_MESSAGES[code], status_code=status_code, response_body=body, code=code
        )
    return KeyorixError(f"Server returned {status_code}", status_code=status_code, response_body=body, code=code)


def _redact_value(body: str, payload: Optional[dict]) -> str:
    """Remove every occurrence of the request's secret value (raw and
    JSON-escaped) from a response body, so a server that echoes request
    content in a validation message cannot put the secret into an error's
    response_body."""
    value = payload.get("value") if payload else None
    if not isinstance(value, str) or value == "":
        return body
    escaped = json.dumps(value)[1:-1]
    return body.replace(value, "[REDACTED]").replace(escaped, "[REDACTED]")


def _secret_id(secret_id: int) -> int:
    """A secret ID is interpolated into the request path: accept only a
    positive int, so a caller-influenced id cannot change which resource is
    addressed."""
    if not isinstance(secret_id, int) or isinstance(secret_id, bool) or secret_id <= 0:
        raise KeyorixError("secret id must be a positive integer")
    return secret_id


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
    #: Restore deadline of a soft-deleted secret (RFC 3339 UTC; see
    #: Client.list_deleted_secrets). Empty for a live secret.
    purge_at: str = ""

    @classmethod
    def _from_dict(cls, data: dict) -> "Secret":
        return cls(
            id=data.get("id", 0),
            name=data.get("name", ""),
            type=data.get("type", ""),
            project_id=data.get("project_id", 0),
            environment=data.get("environment_name", ""),
            created_at=data.get("created_at", ""),
            purge_at=data.get("purge_at", ""),
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
            id=data.get("id", 0),
            name=data.get("name", ""),
            description=data.get("description", ""),
            created_at=data.get("created_at", ""),
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
            id=data.get("id", 0),
            project_id=data.get("project_id", 0),
            name=data.get("name", ""),
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
    return _auth_request(server_url, "/auth/login", {"username": username, "password": password}, timeout, "Login")


def verify_mfa(server_url: str, challenge: str, code: str, timeout: int = 30) -> str:
    """Complete a password login that raised MFARequiredError.

    Exchanges the error's ``challenge`` and a current TOTP (or recovery) code
    for a session token.

    Raises:
        AuthError: If the code or challenge is wrong or expired
        KeyorixError: On other errors
    """
    return _auth_request(
        server_url, "/auth/mfa/verify", {"mfa_challenge": challenge, "code": code}, timeout, "MFA verify"
    )


def _auth_request(server_url: str, path: str, payload: dict, timeout: int, what: str) -> str:
    _validate_server_url(server_url)
    req = urllib.request.Request(
        f"{server_url.rstrip('/')}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read()).get("data", {})
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise AuthError(
            f"{what} failed (HTTP {e.code})", status_code=e.code, response_body=body, code=_error_code(body)
        ) from e
    except urllib.error.URLError as e:
        raise KeyorixError(f"Server unreachable: {e.reason}") from e
    except TimeoutError as e:
        raise KeyorixError(f"Request timed out: {e}") from e

    if data.get("token"):
        return data["token"]
    if data.get("mfa_required") and data.get("mfa_challenge"):
        raise MFARequiredError(
            data["mfa_challenge"],
            totp_available=data.get("totp_available") is True,
            webauthn_available=data.get("webauthn_available") is True,
        )
    raise AuthError(f"No token in {what.lower()} response")


class Client:
    """Keyorix API client.

    Args:
        server_url: Base URL of your Keyorix server
        token: Session token (obtain via keyorix.login() or CLI)
        timeout: Request timeout in seconds (default 30)
        ca_file: Path to a PEM file of trusted CA certificate(s), for
            servers using a private/internal CA. No effect on plain
            http:// (loopback-only) connections.
    """

    def __init__(self, server_url: str, token: str, timeout: int = 30, ca_file: Optional[str] = None):
        _validate_server_url(server_url)
        self._base = server_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._ssl_context = ssl.create_default_context(cafile=ca_file) if ca_file else None
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
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl_context) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise _error_for_response(e.code, body) from e
        except urllib.error.URLError as e:
            raise KeyorixError(f"Request failed: {e.reason}") from e
        except TimeoutError as e:
            raise KeyorixError(f"Request timed out: {e}") from e

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
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl_context) as resp:
                return resp.status == 200
        except urllib.error.URLError as e:
            raise KeyorixError(f"Server unreachable: {e}") from e
        except TimeoutError as e:
            raise KeyorixError(f"Request timed out: {e}") from e

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

        Follows every page the server reports (`data.total_pages`) at
        page_size=100, so a scope with more secrets than fit on one page
        (the server defaults to 20) is never silently truncated.

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

        all_secrets: List[Secret] = []
        page = 1
        while True:
            path = (
                f"/api/v1/secrets?project_id={project_id}&environment_id={env_id}"
                f"&page={page}&page_size=100"
            )
            data = self._request("GET", path).get("data", {})
            all_secrets.extend(Secret._from_dict(s) for s in data.get("secrets", []))
            if page >= data.get("total_pages", 0):
                break
            page += 1
        return all_secrets

    def list_deleted_secrets(self, project: Union[str, int]) -> List[Secret]:
        """List a project's soft-deleted (restorable) secrets, newest deleted
        first. Each returned Secret has purge_at set: the instant (RFC 3339,
        UTC) before which the server will not hard-delete it, i.e. the
        restore deadline. Requires secrets.read at the project scope; the
        server caps the list at 500.

        Args:
            project: Project name or numeric project ID.
        """
        project_id = self._resolve_project(project)
        data = self._request("GET", f"/api/v1/projects/{project_id}/secrets/deleted?limit=500").get("data", {})
        secrets = [Secret._from_dict(s) for s in data.get("deleted", [])]
        for s in secrets:
            s.project_id = project_id
        return secrets

    def get_secret_in(self, project: str, environment: str, name: str) -> str:
        """Get the value of secret `name` within `project`/`environment`, all
        by name, via a single server-authorized round trip -- a thin wrapper
        around get_secret_by_ref. Unlike get_secret_scoped, this needs no
        project/environment-list permission, since the server resolves and
        authorizes the whole reference itself. project/environment/name are
        joined with "/" -- if any contains a literal "/", call
        get_secret_by_ref directly with your own escaping.

        Returns:
            Plaintext secret value
        """
        return self.get_secret_by_ref(f"{project}/{environment}/{name}")

    def get_secret_by_ref(self, ref: str) -> str:
        """Get a secret's value by its "project/environment/name" reference,
        via GET /api/v1/secrets/value?ref=<ref>. The server resolves and
        authorizes ref against the resolved secret's own scope in one round
        trip -- no project/environment-list permission needed, unlike
        get_secret_scoped. The secret name may itself contain "/"; only the
        first two "/"-separated segments of ref are taken as project and
        environment.

        Raises:
            NotFoundError: ref resolves to nothing and the caller holds the
                global permission needed to confirm that.
            ForbiddenError: either the token lacks permission outright, OR
                ref resolves to nothing and the caller does NOT hold that
                global permission -- the server denies without confirming
                the resource exists, to avoid existence enumeration.
            AuthError: the token is missing or invalid.
            KeyorixError: a malformed ref (not "project/environment/name")
                or any other error -- see _error_for_response.

        Returns:
            Plaintext secret value
        """
        data = self._request("GET", f"/api/v1/secrets/value?ref={urllib.parse.quote(ref, safe='')}")
        return data.get("data", {}).get("value", "")

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
        return self._get_secret_value(self._find_secret_id(name, project, environment))

    def _find_secret_id(self, name: str, project: Union[str, int], environment: Union[str, int]) -> int:
        """Resolve the secret named `name` within project+environment to its
        ID: SecretNotFoundError if none has that name, AmbiguousSecretError if
        more than one does."""
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
        return matches[0].id

    def update_secret(
        self, project: Union[str, int], environment: Union[str, int], name: str, value: str
    ) -> Secret:
        """Write `value` as a new version of the secret named `name` within
        project+environment and return its metadata (never the value). The
        name is resolved as for get_secret_scoped.

        Raises:
            SecretNotFoundError: If no secret in scope has this name
            AmbiguousSecretError: If more than one secret in scope has this name
            KeyorixError: See update_secret_by_id
        """
        return self.update_secret_by_id(self._find_secret_id(name, project, environment), value)

    def update_secret_by_id(self, secret_id: int, value: str) -> Secret:
        """Write `value` as a new version of secret `secret_id`, via
        PUT /api/v1/secrets/{id}, and return its metadata (never the value).
        Earlier versions are kept; a read returns the new value. `value` must
        not be empty (the server ignores an empty value, so nothing would be
        written).

        Raises:
            AuthError: 401
            ForbiddenError: 403 -- the token cannot write this secret
            NotFoundError: 404 -- no such live secret (a soft-deleted one included)
            KeyorixError: any other error; a 409 under heavy write contention
                on the same secret is a plain KeyorixError: retry. The value is
                never included in an error's message, and any echo of it is
                stripped from response_body.
        """
        if not isinstance(value, str) or value == "":
            raise KeyorixError("update_secret value must be a non-empty string")
        body, _ = self._write("PUT", f"/api/v1/secrets/{_secret_id(secret_id)}", {"value": value}, (200,))
        return Secret._from_dict(json.loads(body).get("data", {}))

    def delete_secret(
        self, project: Union[str, int], environment: Union[str, int], name: str
    ) -> Optional[str]:
        """Soft-delete the secret named `name` within project+environment. The
        name is resolved as for get_secret_scoped. See delete_secret_by_id.

        Raises:
            SecretNotFoundError: If no secret in scope has this name
            AmbiguousSecretError: If more than one secret in scope has this name
        """
        return self.delete_secret_by_id(self._find_secret_id(name, project, environment))

    def delete_secret_by_id(self, secret_id: int) -> Optional[str]:
        """Soft-delete secret `secret_id`, via DELETE /api/v1/secrets/{id}. The
        secret stops being readable at once but is restorable until the
        returned purge date (RFC 3339 UTC; list_deleted_secrets lists it with
        the same date). None only if the server did not send one; the delete
        itself still succeeded.

        Raises:
            AuthError: 401
            ForbiddenError: 403
            NotFoundError: 404 -- no such live secret, so deleting twice fails
                the second time
            KeyorixError: any other error. The server asks for no step-up or
                MFA for a delete.
        """
        _, headers = self._write("DELETE", f"/api/v1/secrets/{_secret_id(secret_id)}", None, (200, 204))
        return headers.get("Keyorix-Purge-At") or None

    def _write(self, method: str, path: str, payload: Optional[dict], ok: tuple):
        """Send a write request (JSON body when `payload` is given) and return
        (response body, response headers); raise the typed error for any
        status not in `ok`. A string "value" in `payload` is stripped from the
        error's response_body, so a server that echoes request content cannot
        put the secret there."""
        headers = {"Authorization": f"Bearer {self._token}"}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self._base}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl_context) as resp:
                if resp.status not in ok:
                    raise _error_for_response(resp.status, _redact_value(resp.read().decode(errors="replace"), payload))
                return resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            body = _redact_value(e.read().decode(errors="replace"), payload)
            e.close()
            raise _error_for_response(e.code, body) from e
        except urllib.error.URLError as e:
            raise KeyorixError(f"Request failed: {e.reason}") from e
        except TimeoutError as e:
            raise KeyorixError(f"Request timed out: {e}") from e

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
            with urllib.request.urlopen(req, timeout=self._timeout, context=self._ssl_context) as resp:
                data = json.loads(resp.read())
                return Project._from_dict(data.get("data", {}))
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise _error_for_response(e.code, body) from e
        except urllib.error.URLError as e:
            raise KeyorixError(f"Request failed: {e.reason}") from e
        except TimeoutError as e:
            raise KeyorixError(f"Request timed out: {e}") from e

    def list_environments(self, project_id: int) -> List["Environment"]:
        """List all environments for a project.

        Args:
            project_id: ID of the project

        Returns:
            List of Environment objects
        """
        data = self._request("GET", f"/api/v1/projects/{project_id}/environments")
        return [Environment._from_dict(e) for e in data.get("data", {}).get("environments", [])]
