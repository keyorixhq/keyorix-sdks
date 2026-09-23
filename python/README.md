# Python SDK

Python client for Keyorix — lightweight on-premise secrets manager.

## Install

    pip install keyorix

Zero dependencies — stdlib only. Or just copy keyorix.py into your project.

## Quick start

    import keyorix

    token = keyorix.login("https://your-server:8443", "admin", "password")
    client = keyorix.Client("https://your-server:8443", token)

    db_password = client.get_secret("db-password", "production")

    secrets = client.list_secrets("production")
    for s in secrets:
        print(s.name, s.type)

## Environment variables pattern

    import os, keyorix
    client = keyorix.Client(os.environ["KEYORIX_SERVER"], os.environ["KEYORIX_TOKEN"])
    db_password = client.get_secret("db-password", "production")

## API

- keyorix.login(server_url, username, password) -> str
- keyorix.Client(server_url, token, timeout=30)
- client.get_secret(name, environment="") -> str — matches `environment` by name across
  every project you can read; use `get_secret_in_project` if the same environment name
  exists in more than one project
- client.list_secrets(environment="") -> list — same caveat as above; see
  `list_secrets_in_project` to scope to one specific project
- client.list_secrets_in_project(project_id, environment="") -> list — resolves
  `environment` to its numeric ID within `project_id` before querying
- client.get_secret_in_project(project_id, name, environment="") -> str
- client.list_projects() -> list
- client.list_environments(project_id) -> list
- client.health() -> bool

## Exceptions

- KeyorixError — base
- AuthError — authentication failure
- SecretNotFoundError — secret not found

## Requirements

Python 3.8+, zero external dependencies, Keyorix server v0.1.0+

## License

Apache-2.0 — see the [repository root LICENSE](../LICENSE)
