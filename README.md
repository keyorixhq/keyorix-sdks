# keyorix-py

Python client for Keyorix — lightweight on-premise secrets manager.

## Install

    pip install keyorix

Zero dependencies — stdlib only. Or just copy keyorix.py into your project.

## Quick start

    import keyorix

    token = keyorix.login("http://your-server:8080", "admin", "password")
    client = keyorix.Client("http://your-server:8080", token)

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
- client.get_secret(name, environment="") -> str
- client.list_secrets(environment="") -> list
- client.health() -> bool

## Exceptions

- KeyorixError — base
- AuthError — authentication failure
- SecretNotFoundError — secret not found

## Requirements

Python 3.8+, zero external dependencies, Keyorix server v0.1.0+

## License

AGPL-3.0
