# Keyorix Pet Store

A minimal REST API demonstrating how to fetch database credentials from Keyorix at startup. Zero hardcoded passwords.

## What this shows

App starts → connects to Keyorix → fetches "petstore-db-password" secret → connects to PostgreSQL → serves /pets API

The app has no password in its config, environment files, or source code.

## Prerequisites

1. Keyorix server running
2. Create the secret:

```bash
keyorix connect http://localhost:8080 --username admin --password Admin123!
keyorix secret create petstore-db-password --value changeme --env production
```

## Quick start

```bash
export KEYORIX_SERVER=http://host.docker.internal:8080
export KEYORIX_TOKEN=your-token-here
docker compose up
curl http://localhost:3001/pets
curl -X POST http://localhost:3001/pets \
  -H "Content-Type: application/json" \
  -d '{"name": "Luna", "species": "cat"}'
```

## API

| Method | Path | Description |
|---|---|---|
| GET | /pets | List all pets |
| POST | /pets | Create a pet |
| GET | /pets/:id | Get a pet by ID |
| DELETE | /pets/:id | Delete a pet |
| GET | /health | Health check |

## Demo script

1. Show main.go — no password anywhere
2. docker compose up — logs show Keyorix fetching credentials
3. curl /pets — API works
4. Open Keyorix dashboard Audit Log — shows secret access event
