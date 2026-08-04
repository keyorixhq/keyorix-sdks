# Keyorix Pet Store (Node.js)

Node.js example app demonstrating keyorix-node SDK in production.
Fetches DB password from Keyorix at startup. Zero hardcoded credentials.

## Quick start

    export KEYORIX_SERVER=http://host.docker.internal:8080
    export KEYORIX_TOKEN=your-token
    docker compose up
    curl http://localhost:3003/pets
    curl -X POST http://localhost:3003/pets \
      -H "Content-Type: application/json" \
      -d '{"name": "Luna", "species": "cat"}'

## API

GET    /pets         List all pets
POST   /pets         Create a pet
GET    /pets/:id     Get a pet
DELETE /pets/:id     Delete a pet
GET    /health       Health check
