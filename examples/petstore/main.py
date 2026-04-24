"""
Keyorix Pet Store — Python example application

Demonstrates fetching database credentials from Keyorix at startup.
Zero hardcoded credentials — all secrets come from Keyorix.

Run with:
    docker compose up

Or manually:
    KEYORIX_SERVER=http://localhost:8080 \
    KEYORIX_TOKEN=your-token \
    python main.py
"""

import json
import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
import keyorix

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("ERROR: psycopg2 is required. Run: pip install psycopg2-binary")
    sys.exit(1)

db_conn = None


def get_db():
    return db_conn


class PetStoreHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default logging

    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        if path == '/health':
            self.send_json(200, {'status': 'ok'})

        elif path == '/pets':
            with get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute('SELECT id, name, species, created_at::text FROM pets ORDER BY id')
                pets = [dict(row) for row in cur.fetchall()]
            self.send_json(200, pets)

        elif path.startswith('/pets/'):
            try:
                pet_id = int(path.split('/')[-1])
            except ValueError:
                self.send_json(400, {'error': 'invalid id'})
                return
            with get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute('SELECT id, name, species, created_at::text FROM pets WHERE id = %s', (pet_id,))
                row = cur.fetchone()
            if row is None:
                self.send_json(404, {'error': 'pet not found'})
            else:
                self.send_json(200, dict(row))
        else:
            self.send_json(404, {'error': 'not found'})

    def do_POST(self):
        if self.path.rstrip('/') != '/pets':
            self.send_json(404, {'error': 'not found'})
            return

        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length))
        name = body.get('name', '').strip()
        species = body.get('species', '').strip()

        if not name or not species:
            self.send_json(400, {'error': 'name and species are required'})
            return

        with get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                'INSERT INTO pets (name, species) VALUES (%s, %s) RETURNING id, name, species, created_at::text',
                (name, species)
            )
            pet = dict(cur.fetchone())
            get_db().commit()

        self.send_json(201, pet)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        if not path.startswith('/pets/'):
            self.send_json(404, {'error': 'not found'})
            return
        try:
            pet_id = int(path.split('/')[-1])
        except ValueError:
            self.send_json(400, {'error': 'invalid id'})
            return

        with get_db().cursor() as cur:
            cur.execute('DELETE FROM pets WHERE id = %s', (pet_id,))
            deleted = cur.rowcount
            get_db().commit()

        if deleted == 0:
            self.send_json(404, {'error': 'pet not found'})
        else:
            self.send_response(204)
            self.end_headers()


def main():
    global db_conn

    # ── 1. Connect to Keyorix ────────────────────────────────────────────────
    server = os.environ.get('KEYORIX_SERVER')
    token = os.environ.get('KEYORIX_TOKEN')

    if not server:
        print('ERROR: KEYORIX_SERVER is required')
        sys.exit(1)
    if not token:
        print('ERROR: KEYORIX_TOKEN is required')
        sys.exit(1)

    print(f'🔐 Connecting to Keyorix at {server}')
    client = keyorix.Client(server, token)
    client.health()
    print('✅ Keyorix connection OK')

    print('🔑 Fetching database credentials from Keyorix...')
    db_password = client.get_secret('petstore-db-password', 'production')
    print('✅ Database credentials retrieved')

    # ── 2. Connect to PostgreSQL ─────────────────────────────────────────────
    db_host = os.environ.get('DB_HOST', 'localhost')
    db_port = os.environ.get('DB_PORT', '5432')
    db_user = os.environ.get('DB_USER', 'petstore')
    db_name = os.environ.get('DB_NAME', 'petstore')

    print(f'🐘 Connecting to PostgreSQL at {db_host}:{db_port}/{db_name}')
    for i in range(10):
        try:
            db_conn = psycopg2.connect(
                host=db_host, port=db_port,
                user=db_user, password=db_password, dbname=db_name
            )
            break
        except Exception as e:
            print(f'⏳ Waiting for database... ({i+1}/10)')
            time.sleep(2)
    else:
        print('ERROR: Database not ready')
        sys.exit(1)
    print('✅ Database connection OK')

    # ── 3. Create table ──────────────────────────────────────────────────────
    with db_conn.cursor() as cur:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS pets (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                species TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        ''')
        db_conn.commit()

    # ── 4. Start server ──────────────────────────────────────────────────────
    port = int(os.environ.get('PORT', 3002))
    print(f'🚀 Pet Store API listening on http://localhost:{port}')
    print(f'   Try: curl http://localhost:{port}/pets')
    HTTPServer(('', port), PetStoreHandler).serve_forever()


if __name__ == '__main__':
    main()
