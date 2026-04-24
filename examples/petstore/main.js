'use strict';

/**
 * Keyorix Pet Store — Node.js example application
 *
 * Demonstrates fetching database credentials from Keyorix at startup.
 * Zero hardcoded credentials — all secrets come from Keyorix.
 *
 * Run with:
 *   docker compose up
 *
 * Or manually:
 *   KEYORIX_SERVER=http://localhost:8080 \
 *   KEYORIX_TOKEN=your-token \
 *   node main.js
 */

const http = require('http');
const { Client } = require('keyorix');
const { Pool } = require('pg');

let pool;

// ── Router ───────────────────────────────────────────────────────────────────

async function handleRequest(req, res) {
  const url = new URL(req.url, `http://localhost`);
  const path = url.pathname.replace(/\/$/, '');

  try {
    if (req.method === 'GET' && path === '/health') {
      return json(res, 200, { status: 'ok' });
    }

    if (req.method === 'GET' && path === '/pets') {
      const { rows } = await pool.query('SELECT id, name, species, created_at FROM pets ORDER BY id');
      return json(res, 200, rows);
    }

    if (req.method === 'GET' && path.match(/^\/pets\/\d+$/)) {
      const id = parseInt(path.split('/')[2]);
      const { rows } = await pool.query('SELECT id, name, species, created_at FROM pets WHERE id = $1', [id]);
      if (rows.length === 0) return json(res, 404, { error: 'pet not found' });
      return json(res, 200, rows[0]);
    }

    if (req.method === 'POST' && path === '/pets') {
      const body = await readBody(req);
      const { name, species } = JSON.parse(body);
      if (!name || !species) return json(res, 400, { error: 'name and species are required' });
      const { rows } = await pool.query(
        'INSERT INTO pets (name, species) VALUES ($1, $2) RETURNING id, name, species, created_at',
        [name, species]
      );
      return json(res, 201, rows[0]);
    }

    if (req.method === 'DELETE' && path.match(/^\/pets\/\d+$/)) {
      const id = parseInt(path.split('/')[2]);
      const { rowCount } = await pool.query('DELETE FROM pets WHERE id = $1', [id]);
      if (rowCount === 0) return json(res, 404, { error: 'pet not found' });
      res.writeHead(204);
      return res.end();
    }

    json(res, 404, { error: 'not found' });
  } catch (err) {
    console.error(err);
    json(res, 500, { error: 'internal server error' });
  }
}

function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const server = process.env.KEYORIX_SERVER;
  const token = process.env.KEYORIX_TOKEN;

  if (!server) { console.error('ERROR: KEYORIX_SERVER is required'); process.exit(1); }
  if (!token)  { console.error('ERROR: KEYORIX_TOKEN is required');  process.exit(1); }

  // 1. Connect to Keyorix
  console.log(`🔐 Connecting to Keyorix at ${server}`);
  const client = new Client(server, token);
  await client.health();
  console.log('✅ Keyorix connection OK');

  console.log('🔑 Fetching database credentials from Keyorix...');
  const dbPassword = await client.getSecret('petstore-db-password', 'production');
  console.log('✅ Database credentials retrieved');

  // 2. Connect to PostgreSQL
  const dbHost = process.env.DB_HOST || 'localhost';
  const dbPort = process.env.DB_PORT || '5432';
  const dbUser = process.env.DB_USER || 'petstore';
  const dbName = process.env.DB_NAME || 'petstore';

  console.log(`🐘 Connecting to PostgreSQL at ${dbHost}:${dbPort}/${dbName}`);
  pool = new Pool({ host: dbHost, port: dbPort, user: dbUser, password: dbPassword, database: dbName });

  for (let i = 0; i < 10; i++) {
    try { await pool.query('SELECT 1'); break; }
    catch { console.log(`⏳ Waiting for database... (${i+1}/10)`); await new Promise(r => setTimeout(r, 2000)); }
  }
  console.log('✅ Database connection OK');

  // 3. Create table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pets (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      species TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // 4. Start server
  const port = process.env.PORT || 3003;
  http.createServer(handleRequest).listen(port, () => {
    console.log(`🚀 Pet Store API listening on http://localhost:${port}`);
    console.log(`   Try: curl http://localhost:${port}/pets`);
  });
}

main().catch(err => { console.error(err); process.exit(1); });
