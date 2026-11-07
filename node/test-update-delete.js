'use strict';

// Unit tests for updateSecret / deleteSecret (and their ById primitives)
// against a local stub server: request shape, typed errors, and the rule that
// the secret value never appears in an error. The behaviour against a real
// server is in contract-update-delete-test.js.

const http = require('node:http');
const {
  Client,
  KeyorixError,
  AuthError,
  ForbiddenError,
  NotFoundError,
  SecretNotFoundError,
  AmbiguousSecretError,
} = require('./keyorix');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✅ ${message}`);
    passed++;
  } else {
    console.log(`  ❌ ${message}`);
    failed++;
  }
}

const VALUE = 's3cr3t-rotated-value';

// Starts a stub server; `handler(req, bodyString, res)` answers each request.
async function withServer(handler, fn) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      calls.push({ method: req.method, url: req.url, auth: req.headers.authorization, body: raw });
      handler(req, raw, res);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    await fn(new Client(`http://127.0.0.1:${server.address().port}`, 'tok'), calls);
  } finally {
    await new Promise((r) => server.close(r));
  }
}

async function rejection(promise) {
  try {
    await promise;
    return null;
  } catch (e) {
    return e;
  }
}

async function main() {
  console.log('Update/delete unit tests');
  console.log('========================');

  await withServer((req, _b, res) => {
    res.writeHead(200);
    res.end(JSON.stringify({ data: { id: 7, name: 'db', type: 'generic', project_id: 3, created_at: 't' } }));
  }, async (client, calls) => {
    const s = await client.updateSecretById(7, VALUE);
    assert(calls[0].method === 'PUT' && calls[0].url === '/api/v1/secrets/7', 'updateSecretById sends PUT /api/v1/secrets/7');
    assert(calls[0].auth === 'Bearer tok', 'updateSecretById sends the bearer token');
    assert(calls[0].body === JSON.stringify({ value: VALUE }), 'updateSecretById body is {value}');
    assert(s.id === 7 && s.name === 'db' && s.projectId === 3, 'updateSecretById returns metadata');
    assert(!JSON.stringify(s).includes(VALUE), 'returned metadata carries no value');
  });

  await withServer((_r, _b, res) => { res.writeHead(200); res.end('{}'); }, async (client, calls) => {
    for (const bad of ['', undefined, null, 42]) {
      const e = await rejection(client.updateSecretById(7, bad));
      assert(e instanceof KeyorixError, `updateSecretById(${JSON.stringify(bad)}) is refused`);
    }
    for (const id of [0, -1, 1.5, '7', '7/versions', NaN]) {
      const e = await rejection(client.deleteSecretById(id));
      assert(e instanceof KeyorixError, `deleteSecretById(${JSON.stringify(id)}) is refused`);
    }
    assert(calls.length === 0, 'refused calls never reach the server');
  });

  // Errors never carry the value, even if the server echoes it (raw and JSON-escaped).
  const tricky = `pa"ss${VALUE}`;
  for (const status of [400, 403, 404, 409, 500]) {
    await withServer((_r, _b, res) => {
      res.writeHead(status);
      res.end(JSON.stringify({ error: 'X', message: `bad value ${tricky}` }));
    }, async (client) => {
      const e = await rejection(client.updateSecretById(7, tricky));
      assert(e instanceof KeyorixError, `${status}: update throws a KeyorixError`);
      const everything = `${e.message} ${e.responseBody} ${JSON.stringify(e)} ${e.stack}`;
      assert(!everything.includes(VALUE), `${status}: value absent from message, responseBody, JSON and stack`);
    });
  }

  for (const [status, Type] of [[401, AuthError], [403, ForbiddenError], [404, NotFoundError]]) {
    await withServer((_r, _b, res) => { res.writeHead(status); res.end('{}'); }, async (client) => {
      assert((await rejection(client.updateSecretById(1, 'v'))) instanceof Type, `update ${status} is ${Type.name}`);
      assert((await rejection(client.deleteSecretById(1))) instanceof Type, `delete ${status} is ${Type.name}`);
    });
  }

  await withServer((_r, _b, res) => {
    res.writeHead(204, { 'Keyorix-Purge-At': '2026-11-30T14:56:16Z' });
    res.end();
  }, async (client, calls) => {
    const r = await client.deleteSecretById(9);
    assert(calls[0].method === 'DELETE' && calls[0].url === '/api/v1/secrets/9', 'deleteSecretById sends DELETE /api/v1/secrets/9');
    assert(calls[0].body === '', 'deleteSecretById sends no body');
    assert(r.purgeAt === '2026-11-30T14:56:16Z', 'deleteSecretById returns purgeAt from Keyorix-Purge-At');
  });

  await withServer((_r, _b, res) => { res.writeHead(204); res.end(); }, async (client) => {
    const r = await client.deleteSecretById(9);
    assert(r.purgeAt === null, 'no Keyorix-Purge-At header: purgeAt is null and the delete still succeeds');
  });

  await withServer((req, _b, res) => {
    if (req.method === 'GET' && req.url.startsWith('/api/v1/secrets?')) {
      res.writeHead(200);
      res.end(JSON.stringify({ data: { secrets: [{ id: 1, name: 'dup' }, { id: 2, name: 'dup' }, { id: 3, name: 'solo' }], total_pages: 1 } }));
    } else if (req.method === 'PUT') {
      res.writeHead(200);
      res.end(JSON.stringify({ data: { id: 3, name: 'solo' } }));
    } else {
      res.writeHead(204);
      res.end();
    }
  }, async (client, calls) => {
    const s = await client.updateSecret(1, 1, 'solo', 'v');
    assert(s.id === 3 && calls.some((c) => c.method === 'PUT' && c.url === '/api/v1/secrets/3'), 'updateSecret resolves the name to its id');
    await client.deleteSecret(1, 1, 'solo');
    assert(calls.some((c) => c.method === 'DELETE' && c.url === '/api/v1/secrets/3'), 'deleteSecret resolves the name to its id');
    assert((await rejection(client.updateSecret(1, 1, 'dup', 'v'))) instanceof AmbiguousSecretError, 'updateSecret refuses an ambiguous name');
    assert((await rejection(client.deleteSecret(1, 1, 'dup'))) instanceof AmbiguousSecretError, 'deleteSecret refuses an ambiguous name');
    assert((await rejection(client.updateSecret(1, 1, 'ghost', 'v'))) instanceof SecretNotFoundError, 'updateSecret on a missing name is SecretNotFoundError');
    assert(!calls.some((c) => (c.method === 'PUT' || c.method === 'DELETE') && /\/secrets\/[12]$/.test(c.url)), 'an ambiguous name never writes');
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
