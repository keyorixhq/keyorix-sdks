'use strict';

const http = require('node:http');
const { Client, login, KeyorixError, AuthError, SecretNotFoundError } = require('./keyorix');

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

async function runTests() {
  console.log('Unit tests');
  console.log('==========');

  // Error hierarchy
  assert(new AuthError('x') instanceof KeyorixError, 'AuthError extends KeyorixError');
  assert(new SecretNotFoundError('x') instanceof KeyorixError, 'SecretNotFoundError extends KeyorixError');
  assert(new AuthError('x').name === 'AuthError', 'AuthError.name correct');
  assert(new SecretNotFoundError('x').name === 'SecretNotFoundError', 'SecretNotFoundError.name correct');

  // Client construction
  const client = new Client('http://localhost:8080/', 'test-token');
  assert(client._base === 'http://localhost:8080', 'Client strips trailing slash');
  assert(client._token === 'test-token', 'Client stores token');
  assert(client._timeout === 30000, 'Client default timeout 30s');

  const clientCustom = new Client('http://localhost:8080', 'tok', { timeout: 5000 });
  assert(clientCustom._timeout === 5000, 'Client custom timeout');

  // Server URL scheme restriction
  assert((() => { new Client('https://example.com:8443', 'tok'); return true; })(), 'Client allows https://');
  assert((() => { new Client('http://localhost:8080', 'tok'); return true; })(), 'Client allows http:// localhost');
  assert((() => { new Client('http://127.0.0.1:8080', 'tok'); return true; })(), 'Client allows http:// 127.0.0.1');
  assert((() => { new Client('http://[::1]:8080', 'tok'); return true; })(), 'Client allows http:// ::1');
  assert((() => {
    try { new Client('http://example.com:8080', 'tok'); return false; }
    catch (e) { return e instanceof KeyorixError; }
  })(), 'Client rejects non-loopback http://');
  assert((() => {
    try { new Client('file:///etc/passwd', 'tok'); return false; }
    catch (e) { return e instanceof KeyorixError; }
  })(), 'Client rejects file:// scheme');
  assert(await (async () => {
    try { await login('http://example.com:8080', 'user', 'pass'); return false; }
    catch (e) { return e instanceof KeyorixError; }
  })(), 'login rejects non-loopback http://');

  // Error redaction: server error body must not leak into err.message
  const raw = 'internal: secret_key=super-sensitive-detail';
  const fakeServer = http.createServer((req, res) => {
    res.writeHead(500);
    res.end(raw);
  });
  await new Promise((resolve) => fakeServer.listen(0, resolve));
  try {
    const port = fakeServer.address().port;
    const badClient = new Client(`http://localhost:${port}`, 'tok');
    try {
      await badClient.listSecrets();
      assert(false, 'listSecrets should have thrown');
    } catch (e) {
      assert(e instanceof KeyorixError, 'listSecrets throws KeyorixError on 500');
      assert(!e.message.includes(raw), 'err.message does not leak the raw response body');
      assert(e.responseBody === raw, 'err.responseBody carries the raw response body');
      assert(e.statusCode === 500, 'err.statusCode carries the HTTP status');
    }
  } finally {
    fakeServer.close();
  }

  // keyorix-sdks#35: listSecrets must never send the rejected `environment`
  // name query parameter (keyorix#2013 -- the server now returns 400 for
  // it), and must instead filter the (unscoped) response client-side by the
  // environment_name field every secret already carries.
  {
    const envFilterServer = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://localhost');
      if (url.searchParams.get('environment')) {
        res.writeHead(400);
        res.end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        data: {
          secrets: [
            { ID: 1, Name: 'db-pass', Type: 'password', ProjectID: 1, environment_name: 'production', CreatedAt: '2026-01-01T00:00:00Z' },
            { ID: 2, Name: 'api-key', Type: 'generic', ProjectID: 1, environment_name: 'staging', CreatedAt: '2026-01-01T00:00:00Z' },
          ],
        },
      }));
    });
    await new Promise((resolve) => envFilterServer.listen(0, resolve));
    try {
      const port = envFilterServer.address().port;
      const c = new Client(`http://localhost:${port}`, 'tok');
      const prod = await c.listSecrets('production');
      assert(prod.length === 1 && prod[0].name === 'db-pass', 'listSecrets filters client-side by environment name');
      const all = await c.listSecrets();
      assert(all.length === 2, 'listSecrets() with no environment returns everything');
    } finally {
      envFilterServer.close();
    }
  }

  // listSecretsInProject/getSecretInProject: resolve environment name to its
  // numeric ID within the given project and send project_id+environment_id
  // -- the filters the server actually honors -- not the rejected name param.
  {
    const gotQueries = [];
    const inProjectServer = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/api/v1/projects/1/environments') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: { environments: [{ ID: 7, ProjectID: 1, Name: 'production' }] } }));
        return;
      }
      if (url.pathname === '/api/v1/secrets') {
        gotQueries.push(url.search);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          data: { secrets: [{ ID: 42, Name: 'db-pass', Type: 'password', ProjectID: 1, environment_name: 'production', CreatedAt: '2026-01-01T00:00:00Z' }] },
        }));
        return;
      }
      if (url.pathname === '/api/v1/secrets/42') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: { value: 's3cr3t' } }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise((resolve) => inProjectServer.listen(0, resolve));
    try {
      const port = inProjectServer.address().port;
      const c = new Client(`http://localhost:${port}`, 'tok');

      const secrets = await c.listSecretsInProject(1, 'production');
      assert(secrets.length === 1 && secrets[0].name === 'db-pass', 'listSecretsInProject returns the scoped secret');
      assert(gotQueries.length === 1, 'listSecretsInProject makes exactly one /api/v1/secrets request');
      assert(gotQueries[0].includes('project_id=1'), 'listSecretsInProject sends project_id');
      assert(gotQueries[0].includes('environment_id=7'), 'listSecretsInProject resolves environment name to its numeric ID');
      assert(!gotQueries[0].includes('environment=production'), 'listSecretsInProject never sends the rejected bare environment name filter');

      const value = await c.getSecretInProject(1, 'db-pass', 'production');
      assert(value === 's3cr3t', 'getSecretInProject returns the resolved secret value');

      try {
        await c.listSecretsInProject(1, 'nonexistent-env');
        assert(false, 'listSecretsInProject should have thrown for an unknown environment name');
      } catch (e) {
        assert(e instanceof KeyorixError, 'listSecretsInProject throws KeyorixError for an unknown environment name');
      }
    } finally {
      inProjectServer.close();
    }
  }

  // Integration tests (only if server is available)
  if (process.env.KEYORIX_SERVER) {
    console.log('\nIntegration tests');
    console.log('=================');
    const server = process.env.KEYORIX_SERVER;

    try {
      const token = await login(server, 'admin', 'Admin123!');
      assert(token.length > 0, `Login OK — token: ${token.slice(0, 8)}...`);

      const c = new Client(server, token);

      const healthy = await c.health();
      assert(healthy === true, 'Health OK');

      const secrets = await c.listSecrets('production');
      assert(Array.isArray(secrets), `ListSecrets OK — ${secrets.length} secrets`);
      secrets.forEach(s => console.log(`    - ${s.name} (${s.type})`));

      const val = await c.getSecret('petstore-db-password', 'production');
      assert(val === 'changeme', `GetSecret OK — petstore-db-password: ${val}`);

      try {
        await c.getSecret('nonexistent-secret', 'production');
        assert(false, 'Should have thrown SecretNotFoundError');
      } catch (e) {
        assert(e instanceof SecretNotFoundError, `SecretNotFoundError thrown correctly`);
      }
    } catch (err) {
      console.log(`  ❌ Integration test failed: ${err.message}`);
      failed++;
    }
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
