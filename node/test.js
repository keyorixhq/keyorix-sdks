'use strict';

const http = require('node:http');
const {
  Client,
  login,
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
      await badClient.listSecretsScoped('proj', 'prod');
      assert(false, 'listSecretsScoped should have thrown');
    } catch (e) {
      assert(e instanceof KeyorixError, 'listSecretsScoped throws KeyorixError on 500');
      assert(!e.message.includes(raw), 'err.message does not leak the raw response body');
      assert(e.responseBody === raw, 'err.responseBody carries the raw response body');
      assert(e.statusCode === 500, 'err.statusCode carries the HTTP status');
    }
  } finally {
    fakeServer.close();
  }

  // Typed error mapping: every request path returns a typed error that
  // `instanceof` can distinguish for the three statuses callers most need
  // to branch on, not just one generic KeyorixError.
  for (const [status, ErrorClass, label] of [
    [401, AuthError, 'AuthError'],
    [403, ForbiddenError, 'ForbiddenError'],
    [404, NotFoundError, 'NotFoundError'],
  ]) {
    const statusServer = http.createServer((req, res) => {
      res.writeHead(status);
      res.end();
    });
    await new Promise((resolve) => statusServer.listen(0, resolve));
    try {
      const port = statusServer.address().port;
      const badClient = new Client(`http://localhost:${port}`, 'tok');
      try {
        await badClient.listProjects();
        assert(false, `listProjects should have thrown on ${status}`);
      } catch (e) {
        assert(e instanceof ErrorClass, `HTTP ${status} maps to ${label}`);
        assert(e.statusCode === status, `${label}.statusCode carries ${status}`);
      }
    } finally {
      statusServer.close();
    }
  }

  // Deprecated environment-only methods: removed in v0.3.0, must never hit the network.
  {
    let called = false;
    const srv = http.createServer(() => { called = true; });
    await new Promise((resolve) => srv.listen(0, resolve));
    try {
      const port = srv.address().port;
      const c = new Client(`http://localhost:${port}`, 'tok');
      try {
        await c.listSecrets('production');
        assert(false, 'listSecrets should have thrown');
      } catch (e) {
        assert(e instanceof KeyorixError, 'listSecrets(deprecated) throws KeyorixError');
        assert(e.message.includes('listSecretsScoped'), 'listSecrets(deprecated) points at listSecretsScoped');
      }
      try {
        await c.getSecret('db-password', 'production');
        assert(false, 'getSecret should have thrown');
      } catch (e) {
        assert(e instanceof KeyorixError, 'getSecret(deprecated) throws KeyorixError');
        assert(e.message.includes('getSecretScoped'), 'getSecret(deprecated) points at getSecretScoped');
      }
      assert(!called, 'deprecated listSecrets/getSecret must not contact the server');
    } finally {
      srv.close();
    }
  }

  // Scoped list/get test matrix: two projects, each with its own "prod"
  // environment (names aren't unique across projects) and its own
  // "db-password" secret.
  {
    const routes = {
      '/api/v1/projects': { projects: [{ id: 10, name: 'proj-a' }, { id: 20, name: 'proj-b' }] },
      '/api/v1/projects/10/environments': { environments: [{ id: 101, name: 'prod', project_id: 10 }] },
      '/api/v1/projects/20/environments': { environments: [{ id: 201, name: 'prod', project_id: 20 }] },
      '/api/v1/secrets/1': { value: 'secret-a' },
      '/api/v1/secrets/2': { value: 'secret-b' },
    };
    const scopedSrv = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/api/v1/secrets') {
        const pid = url.searchParams.get('project_id');
        const eid = url.searchParams.get('environment_id');
        let secrets = [];
        if (pid === '10' && eid === '101') secrets = [{ id: 1, name: 'db-password' }];
        if (pid === '20' && eid === '201') {
          secrets = [
            { id: 2, name: 'db-password' },
            { id: 3, name: 'ambiguous-secret' },
            { id: 4, name: 'ambiguous-secret' },
          ];
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: { secrets } }));
        return;
      }
      const route = routes[url.pathname];
      if (route) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data: route }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise((resolve) => scopedSrv.listen(0, resolve));
    try {
      const port = scopedSrv.address().port;
      const c = new Client(`http://localhost:${port}`, 'tok');

      const secretsA = await c.listSecretsScoped('proj-a', 'prod');
      assert(secretsA.length === 1 && secretsA[0].id === 1, 'listSecretsScoped(proj-a, prod) returns id 1');

      const secretsB = await c.listSecretsScoped('proj-b', 'prod');
      assert(secretsB.length === 3, 'listSecretsScoped(proj-b, prod) returns 3 secrets');

      const valA = await c.getSecretScoped('db-password', 'proj-a', 'prod');
      assert(valA === 'secret-a', "getSecretScoped resolves proj-a's own db-password");

      const valB = await c.getSecretScoped('db-password', 'proj-b', 'prod');
      assert(valB === 'secret-b', "getSecretScoped resolves proj-b's own db-password, not proj-a's");

      try {
        await c.getSecretScoped('does-not-exist', 'proj-a', 'prod');
        assert(false, 'expected SecretNotFoundError');
      } catch (e) {
        assert(e instanceof SecretNotFoundError, 'missing name throws SecretNotFoundError');
      }

      try {
        await c.getSecretScoped('ambiguous-secret', 'proj-b', 'prod');
        assert(false, 'expected AmbiguousSecretError');
      } catch (e) {
        assert(e instanceof AmbiguousSecretError, 'ambiguous name throws AmbiguousSecretError');
        assert(JSON.stringify(e.ids) === JSON.stringify([3, 4]), `ambiguous error lists both IDs, got ${JSON.stringify(e.ids)}`);
      }

      const byId = await c.listSecretsScoped(10, 101);
      assert(byId.length === 1 && byId[0].id === 1, 'listSecretsScoped by numeric IDs works');
    } finally {
      scopedSrv.close();
    }
  }

  // TLS with a private CA: proves the `ca` client option actually gets
  // verified against, not just plumbed through and ignored. Uses a
  // throwaway self-signed cert (openssl) as its own private CA. Skips
  // gracefully if openssl isn't on PATH (matches the "skip when absent,
  // real failure when present" convention used for the server-gated
  // integration tests below).
  {
    const { execFileSync } = require('node:child_process');
    const os = require('node:os');
    const path = require('node:path');
    const fs = require('node:fs');
    let opensslAvailable = true;
    try {
      execFileSync('openssl', ['version'], { stdio: 'ignore' });
    } catch {
      opensslAvailable = false;
    }

    if (!opensslAvailable) {
      console.log('  (skipped: openssl not on PATH) TLS with a private CA');
    } else {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keyorix-tls-test-'));
      const keyPath = path.join(dir, 'key.pem');
      const certPath = path.join(dir, 'cert.pem');
      execFileSync('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', keyPath, '-out', certPath,
        '-days', '1', '-subj', '/CN=localhost',
      ], { stdio: 'ignore' });
      const key = fs.readFileSync(keyPath);
      const cert = fs.readFileSync(certPath);

      const https = require('node:https');
      const tlsServer = https.createServer({ key, cert }, (req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'healthy' }));
      });
      await new Promise((resolve) => tlsServer.listen(0, resolve));
      const port = tlsServer.address().port;

      try {
        const untrusted = new Client(`https://localhost:${port}`, 'tok');
        try {
          await untrusted.health();
          assert(false, 'expected an untrusted self-signed cert to be rejected by default');
        } catch (e) {
          assert(
            /self.signed|unable to verify|certificate/i.test(e.message),
            `TLS verification stays on by default (rejected self-signed cert): ${e.message}`
          );
        }

        const trusted = new Client(`https://localhost:${port}`, 'tok', { ca: cert });
        const ok = await trusted.health();
        assert(ok === true, 'health() succeeds once the private CA is supplied via the ca option');
      } finally {
        tlsServer.close();
        fs.rmSync(dir, { recursive: true, force: true });
      }
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

      const project = process.env.KEYORIX_PROJECT || 'default';
      const secrets = await c.listSecretsScoped(project, 'production');
      assert(Array.isArray(secrets), `ListSecretsScoped OK — ${secrets.length} secrets`);
      secrets.forEach(s => console.log(`    - ${s.name} (${s.type})`));

      const val = await c.getSecretScoped('petstore-db-password', project, 'production');
      assert(val === 'changeme', `GetSecretScoped OK — petstore-db-password: ${val}`);

      try {
        await c.getSecretScoped('nonexistent-secret', project, 'production');
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
