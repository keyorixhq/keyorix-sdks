'use strict';

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
