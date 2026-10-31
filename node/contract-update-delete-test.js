'use strict';

// Contract test for updateSecret / deleteSecret against a REAL, running
// keyorix-server (see contract-test.js for what these tests are for and how
// the server is started). Update writes a new version whose value is readable;
// delete is a soft delete (gone from a get, listed in the deleted listing with
// the purge date the delete returned).
//
// Skipped unless KEYORIX_CONTRACT_SERVER_URL is set.

const http = require('node:http');
const { Client, login, ForbiddenError, NotFoundError, SecretNotFoundError } = require('./keyorix');

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

// Raw JSON request (project/machine administration, secret creation and the
// version listing are not part of this SDK's public surface).
function raw(serverUrl, method, path, body, token) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const url = new URL(path, serverUrl);
    const mod = url.protocol === 'https:' ? require('node:https') : http;
    const headers = {};
    if (data !== undefined) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    if (token) headers.Authorization = `Bearer ${token}`;
    const req = mod.request(url, { method, headers }, (res) => {
      let out = '';
      res.on('data', (chunk) => (out += chunk));
      res.on('end', () => resolve({ statusCode: res.statusCode, body: out }));
    });
    req.on('error', reject);
    if (data !== undefined) req.write(data);
    req.end();
  });
}

async function ok(promise, what) {
  const resp = await promise;
  if (resp.statusCode >= 300) throw new Error(`${what}: unexpected status ${resp.statusCode}: ${resp.body}`);
  return JSON.parse(resp.body || '{}');
}

async function versionNumbers(serverUrl, token, id) {
  const out = await ok(raw(serverUrl, 'GET', `/api/v1/secrets/${id}/versions`, undefined, token), 'GET versions');
  return (out.data.versions || []).map((v) => v.VersionNumber);
}

async function runContractTests() {
  const serverUrl = process.env.KEYORIX_CONTRACT_SERVER_URL;
  if (!serverUrl) {
    console.log('KEYORIX_CONTRACT_SERVER_URL not set -- skipping contract test (needs a real keyorix-server)');
    return;
  }
  const bootstrapToken = process.env.KEYORIX_CONTRACT_BOOTSTRAP_TOKEN;
  if (!bootstrapToken) {
    throw new Error('KEYORIX_CONTRACT_BOOTSTRAP_TOKEN must be set alongside KEYORIX_CONTRACT_SERVER_URL');
  }

  console.log('Update/delete contract test (real keyorix-server)');
  console.log('=================================================');

  await ok(raw(serverUrl, 'POST', '/system/init', {
    username: 'contract-admin',
    email: 'contract-admin@example.com',
    password: 'ContractTestPassw0rd!',
    bootstrap_token: bootstrapToken,
  }), 'POST /system/init');
  const token = await login(serverUrl, 'contract-admin', 'ContractTestPassw0rd!');
  const client = new Client(serverUrl, token);

  const project = (await client.listProjects()).find((p) => p.name === 'default');
  if (!project) throw new Error('default project not found');
  const env = (await client.listEnvironments(project.id)).find((e) => e.name === 'development');
  if (!env) throw new Error('development environment not found');

  const name = `contract-upd-del-${Date.now()}`;
  await ok(raw(serverUrl, 'POST', '/api/v1/secrets', {
    name, value: 'value-one', project_id: project.id, environment_id: env.id, type: 'generic',
  }, token), 'POST /api/v1/secrets');
  const id = (await client.listSecretsScoped(project.id, env.id)).find((s) => s.name === name)?.id;
  if (!id) throw new Error(`seeded secret ${name} not found`);
  assert((await versionNumbers(serverUrl, token, id)).length === 1, 'a fresh secret has exactly one version');

  // update: new version, new value readable
  const updated = await client.updateSecret(project.id, env.id, name, 'value-two');
  assert(updated.id === id && updated.name === name, 'updateSecret returns the secret metadata');
  assert((await client.getSecretScoped(name, project.id, env.id)) === 'value-two', 'the new value is readable after updateSecret');
  let versions = await versionNumbers(serverUrl, token, id);
  assert(versions.length === 2 && versions[0] === 2, `one update: two versions, newest numbered 2 (got ${JSON.stringify(versions)})`);

  await client.updateSecretById(id, 'value-three');
  assert((await client.getSecretScoped(name, project.id, env.id)) === 'value-three', 'the new value is readable after updateSecretById');
  versions = await versionNumbers(serverUrl, token, id);
  assert(versions.length === 3 && versions[0] === 3, `two updates: three versions, newest numbered 3 (got ${JSON.stringify(versions)})`);

  // 403: a zero-grant machine token may neither update nor delete
  const machine = await ok(raw(serverUrl, 'POST', `/api/v1/projects/${project.id}/machine-identities`,
    { name: `contract-test-machine-${Date.now()}`, identity_type: 'service' }, token), 'create machine identity');
  const machineToken = (await ok(raw(serverUrl, 'POST',
    `/api/v1/projects/${project.id}/machine-identities/${machine.data.machine_identity.id}/tokens`,
    { name: 'contract-test-machine-token' }, token), 'issue machine token')).data.token;
  const machineClient = new Client(serverUrl, machineToken);
  for (const [label, call] of [
    ['updateSecretById', () => machineClient.updateSecretById(id, 'attacker-value')],
    ['deleteSecretById', () => machineClient.deleteSecretById(id)],
  ]) {
    let err;
    try { await call(); } catch (e) { err = e; }
    assert(err instanceof ForbiddenError, `${label} with a zero-grant token is a ForbiddenError`);
  }
  assert((await client.getSecretScoped(name, project.id, env.id)) === 'value-three', 'the refused calls changed nothing');

  // delete: soft delete with a purge date
  const { purgeAt } = await client.deleteSecret(project.id, env.id, name);
  const days = (Date.parse(purgeAt) - Date.now()) / 86400000;
  assert(typeof purgeAt === 'string' && days > 29 && days < 31, `deleteSecret returns a purge date ~30 days out (got ${purgeAt})`);

  let err;
  try { await client.getSecretScoped(name, project.id, env.id); } catch (e) { err = e; }
  assert(err instanceof SecretNotFoundError, 'a deleted secret is gone from getSecretScoped');

  const listed = (await client.listDeletedSecrets(project.id)).find((s) => s.id === id);
  assert(listed !== undefined, 'a deleted secret is listed by listDeletedSecrets');
  assert(listed && Math.abs(Date.parse(listed.purgeAt) - Date.parse(purgeAt)) <= 2000, 'the listed purgeAt matches the one deleteSecret returned');

  // 404: a deleted secret can be neither updated nor deleted again
  for (const [label, call, Type] of [
    ['updateSecretById', () => client.updateSecretById(id, 'late'), NotFoundError],
    ['deleteSecretById', () => client.deleteSecretById(id), NotFoundError],
    ['updateSecret by name', () => client.updateSecret(project.id, env.id, name, 'late'), SecretNotFoundError],
    ['deleteSecret by name', () => client.deleteSecret(project.id, env.id, name), SecretNotFoundError],
  ]) {
    let e;
    try { await call(); } catch (x) { e = x; }
    assert(e instanceof Type, `${label} on a deleted secret is a ${Type.name}`);
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

runContractTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
