'use strict';

// Contract test: exercises this SDK's public API against a REAL, running
// keyorix-server -- not a mock -- to prove the SDK's wire-format assumptions
// (property names read off parsed JSON, envelope shapes) still match the
// actual API on keyorixhq/keyorix's main branch. Every case here is green on
// main today (verified against a local keyorix-server built from main,
// 2026-09-25); its purpose is to go RED the moment a server-side change
// (e.g. a wire-format migration to snake_case for a type this SDK parses)
// lands without a matching SDK update.
//
// Distinct from test.js's own KEYORIX_SERVER-gated integration block: that
// one assumes a pre-seeded "petstore" example server (docker-compose,
// postgres, admin/Admin123!, a secret named petstore-db-password). This test
// is self-contained -- it bootstraps its own fresh admin account via
// /system/init -- so CI can run it against a bare `go run ./server` +
// SQLite, no Docker/Postgres fixture required (see .github/workflows/
// contract.yml). JavaScript's JSON.parse does no case-insensitive key
// matching (unlike Go's encoding/json), so this test is the most sensitive
// of the four SDKs' contract tests to an exact-casing wire-format change.
//
// Skipped unless KEYORIX_CONTRACT_SERVER_URL is set.

const http = require('node:http');
const { Client, login } = require('./keyorix');

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

function postJSON(serverUrl, path, body, token) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const url = new URL(path, serverUrl);
    const mod = url.protocol === 'https:' ? require('node:https') : http;
    const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) };
    if (token) headers.Authorization = `Bearer ${token}`;
    const req = mod.request(url, { method: 'POST', headers }, (res) => {
      let raw = '';
      res.on('data', (chunk) => (raw += chunk));
      res.on('end', () => resolve({ statusCode: res.statusCode, body: raw }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function seedAdminSession(serverUrl, bootstrapToken) {
  const initResp = await postJSON(serverUrl, '/system/init', {
    username: 'contract-admin',
    email: 'contract-admin@example.com',
    password: 'ContractTestPassw0rd!',
    bootstrap_token: bootstrapToken,
  });
  if (initResp.statusCode >= 300) {
    throw new Error(`POST /system/init: unexpected status ${initResp.statusCode}: ${initResp.body}`);
  }
  return login(serverUrl, 'contract-admin', 'ContractTestPassw0rd!');
}

async function seedSecret(serverUrl, token, projectId, environmentId, name, value) {
  const resp = await postJSON(
    serverUrl,
    '/api/v1/secrets',
    { name, value, project_id: projectId, environment_id: environmentId, type: 'generic' },
    token
  );
  if (resp.statusCode >= 300) {
    throw new Error(`POST /api/v1/secrets: unexpected status ${resp.statusCode}: ${resp.body}`);
  }
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

  console.log('Contract tests');
  console.log('==============');

  const token = await seedAdminSession(serverUrl, bootstrapToken);
  const client = new Client(serverUrl, token);

  assert(await client.health() === true, 'health()');

  const projects = await client.listProjects();
  const defaultProject = projects.find((p) => p.name === 'default');
  assert(defaultProject !== undefined, `listProjects() finds the bootstrap-seeded 'default' project`);

  const envs = await client.listEnvironments(defaultProject.id);
  const envNames = envs.map((e) => e.name).sort();
  assert(
    JSON.stringify(envNames) === JSON.stringify(['development', 'production', 'staging']),
    `listEnvironments() returns the three bootstrap-seeded environments — got ${envNames.join(', ')}`
  );
  const devEnv = envs.find((e) => e.name === 'development');
  assert(devEnv && devEnv.projectId === defaultProject.id, 'environment.projectId matches its parent project');

  const projectName = `contract-test-project-${Date.now()}`;
  const created = await client.createProject(projectName, 'created by the Node SDK contract test');
  assert(created.name === projectName, 'createProject() round-trips name');
  assert(created.description === 'created by the Node SDK contract test', 'createProject() round-trips description');
  assert(typeof created.id === 'number' && created.id > 0, 'createProject() returns a nonzero id');

  const secretName = `contract-test-secret-${Date.now()}`;
  const secretValue = 'contract-test-value-do-not-use';
  await seedSecret(serverUrl, token, defaultProject.id, devEnv.id, secretName, secretValue);

  const secrets = await client.listSecretsScoped(defaultProject.id, devEnv.id);
  const found = secrets.find((s) => s.name === secretName);
  assert(found !== undefined, `listSecretsScoped() finds the seeded secret ${secretName}`);
  assert(found && found.projectId === defaultProject.id, 'secret.projectId matches its parent project');

  const value = await client.getSecretScoped(secretName, defaultProject.id, devEnv.id);
  assert(value === secretValue, `getSecretScoped() round-trips the secret value — got ${JSON.stringify(value)}`);

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

runContractTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
