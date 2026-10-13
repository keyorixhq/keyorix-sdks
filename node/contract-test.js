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
// is self-contained apart from the admin credential, which
// scripts/contract_bootstrap.py provides (see seedAdminSession) -- so CI can run it against a bare `go run ./server` +
// SQLite, no Docker/Postgres fixture required (see .github/workflows/
// contract.yml). JavaScript's JSON.parse does no case-insensitive key
// matching (unlike Go's encoding/json), so this test is the most sensitive
// of the four SDKs' contract tests to an exact-casing wire-format change.
//
// Skipped unless KEYORIX_CONTRACT_SERVER_URL is set.

const http = require('node:http');
const { Client, ForbiddenError } = require('./keyorix');

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

// The server enforces MFA by default (security.require_mfa, ADR-112), so a
// password-only login cannot authenticate: scripts/contract_bootstrap.py
// bootstraps the admin, enrols TOTP, completes the real MFA step and mints a
// PAT, exported as KEYORIX_CONTRACT_ADMIN_TOKEN. MFA is never turned off.
function seedAdminSession() {
  const token = process.env.KEYORIX_CONTRACT_ADMIN_TOKEN;
  if (!token) {
    throw new Error('KEYORIX_CONTRACT_ADMIN_TOKEN must be set alongside KEYORIX_CONTRACT_SERVER_URL (run scripts/contract_bootstrap.py)');
  }
  return token;
}

// Keeps MFA-by-default covered: a user with no token who logs in with only a
// password gets an MFA challenge, not a session. A challenge login keeps its
// rate-limit slot until the second factor completes (10 per 15 min per IP), so
// this makes exactly one login call, on the raw response, not also login().
async function checkPasswordLoginReturnsMFAChallenge(serverUrl) {
  const resp = await postJSON(serverUrl, '/auth/login', {
    username: 'contract-admin',
    password: 'ContractTestPassw0rd!',
  });
  const data = JSON.parse(resp.body)?.data ?? {};
  assert(resp.statusCode === 200 && data.mfa_required === true && Boolean(data.mfa_challenge),
    'password-only login returns an MFA challenge');
  assert(!data.token, 'password-only login returns no session token');
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

// Mints a personal access token for the caller identified by adminToken, via
// raw HTTP (PAT issuance is not part of this SDK's public surface).
async function createPAT(serverUrl, adminToken, name) {
  const resp = await postJSON(serverUrl, '/api/v1/auth/tokens', { name }, adminToken);
  if (resp.statusCode >= 300) {
    throw new Error(`POST /api/v1/auth/tokens: unexpected status ${resp.statusCode}: ${resp.body}`);
  }
  const token = JSON.parse(resp.body)?.data?.token;
  if (!token) throw new Error('create-PAT response had no token');
  return token;
}

// Creates a fresh machine identity in projectId and issues it a token, via
// raw HTTP (neither is part of this SDK's public surface). A brand-new
// machine identity holds no roles, so this token authenticates but is not
// authorized for anything yet -- exactly the shape needed to prove
// authentication succeeds independently of authorization.
async function createMachineToken(serverUrl, adminToken, projectId) {
  const idResp = await postJSON(
    serverUrl,
    `/api/v1/projects/${projectId}/machine-identities`,
    { name: `contract-test-machine-${Date.now()}`, identity_type: 'service' },
    adminToken
  );
  if (idResp.statusCode >= 300) {
    throw new Error(`POST machine-identities: unexpected status ${idResp.statusCode}: ${idResp.body}`);
  }
  const machineId = JSON.parse(idResp.body)?.data?.machine_identity?.id;
  if (!machineId) throw new Error('create-machine-identity response had no id');

  const tokResp = await postJSON(
    serverUrl,
    `/api/v1/projects/${projectId}/machine-identities/${machineId}/tokens`,
    { name: 'contract-test-machine-token' },
    adminToken
  );
  if (tokResp.statusCode >= 300) {
    throw new Error(`POST machine-identities tokens: unexpected status ${tokResp.statusCode}: ${tokResp.body}`);
  }
  const token = JSON.parse(tokResp.body)?.data?.token;
  if (!token) throw new Error('issue-machine-token response had no token');
  return token;
}

async function runContractTests() {
  const serverUrl = process.env.KEYORIX_CONTRACT_SERVER_URL;
  if (!serverUrl) {
    console.log('KEYORIX_CONTRACT_SERVER_URL not set -- skipping contract test (needs a real keyorix-server)');
    return;
  }
  console.log('Contract tests');
  console.log('==============');

  const token = seedAdminSession();
  const client = new Client(serverUrl, token);

  await checkPasswordLoginReturnsMFAChallenge(serverUrl);

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

  const pat = await createPAT(serverUrl, token, 'contract-test-pat');
  const patClient = new Client(serverUrl, pat);
  try {
    await patClient.listProjects();
    assert(true, 'Client works transparently with a PAT, not just a session token');
  } catch (e) {
    assert(false, `Client with a PAT: ${e.message} (expected success -- a PAT presents identically to a session token)`);
  }

  const machineToken = await createMachineToken(serverUrl, token, defaultProject.id);
  const machineClient = new Client(serverUrl, machineToken);
  // A brand-new machine identity holds no roles, so this must authenticate (not
  // AuthError) even though it can't yet be authorized for anything -- proving
  // the token is recognized as valid, distinct from being permitted. Current
  // keyorix main answers a role-less machine's project listing with an empty,
  // permission-filtered list; older servers answered 403 (ForbiddenError).
  // Either proves "authenticated but not authorized"; seeing projects, or an
  // AuthError, does not.
  try {
    const machineProjects = await machineClient.listProjects();
    assert(machineProjects.length === 0, `Client works transparently with a machine identity token — got ${machineProjects.length} projects, want none (the identity holds no roles)`);
  } catch (e) {
    assert(e instanceof ForbiddenError, `Client works transparently with a machine identity token — got ${e.constructor.name}, want ForbiddenError`);
  }

  const slowServer = http.createServer((req, res) => {
    setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ data: { projects: [] } }));
    }, 200);
  });
  await new Promise((resolve) => slowServer.listen(0, resolve));
  try {
    const slowClient = new Client(`http://localhost:${slowServer.address().port}`, 'tok', { timeout: 10 });
    try {
      await slowClient.listProjects();
      assert(false, 'expected a timeout error from a 10ms client against a 200ms-slow server');
    } catch (e) {
      assert(true, `timeout is actually enforced against a slow server — ${e.message}`);
    }
  } finally {
    slowServer.close();
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

runContractTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
