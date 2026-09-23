'use strict';

/**
 * Keyorix Node.js SDK
 * Zero external dependencies — uses Node.js built-in https/http modules.
 *
 * Quick start:
 *
 *   const keyorix = require('@keyorixhq/sdk');
 *
 *   const token = await keyorix.login('https://your-server:8443', 'admin', 'password');
 *   const client = new keyorix.Client('https://your-server:8443', token);
 *
 *   const dbPassword = await client.getSecret('db-password', 'production');
 *   const secrets = await client.listSecrets('production');
 */

const http = require('node:http');
const https = require('node:https');

// ── Errors ───────────────────────────────────────────────────────────────────

// KeyorixError's message deliberately omits the raw response body: it's
// server-controlled content that this SDK's own README quick-start passes
// straight to console.error, and an unconditional relay into that path is
// exactly how untrusted content ends up verbatim in application logs.
// Callers who need the body for their own (redacted) logging can read the
// responseBody property directly.
class KeyorixError extends Error {
  constructor(message, { statusCode, responseBody } = {}) {
    super(message);
    this.name = 'KeyorixError';
    this.statusCode = statusCode;
    this.responseBody = responseBody;
  }
}

class AuthError extends KeyorixError {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'AuthError';
  }
}

class SecretNotFoundError extends KeyorixError {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'SecretNotFoundError';
  }
}

// ── HTTP helper ──────────────────────────────────────────────────────────────

function request(options, body) {
  return new Promise((resolve, reject) => {
    const transport = options.protocol === 'https:' ? https : http;
    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        resolve({ status: res.statusCode, body: raw });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function parseUrl(serverUrl) {
  const u = new URL(serverUrl);
  return {
    protocol: u.protocol,
    hostname: u.hostname,
    port: u.port || (u.protocol === 'https:' ? 443 : 80),
  };
}

function isLoopbackHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

// Rejects any scheme but https; allows http only for localhost/loopback. A
// bearer token and every secret value would otherwise be sent/received in
// cleartext, and an unrestricted scheme (e.g. file://) would let a
// caller-influenced serverUrl reach something other than an HTTP server
// entirely.
function validateServerUrl(serverUrl) {
  let u;
  try {
    u = new URL(serverUrl);
  } catch (err) {
    throw new KeyorixError(`Invalid server URL '${serverUrl}': ${err.message}`);
  }
  if (u.protocol === 'https:') return;
  if (u.protocol === 'http:' && isLoopbackHost(u.hostname)) return;
  throw new KeyorixError(
    `Server URL '${serverUrl}' must use https:// (http:// is only allowed for localhost/loopback)`
  );
}

// ── login ────────────────────────────────────────────────────────────────────

/**
 * Authenticate with Keyorix and return a session token.
 *
 * @param {string} serverUrl - Base URL of your Keyorix server
 * @param {string} username
 * @param {string} password
 * @param {number} [timeout=30000] - Timeout in milliseconds
 * @returns {Promise<string>} Session token
 */
async function login(serverUrl, username, password, timeout = 30000) {
  validateServerUrl(serverUrl);
  const base = parseUrl(serverUrl);
  const body = JSON.stringify({ username, password });

  const options = {
    ...base,
    path: '/auth/login',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
    timeout,
  };

  let resp;
  try {
    resp = await request(options, body);
  } catch (err) {
    throw new KeyorixError(`Server unreachable: ${err.message}`);
  }

  if (resp.status !== 200) {
    throw new AuthError(`Login failed (HTTP ${resp.status})`, { statusCode: resp.status, responseBody: resp.body });
  }

  const data = JSON.parse(resp.body);
  const token = data?.data?.token;
  if (!token) throw new AuthError('No token in login response');
  return token;
}

// ── Client ───────────────────────────────────────────────────────────────────

class Client {
  /**
   * @param {string} serverUrl - Base URL of your Keyorix server
   * @param {string} token - Session token
   * @param {object} [opts]
   * @param {number} [opts.timeout=30000] - Timeout in milliseconds
   */
  constructor(serverUrl, token, opts = {}) {
    validateServerUrl(serverUrl);
    this._base = serverUrl.replace(/\/$/, '');
    this._token = token;
    this._timeout = opts.timeout || 30000;
    this._parsed = parseUrl(this._base);
  }

  async _request(path) {
    const options = {
      ...this._parsed,
      path,
      method: 'GET',
      headers: { Authorization: `Bearer ${this._token}` },
      timeout: this._timeout,
    };

    let resp;
    try {
      resp = await request(options);
    } catch (err) {
      throw new KeyorixError(`Request failed: ${err.message}`);
    }

    if (resp.status === 401) throw new AuthError('Unauthorized — check your token');
    if (resp.status !== 200) {
      throw new KeyorixError(`Server returned ${resp.status}`, { statusCode: resp.status, responseBody: resp.body });
    }

    return JSON.parse(resp.body);
  }

  /**
   * Check if the server is reachable and healthy.
   * @returns {Promise<boolean>}
   */
  async health() {
    const options = {
      ...this._parsed,
      path: '/health',
      method: 'GET',
      timeout: this._timeout,
    };
    try {
      const resp = await request(options);
      return resp.status === 200;
    } catch (err) {
      throw new KeyorixError(`Server unreachable: ${err.message}`);
    }
  }

  async _listSecretsRaw(query) {
    let path = '/api/v1/secrets';
    const qs = new URLSearchParams(query).toString();
    if (qs) path += `?${qs}`;
    const data = await this._request(path);
    return (data?.data?.secrets || []).map((s) => ({
      id: s.ID,
      name: s.Name,
      type: s.Type,
      projectId: s.ProjectID,
      environment: s.environment_name,
      createdAt: s.CreatedAt,
    }));
  }

  /**
   * List secrets visible to the authenticated user, filtered by environment
   * name across every project you can read.
   *
   * An environment name is only unique WITHIN a project, not globally -- if
   * two projects both have a "production" environment, this filters to
   * secrets in EITHER of them. Use listSecretsInProject to scope to one
   * specific project as well.
   *
   * The server only recognizes project_id/environment_id (numeric) as real
   * filters -- a bare `environment` name query parameter is rejected with
   * 400. This method filters by name CLIENT-SIDE, after fetching the
   * caller's full (unscoped) secret list, so the environment argument's
   * documented behavior actually works, instead of previously being
   * silently ignored server-side.
   *
   * @param {string} [environment] - Filter by environment name
   * @returns {Promise<Array>}
   */
  async listSecrets(environment = '') {
    const secrets = await this._listSecretsRaw({});
    if (!environment) return secrets;
    return secrets.filter((s) => s.environment === environment);
  }

  /**
   * Get the value of a secret by name. environment is matched by name
   * across every project you can read -- if the SAME environment name
   * exists in more than one project and both contain a same-named secret,
   * which one is returned is unspecified. Use getSecretInProject to
   * disambiguate.
   * @param {string} name - Secret name
   * @param {string} [environment] - Environment to search in
   * @returns {Promise<string>} Plaintext secret value
   */
  async getSecret(name, environment = '') {
    const secrets = await this.listSecrets(environment);
    const secret = secrets.find((s) => s.name === name);
    if (!secret) {
      const envMsg = environment ? ` in environment '${environment}'` : '';
      throw new SecretNotFoundError(`Secret '${name}' not found${envMsg}`);
    }
    return this._getSecretValue(secret.id);
  }

  /**
   * List secrets in a single project, optionally filtered to one
   * environment within it (by name). Unlike listSecrets, this resolves
   * environment to the numeric environment_id the server actually honors,
   * scoped by project_id -- so it never confuses a same-named
   * environment/secret in a different project the way name-only filtering
   * can.
   * @param {number} projectId
   * @param {string} [environment] - Environment name within that project
   * @returns {Promise<Array>}
   */
  async listSecretsInProject(projectId, environment = '') {
    const query = { project_id: String(projectId) };
    if (environment) {
      const envs = await this.listEnvironments(projectId);
      const env = envs.find((e) => e.name === environment);
      if (!env) {
        throw new KeyorixError(`environment '${environment}' not found in project ${projectId}`);
      }
      query.environment_id = String(env.id);
    }
    return this._listSecretsRaw(query);
  }

  /**
   * Get the value of a secret by name, scoped to one project and
   * (optionally) one environment within it -- the disambiguated
   * counterpart to getSecret for deployments where the same environment
   * name (or secret name) recurs across projects.
   * @param {number} projectId
   * @param {string} name - Secret name
   * @param {string} [environment] - Environment name within that project
   * @returns {Promise<string>} Plaintext secret value
   */
  async getSecretInProject(projectId, name, environment = '') {
    const secrets = await this.listSecretsInProject(projectId, environment);
    const secret = secrets.find((s) => s.name === name);
    if (!secret) {
      const envMsg = environment ? `, environment '${environment}'` : '';
      throw new SecretNotFoundError(`Secret '${name}' not found in project ${projectId}${envMsg}`);
    }
    return this._getSecretValue(secret.id);
  }

  async _getSecretValue(secretId) {
    const data = await this._request(`/api/v1/secrets/${secretId}?include_value=true`);
    return data?.data?.value || '';
  }

  /**
   * List all projects.
   * @returns {Promise<Array>}
   */
  async listProjects() {
    const data = await this._request('/api/v1/projects');
    return (data?.data?.projects || []).map((p) => ({
      id: p.ID, name: p.Name, description: p.Description, createdAt: p.CreatedAt,
    }));
  }

  /**
   * Create a new project. Seeds development/staging/production environments.
   * @param {string} name
   * @param {string} [description]
   * @returns {Promise<object>} Created project
   */
  async createProject(name, description = '') {
    const body = JSON.stringify({ name, description });
    const options = {
      ...this._parsed,
      path: '/api/v1/projects',
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this._token}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: this._timeout,
    };
    let resp;
    try { resp = await request(options, body); } catch (err) {
      throw new KeyorixError(`Request failed: ${err.message}`);
    }
    if (resp.status !== 200 && resp.status !== 201) {
      throw new KeyorixError(`Server returned ${resp.status}`, { statusCode: resp.status, responseBody: resp.body });
    }
    const p = JSON.parse(resp.body)?.data || {};
    return { id: p.ID, name: p.Name, description: p.Description, createdAt: p.CreatedAt };
  }

  /**
   * List environments for a project.
   * @param {number} projectId
   * @returns {Promise<Array>}
   */
  async listEnvironments(projectId) {
    const data = await this._request(`/api/v1/projects/${projectId}/environments`);
    return (data?.data?.environments || []).map((e) => ({
      id: e.ID, projectId: e.ProjectID, name: e.Name,
    }));
  }
}

module.exports = { Client, login, KeyorixError, AuthError, SecretNotFoundError };
