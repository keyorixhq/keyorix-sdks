'use strict';

/**
 * Keyorix Node.js SDK
 * Zero external dependencies — uses Node.js built-in https/http modules.
 *
 * Quick start:
 *
 *   const keyorix = require('keyorix');
 *
 *   const token = await keyorix.login('http://your-server:8080', 'admin', 'password');
 *   const client = new keyorix.Client('http://your-server:8080', token);
 *
 *   const dbPassword = await client.getSecret('db-password', 'production');
 *   const secrets = await client.listSecrets('production');
 */

const http = require('http');
const https = require('https');

// ── Errors ───────────────────────────────────────────────────────────────────

class KeyorixError extends Error {
  constructor(message) {
    super(message);
    this.name = 'KeyorixError';
  }
}

class AuthError extends KeyorixError {
  constructor(message) {
    super(message);
    this.name = 'AuthError';
  }
}

class SecretNotFoundError extends KeyorixError {
  constructor(message) {
    super(message);
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
    throw new AuthError(`Login failed (HTTP ${resp.status}): ${resp.body}`);
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
      throw new KeyorixError(`Server returned ${resp.status}: ${resp.body}`);
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

  /**
   * List secrets visible to the authenticated user.
   * @param {string} [environment] - Filter by environment name
   * @returns {Promise<Array>}
   */
  async listSecrets(environment = '') {
    let path = '/api/v1/secrets';
    if (environment) path += `?environment=${encodeURIComponent(environment)}`;
    const data = await this._request(path);
    return (data?.data?.secrets || []).map((s) => ({
      id: s.ID,
      name: s.Name,
      type: s.Type,
      environment: s.environment_name,
      namespace: s.namespace_name,
      createdAt: s.CreatedAt,
    }));
  }

  /**
   * Get the value of a secret by name.
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

  async _getSecretValue(secretId) {
    const data = await this._request(`/api/v1/secrets/${secretId}?include_value=true`);
    return data?.data?.value || '';
  }
}

module.exports = { Client, login, KeyorixError, AuthError, SecretNotFoundError };
