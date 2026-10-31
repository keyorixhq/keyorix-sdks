'use strict';

/**
 * Keyorix Node.js SDK
 * Zero external dependencies — uses Node.js built-in https/http modules.
 *
 * Quick start, for a machine identity token (the recommended credential for
 * an unattended application -- see the README):
 *
 *   const keyorix = require('@keyorixhq/sdk');
 *
 *   const client = new keyorix.Client('https://your-server:8443', process.env.KEYORIX_TOKEN);
 *   const dbPassword = await client.getSecretIn('my-project', 'production', 'db-password');
 *
 * getSecretIn/getSecretByRef resolve and authorize in one round trip and
 * need no project/environment-list permission. getSecretScoped/
 * listSecretsScoped are the alternative when you already have (or want to
 * cache) project/environment IDs rather than names.
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
  constructor(message, { statusCode, responseBody, errorCode } = {}) {
    super(message);
    this.name = 'KeyorixError';
    this.statusCode = statusCode;
    this.responseBody = responseBody;
    // The server's stable error code (the error envelope's "error" field, e.g.
    // "SecretSuspended"), or undefined when the body carries none.
    this.errorCode = errorCode;
  }
}

class AuthError extends KeyorixError {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'AuthError';
  }
}

// Thrown by login() when the password was accepted but the account has a
// second factor, so the server answered with an MFA challenge instead of a
// session. Still an AuthError (login() used to throw a generic AuthError here),
// so existing `instanceof AuthError` handlers keep working. Complete the login
// with verifyMfa(serverUrl, err.challenge, code). `methods` lists the second
// factors the account has ('totp', 'webauthn'); this SDK completes only TOTP or
// recovery codes -- a passkey needs a browser ceremony.
class MFARequiredError extends AuthError {
  constructor({ challenge, totpAvailable, webauthnAvailable }) {
    super('Multi-factor authentication required — complete the login with verifyMfa()');
    this.name = 'MFARequiredError';
    this.challenge = challenge;
    this.totpAvailable = totpAvailable;
    this.webauthnAvailable = webauthnAvailable;
    this.methods = [totpAvailable && 'totp', webauthnAvailable && 'webauthn'].filter(Boolean);
  }
}

// Thrown when the server rejects a request as unauthorized for this
// token's permissions (HTTP 403).
class ForbiddenError extends KeyorixError {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'ForbiddenError';
  }
}

// Thrown when a requested resource does not exist on the server (HTTP
// 404). Distinct from SecretNotFoundError, which is thrown by name-based
// resolution before any such request is made.
class NotFoundError extends KeyorixError {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'NotFoundError';
  }
}

class SecretNotFoundError extends KeyorixError {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'SecretNotFoundError';
  }
}

// Thrown by getSecretScoped when a name matches more than one secret within
// a project+environment scope. Never guessed which one was meant — see the
// ids property for every matching secret ID.
class AmbiguousSecretError extends KeyorixError {
  constructor(message, { ids, ...opts } = {}) {
    super(message, opts);
    this.name = 'AmbiguousSecretError';
    this.ids = ids;
  }
}

// Thrown when the token may read the secret but the secret's own state
// refuses the value read (HTTP 409): it has expired, is suspended, or has used
// up its max-reads budget. errorCode says which; each is reversible by an
// operator.
class SecretUnavailableError extends KeyorixError {
  constructor(message, opts) {
    super(message, opts);
    this.name = 'SecretUnavailableError';
  }
}

// Stable error codes the server sends when a secret's own state refuses a value
// read. A read outside the access schedule is a 403 (ForbiddenError with this
// errorCode); the other three are a 409 (SecretUnavailableError).
const CODE_SECRET_ACCESS_OUTSIDE_SCHEDULE = 'SecretAccessOutsideSchedule';
const SECRET_UNAVAILABLE_MESSAGES = {
  SecretExpired: 'The secret has expired',
  SecretSuspended: 'The secret is suspended',
  SecretMaxReadsExhausted: 'The secret has reached its maximum number of reads',
};

function errorCodeOf(body) {
  try {
    const parsed = JSON.parse(body);
    return parsed && typeof parsed.error === 'string' ? parsed.error : undefined;
  } catch {
    return undefined;
  }
}

// Maps a non-2xx HTTP status to a typed error: AuthError (401),
// ForbiddenError (403), NotFoundError (404), SecretUnavailableError (409 with
// a secret-state code), or the generic KeyorixError for anything else. Every
// request path returns through this so callers can rely on `instanceof`
// matching consistently, regardless of which method failed.
function errorForResponse(status, body) {
  const errorCode = errorCodeOf(body);
  const opts = { statusCode: status, responseBody: body, errorCode };
  if (status === 401) return new AuthError('Unauthorized — check your token', opts);
  if (status === 403) {
    if (errorCode === CODE_SECRET_ACCESS_OUTSIDE_SCHEDULE) {
      return new ForbiddenError('Forbidden — the secret is outside its access schedule', opts);
    }
    return new ForbiddenError('Forbidden — token lacks permission for this request', opts);
  }
  if (status === 404) return new NotFoundError('Resource not found', opts);
  if (status === 409 && Object.prototype.hasOwnProperty.call(SECRET_UNAVAILABLE_MESSAGES, errorCode)) {
    return new SecretUnavailableError(SECRET_UNAVAILABLE_MESSAGES[errorCode], opts);
  }
  return new KeyorixError(`Server returned ${status}`, opts);
}

// Removes every occurrence of `value` (raw and JSON-escaped) from a response
// body, so a server that echoes request content in a validation message
// cannot put the secret into an error's responseBody.
function redactValue(body, value) {
  if (typeof value !== 'string' || value === '') return body;
  const escaped = JSON.stringify(value).slice(1, -1);
  return body.split(value).join('[REDACTED]').split(escaped).join('[REDACTED]');
}

// A secret ID is interpolated into the request path: accept only a positive
// integer, so a caller-influenced id cannot change which resource is addressed.
function secretId(id) {
  if (!Number.isSafeInteger(id) || id <= 0) {
    throw new KeyorixError('secret id must be a positive integer');
  }
  return id;
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
        resolve({ status: res.statusCode, body: raw, headers: res.headers });
      });
    });
    req.on('error', reject);
    // Node's `timeout` request option only emits a 'timeout' event on
    // inactivity -- it does NOT abort the request by itself. Without this
    // handler, the configured timeout (default or caller-supplied) is
    // silently decorative and a hung server would block forever.
    req.on('timeout', () => {
      req.destroy(new KeyorixError(`Request timed out after ${options.timeout}ms`));
    });
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
  return authRequest(serverUrl, '/auth/login', { username, password }, timeout, 'Login');
}

/**
 * Complete a password login that threw MFARequiredError: exchange its
 * `challenge` and a current TOTP (or recovery) code for a session token. A
 * wrong or expired code or challenge is an AuthError.
 *
 * @param {string} serverUrl - Base URL of your Keyorix server
 * @param {string} challenge - `MFARequiredError.challenge`
 * @param {string} code - TOTP or recovery code
 * @param {number} [timeout=30000] - Timeout in milliseconds
 * @returns {Promise<string>} Session token
 */
async function verifyMfa(serverUrl, challenge, code, timeout = 30000) {
  return authRequest(serverUrl, '/auth/mfa/verify', { mfa_challenge: challenge, code }, timeout, 'MFA verify');
}

async function authRequest(serverUrl, path, payload, timeout, what) {
  validateServerUrl(serverUrl);
  const base = parseUrl(serverUrl);
  const body = JSON.stringify(payload);

  const options = {
    ...base,
    path,
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
    throw new AuthError(`${what} failed (HTTP ${resp.status})`, {
      statusCode: resp.status,
      responseBody: resp.body,
      errorCode: errorCodeOf(resp.body),
    });
  }

  const data = JSON.parse(resp.body)?.data;
  if (data?.token) return data.token;
  if (data?.mfa_required && data.mfa_challenge) {
    throw new MFARequiredError({
      challenge: data.mfa_challenge,
      totpAvailable: data.totp_available === true,
      webauthnAvailable: data.webauthn_available === true,
    });
  }
  throw new AuthError(`No token in ${what.toLowerCase()} response`);
}

// ── Client ───────────────────────────────────────────────────────────────────

class Client {
  /**
   * @param {string} serverUrl - Base URL of your Keyorix server
   * @param {string} token - Session token
   * @param {object} [opts]
   * @param {number} [opts.timeout=30000] - Timeout in milliseconds
   * @param {string|Buffer|Array<string|Buffer>} [opts.ca] - Trusted CA
   *   certificate(s) (PEM), for servers using a private/internal CA. Passed
   *   straight through to Node's https.request; no effect on plain http://.
   */
  constructor(serverUrl, token, opts = {}) {
    validateServerUrl(serverUrl);
    this._base = serverUrl.replace(/\/$/, '');
    this._token = token;
    this._timeout = opts.timeout || 30000;
    this._parsed = parseUrl(this._base);
    if (opts.ca) this._parsed.ca = opts.ca;
    // Populated lazily by _resolveProject/_resolveEnvironment and never
    // invalidated for the lifetime of this Client -- a project/environment
    // rename mid-process is expected to be rare enough that a fresh Client
    // is the right way to pick it up, not a cache-expiry policy.
    this._projectCache = new Map(); // lowercased name -> id
    this._envCache = new Map(); // project id -> Map(lowercased name -> id)
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

    if (resp.status !== 200) {
      throw errorForResponse(resp.status, resp.body);
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
   * @deprecated Removed in v0.3.0. An environment name is only unique
   * within one project, not globally, so scoping by environment alone
   * could silently return secrets from every project the caller can read.
   * Always throws without ever contacting the server (no silent fallback
   * to the old, unscoped behavior) -- use listSecretsScoped(project,
   * environment) instead.
   * @param {string} [environment]
   * @returns {Promise<Array>}
   */
  async listSecrets(environment = '') {
    throw new KeyorixError(
      "listSecrets(environment) was removed in v0.3.0 (an environment name is only " +
        'unique within one project, not globally) -- use listSecretsScoped(project, environment) instead'
    );
  }

  /**
   * @deprecated Removed in v0.3.0. An environment name is only unique
   * within one project, not globally, so scoping by environment alone
   * could silently resolve to another project's same-named secret.
   * Always throws without ever contacting the server (no silent fallback
   * to the old, unscoped behavior) -- use getSecretScoped(name, project,
   * environment) instead.
   * @param {string} name
   * @param {string} [environment]
   * @returns {Promise<string>}
   */
  async getSecret(name, environment = '') {
    throw new KeyorixError(
      "getSecret(name, environment) was removed in v0.3.0 (an environment name is only " +
        'unique within one project, not globally) -- use getSecretScoped(name, project, environment) instead'
    );
  }

  /**
   * List every secret within one project's environment. Follows every page
   * the server reports (`data.total_pages`) at page_size=100, so a scope
   * with more secrets than fit on one page (the server defaults to 20) is
   * never silently truncated.
   * @param {string|number} project - Project name (resolved to an ID and
   *   cached on this Client) or numeric project ID (no resolution round trip).
   * @param {string|number} environment - Environment name (resolved within
   *   `project`, cached) or numeric environment ID.
   * @returns {Promise<Array>}
   */
  async listSecretsScoped(project, environment) {
    const projectId = await this._resolveProject(project);
    const envId = await this._resolveEnvironment(projectId, environment);

    const all = [];
    for (let page = 1; ; page++) {
      const path = `/api/v1/secrets?project_id=${projectId}&environment_id=${envId}&page=${page}&page_size=100`;
      const data = await this._request(path);
      for (const s of data?.data?.secrets || []) {
        all.push({
          id: s.id,
          name: s.name,
          type: s.type,
          projectId: s.project_id,
          environment: s.environment_name,
          createdAt: s.created_at,
        });
      }
      if (page >= (data?.data?.total_pages || 0)) break;
    }
    return all;
  }

  /**
   * List a project's soft-deleted (restorable) secrets, newest deleted first.
   * Each entry has `purgeAt`: the instant (RFC 3339, UTC) before which the
   * server will not hard-delete it, i.e. the restore deadline. Requires
   * secrets.read at the project scope; the server caps the list at 500.
   * @param {string|number} project - Project name or numeric project ID.
   * @returns {Promise<Array>}
   */
  async listDeletedSecrets(project) {
    const projectId = await this._resolveProject(project);
    const data = await this._request(`/api/v1/projects/${projectId}/secrets/deleted?limit=500`);
    return (data?.data?.deleted || []).map((s) => ({
      id: s.id,
      name: s.name,
      type: s.type,
      projectId,
      purgeAt: s.purge_at,
    }));
  }

  /**
   * Get the value of secret `name` within `project`/`environment`, all by
   * name, via a single server-authorized round trip -- a thin wrapper
   * around getSecretByRef. Unlike getSecretScoped, this needs no
   * project/environment-list permission, since the server resolves and
   * authorizes the whole reference itself. project/environment/name are
   * joined with "/" -- if any contains a literal "/", use getSecretByRef
   * directly with your own escaping.
   * @param {string} project
   * @param {string} environment
   * @param {string} name
   * @returns {Promise<string>} Plaintext secret value
   */
  async getSecretIn(project, environment, name) {
    return this.getSecretByRef(`${project}/${environment}/${name}`);
  }

  /**
   * Get a secret's value by its "project/environment/name" reference, via
   * GET /api/v1/secrets/value?ref=<ref>. The server resolves and authorizes
   * ref against the resolved secret's own scope in one round trip -- no
   * project/environment-list permission needed, unlike getSecretScoped. The
   * secret name may itself contain "/"; only the first two "/"-separated
   * segments of ref are taken as project and environment.
   *
   * Throws NotFoundError if ref resolves to nothing and the caller holds
   * the global permission needed to confirm that; otherwise (including when
   * ref resolves to nothing and the caller does NOT hold that permission --
   * the server denies without confirming the resource exists, to avoid
   * existence enumeration) a ForbiddenError. A malformed ref (not
   * "project/environment/name") or an AuthError follow the same mapping as
   * every other call -- see errorForResponse.
   * @param {string} ref
   * @returns {Promise<string>} Plaintext secret value
   */
  async getSecretByRef(ref) {
    const data = await this._request(`/api/v1/secrets/value?ref=${encodeURIComponent(ref)}`);
    return data?.data?.value || '';
  }

  /**
   * Get the value of the secret named `name` within one project's
   * environment. `name` is matched exactly (case-sensitive) among the
   * secrets in that scope.
   * @param {string} name
   * @param {string|number} project - See listSecretsScoped.
   * @param {string|number} environment - See listSecretsScoped.
   * @returns {Promise<string>} Plaintext secret value
   * @throws {SecretNotFoundError} if no secret in scope has this name
   * @throws {AmbiguousSecretError} if more than one secret in scope has this
   *   name -- never guessed; .ids lists every match
   */
  async getSecretScoped(name, project, environment) {
    return this._getSecretValue(await this._findSecretId(name, project, environment));
  }

  /**
   * Resolve the secret named `name` within project/environment to its ID:
   * SecretNotFoundError if none has that name, AmbiguousSecretError if more
   * than one does.
   */
  async _findSecretId(name, project, environment) {
    const secrets = await this.listSecretsScoped(project, environment);
    const matches = secrets.filter((s) => s.name === name);
    if (matches.length === 0) {
      throw new SecretNotFoundError(
        `Secret '${name}' not found in project '${project}', environment '${environment}'`
      );
    }
    if (matches.length > 1) {
      const ids = matches.map((m) => m.id);
      throw new AmbiguousSecretError(
        `Secret '${name}' is ambiguous in project '${project}', environment '${environment}': matches IDs ${JSON.stringify(ids)}`,
        { ids }
      );
    }
    return matches[0].id;
  }

  /**
   * Write `value` as a new version of the secret named `name` within
   * project/environment, and return its metadata (never the value). The name
   * is resolved as for getSecretScoped. See updateSecretById.
   * @param {string|number} project - See listSecretsScoped.
   * @param {string|number} environment - See listSecretsScoped.
   * @param {string} name
   * @param {string} value - New plaintext value; must not be empty.
   * @returns {Promise<object>} `{ id, name, type, projectId, createdAt }`
   * @throws {SecretNotFoundError} if no secret in scope has this name
   * @throws {AmbiguousSecretError} if more than one does
   */
  async updateSecret(project, environment, name, value) {
    return this.updateSecretById(await this._findSecretId(name, project, environment), value);
  }

  /**
   * Write `value` as a new version of secret `id`, via PUT /api/v1/secrets/{id}.
   * Earlier versions are kept; a read returns the new value. `value` must not
   * be empty (the server ignores an empty value, so nothing would be written).
   *
   * Throws AuthError (401), ForbiddenError (403: the token cannot write this
   * secret) or NotFoundError (404: no such live secret, including a
   * soft-deleted one). A 409 under heavy write contention on the same secret
   * is a plain KeyorixError: retry. The value is never included in an error's
   * message, and any echo of it is stripped from `responseBody`.
   * @param {number} id
   * @param {string} value
   * @returns {Promise<object>} `{ id, name, type, projectId, createdAt }`
   */
  async updateSecretById(id, value) {
    if (typeof value !== 'string' || value === '') {
      throw new KeyorixError('updateSecret value must be a non-empty string');
    }
    const resp = await this._write('PUT', `/api/v1/secrets/${secretId(id)}`, { value }, [200]);
    const s = JSON.parse(resp.body)?.data || {};
    return { id: s.id, name: s.name, type: s.type, projectId: s.project_id, createdAt: s.created_at };
  }

  /**
   * Soft-delete the secret named `name` within project/environment. The name
   * is resolved as for getSecretScoped. See deleteSecretById.
   * @param {string|number} project - See listSecretsScoped.
   * @param {string|number} environment - See listSecretsScoped.
   * @param {string} name
   * @returns {Promise<{purgeAt: string|null}>}
   * @throws {SecretNotFoundError} if no secret in scope has this name
   * @throws {AmbiguousSecretError} if more than one does
   */
  async deleteSecret(project, environment, name) {
    return this.deleteSecretById(await this._findSecretId(name, project, environment));
  }

  /**
   * Soft-delete secret `id`, via DELETE /api/v1/secrets/{id}. The secret stops
   * being readable at once but is restorable until `purgeAt` (RFC 3339, UTC;
   * listDeletedSecrets lists it with the same date). `purgeAt` is null only if
   * the server did not send one; the delete itself still succeeded.
   *
   * Throws AuthError (401), ForbiddenError (403) or NotFoundError (404: no such
   * live secret, so deleting twice fails the second time). The server asks for
   * no step-up or MFA for a delete.
   * @param {number} id
   * @returns {Promise<{purgeAt: string|null}>}
   */
  async deleteSecretById(id) {
    const resp = await this._write('DELETE', `/api/v1/secrets/${secretId(id)}`, undefined, [200, 204]);
    return { purgeAt: resp.headers['keyorix-purge-at'] || null };
  }

  /**
   * Send a write request (JSON body when `payload` is given) and return the
   * response, or throw the typed error for any status not in `okStatuses`.
   * A string value in `payload` is stripped from the error's `responseBody`,
   * so a server that echoes request content cannot put the secret there.
   */
  async _write(method, path, payload, okStatuses) {
    const body = payload === undefined ? undefined : JSON.stringify(payload);
    const headers = { Authorization: `Bearer ${this._token}` };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    let resp;
    try {
      resp = await request({ ...this._parsed, path, method, headers, timeout: this._timeout }, body);
    } catch (err) {
      throw new KeyorixError(`Request failed: ${err.message}`);
    }
    if (!okStatuses.includes(resp.status)) {
      throw errorForResponse(resp.status, redactValue(resp.body, payload?.value));
    }
    return resp;
  }

  /**
   * Resolve project to an ID. A number resolves with no network call; a
   * string is resolved via GET /api/v1/projects and cached (case-insensitive
   * match).
   */
  async _resolveProject(project) {
    if (typeof project === 'number') return project;
    const key = String(project).toLowerCase();
    if (this._projectCache.has(key)) return this._projectCache.get(key);
    const projects = await this.listProjects();
    for (const p of projects) this._projectCache.set(String(p.name).toLowerCase(), p.id);
    if (!this._projectCache.has(key)) throw new KeyorixError(`Project '${project}' not found`);
    return this._projectCache.get(key);
  }

  /**
   * Resolve environment to an ID within projectId. A number resolves with no
   * network call; a string is resolved via the project-scoped environments
   * route and cached (case-insensitive match).
   */
  async _resolveEnvironment(projectId, environment) {
    if (typeof environment === 'number') return environment;
    const key = String(environment).toLowerCase();
    let byName = this._envCache.get(projectId);
    if (byName?.has(key)) return byName.get(key);
    if (!byName) {
      byName = new Map();
      this._envCache.set(projectId, byName);
    }
    const envs = await this.listEnvironments(projectId);
    for (const e of envs) byName.set(String(e.name).toLowerCase(), e.id);
    if (!byName.has(key)) {
      throw new KeyorixError(`Environment '${environment}' not found in project id=${projectId}`);
    }
    return byName.get(key);
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
      id: p.id, name: p.name, description: p.description, createdAt: p.created_at,
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
      throw errorForResponse(resp.status, resp.body);
    }
    const p = JSON.parse(resp.body)?.data || {};
    return { id: p.id, name: p.name, description: p.description, createdAt: p.created_at };
  }

  /**
   * List environments for a project.
   * @param {number} projectId
   * @returns {Promise<Array>}
   */
  async listEnvironments(projectId) {
    const data = await this._request(`/api/v1/projects/${projectId}/environments`);
    return (data?.data?.environments || []).map((e) => ({
      id: e.id, projectId: e.project_id, name: e.name,
    }));
  }
}

module.exports = {
  Client,
  login,
  verifyMfa,
  KeyorixError,
  AuthError,
  MFARequiredError,
  ForbiddenError,
  NotFoundError,
  SecretUnavailableError,
  SecretNotFoundError,
  AmbiguousSecretError,
};
