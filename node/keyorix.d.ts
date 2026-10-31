export interface Secret {
  id: number;
  name: string;
  type: string;
  projectId: number;
  environment: string;
  createdAt: string;
  /** Restore deadline (RFC 3339 UTC) of a soft-deleted secret; set by listDeletedSecrets. */
  purgeAt?: string;
}

/** Secret metadata returned by updateSecret / updateSecretById (never the value). */
export interface UpdatedSecret {
  id: number;
  name: string;
  type: string;
  projectId: number;
  createdAt: string;
}

/** Result of deleteSecret / deleteSecretById. */
export interface DeletedSecret {
  /** Restore deadline (RFC 3339 UTC); null only if the server sent none. */
  purgeAt: string | null;
}

export interface Project {
  id: number;
  name: string;
  description: string;
  createdAt: string;
}

export interface Environment {
  id: number;
  projectId: number;
  name: string;
}

export interface ClientOptions {
  timeout?: number;
}

export declare class KeyorixError extends Error {
  statusCode?: number;
  responseBody?: string;
  /** The server's stable error code, e.g. "SecretSuspended". */
  errorCode?: string;
}
export declare class AuthError extends KeyorixError {}
/**
 * login() on an account with a second factor: complete with verifyMfa(serverUrl,
 * err.challenge, code). Still an AuthError, as before.
 */
export declare class MFARequiredError extends AuthError {
  challenge: string;
  totpAvailable: boolean;
  webauthnAvailable: boolean;
  /** Second factors the account has: "totp" and/or "webauthn". */
  methods: string[];
}
export declare class ForbiddenError extends KeyorixError {}
export declare class NotFoundError extends KeyorixError {}
/** 409: the secret has expired, is suspended or used up its max reads (see errorCode). */
export declare class SecretUnavailableError extends KeyorixError {}
export declare class SecretNotFoundError extends KeyorixError {}
export declare class AmbiguousSecretError extends KeyorixError {
  ids: number[];
}

export declare function login(
  serverUrl: string,
  username: string,
  password: string,
  timeout?: number
): Promise<string>;

/** Completes a login that threw MFARequiredError with a TOTP or recovery code. */
export declare function verifyMfa(
  serverUrl: string,
  challenge: string,
  code: string,
  timeout?: number
): Promise<string>;

export declare class Client {
  constructor(serverUrl: string, token: string, opts?: ClientOptions);
  health(): Promise<boolean>;
  /** @deprecated Removed in v0.3.0 — always throws. Use listSecretsScoped. */
  listSecrets(environment?: string): Promise<Secret[]>;
  /** @deprecated Removed in v0.3.0 — always throws. Use getSecretScoped. */
  getSecret(name: string, environment?: string): Promise<string>;
  listSecretsScoped(project: string | number, environment: string | number): Promise<Secret[]>;
  listDeletedSecrets(project: string | number): Promise<Secret[]>;
  getSecretScoped(name: string, project: string | number, environment: string | number): Promise<string>;
  getSecretIn(project: string, environment: string, name: string): Promise<string>;
  getSecretByRef(ref: string): Promise<string>;
  /** Writes `value` as a new version of the named secret; returns metadata, never the value. */
  updateSecret(project: string | number, environment: string | number, name: string, value: string): Promise<UpdatedSecret>;
  updateSecretById(id: number, value: string): Promise<UpdatedSecret>;
  /** Soft-deletes the named secret; `purgeAt` is its restore deadline (null if the server sent none). */
  deleteSecret(project: string | number, environment: string | number, name: string): Promise<DeletedSecret>;
  deleteSecretById(id: number): Promise<DeletedSecret>;
  listProjects(): Promise<Project[]>;
  createProject(name: string, description?: string): Promise<Project>;
  listEnvironments(projectId: number): Promise<Environment[]>;
}
