export interface Secret {
  id: number;
  name: string;
  type: string;
  projectId: number;
  environment: string;
  createdAt: string;
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
}
export declare class AuthError extends KeyorixError {}
export declare class ForbiddenError extends KeyorixError {}
export declare class NotFoundError extends KeyorixError {}
export declare class MFARequiredError extends KeyorixError {
  /** Single-use token to pass to verifyMfa() with a TOTP or recovery code. */
  challenge: string;
  totpAvailable: boolean;
  webauthnAvailable: boolean;
}
export declare class SecretNotFoundError extends KeyorixError {}
export declare class AmbiguousSecretError extends KeyorixError {
  ids: number[];
}

export declare function login(
  serverUrl: string,
  username: string,
  password: string,
  timeoutOrOpts?: number | { timeout?: number; mfaCode?: string }
): Promise<string>;

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
  getSecretScoped(name: string, project: string | number, environment: string | number): Promise<string>;
  getSecretIn(project: string, environment: string, name: string): Promise<string>;
  getSecretByRef(ref: string): Promise<string>;
  listProjects(): Promise<Project[]>;
  createProject(name: string, description?: string): Promise<Project>;
  listEnvironments(projectId: number): Promise<Environment[]>;
}
