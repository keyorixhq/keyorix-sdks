export interface Secret {
  id: number;
  name: string;
  type: string;
  environment: string;
  namespace: string;
  createdAt: string;
}

export interface ClientOptions {
  timeout?: number;
}

export declare class KeyorixError extends Error {}
export declare class AuthError extends KeyorixError {}
export declare class SecretNotFoundError extends KeyorixError {}

export declare function login(
  serverUrl: string,
  username: string,
  password: string,
  timeout?: number
): Promise<string>;

export declare class Client {
  constructor(serverUrl: string, token: string, opts?: ClientOptions);
  health(): Promise<boolean>;
  listSecrets(environment?: string): Promise<Secret[]>;
  getSecret(name: string, environment?: string): Promise<string>;
}
