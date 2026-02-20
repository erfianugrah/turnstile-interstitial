export interface Env {
  CHALLENGE_STATUS: DurableObjectNamespace;
  CREDENTIALS_STORAGE: DurableObjectNamespace;
  SITE_KEY: string;
  SECRET_KEY: string;
  MAX_TOKENS: string;
  REFILL_RATE: string;
  REFILL_TIME: string;
  TIME_TO_CHALLENGE: string;
  MAX_CREDENTIAL_BODY_SIZE: string;
  CREDENTIAL_TTL: string;
  /**
   * Comma-separated list of path prefixes to protect with Turnstile challenge.
   * Examples: "/login,/admin,/dashboard" or "/*" for all routes.
   * Defaults to "/login" if not set.
   */
  PROTECTED_PATHS: string;
  /**
   * Path prefix for credential storage on POST requests.
   * Defaults to "/api/login" if not set.
   */
  CREDENTIAL_STORE_PATH: string;
  /**
   * Path used for Turnstile verification callback.
   * Defaults to "/verify" if not set.
   */
  VERIFY_PATH: string;
}

export interface RateLimitInfo {
  tokens: number;
  nextAllowedRequest: number;
  lastAccess: number;
}

export interface StoredCredentials {
  encryptedData: number[];
  iv: number[];
  key: number[];
  storedAt: number;
}

export interface LoginAttemptDetails {
  body: unknown;
  headers: Record<string, string>;
  method: string;
  url: string;
}

export interface RateLimitConfig {
  maxTokens: number;
  refillRate: number;
  refillTime: number;
}
