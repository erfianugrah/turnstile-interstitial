import {
  decryptData,
  encryptData,
  exportKey,
  generateEncryptionKey,
  getCfClearanceValue,
  getClientIP,
  hashValue,
  importKey,
} from "./utils";
import { serveChallengePage, serveRateLimitPage } from "./staticpages";
import { verifyChallenge } from "./siteverify";
import type {
  Env,
  RateLimitConfig,
  RateLimitInfo,
  StoredCredentials,
  TimestampAndIP,
} from "./types";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CLEANUP_EXPIRATION_MS = 24 * 60 * 60 * 1000; // 24 hours
const CLEANUP_BATCH_SIZE = 128;
const MAX_CREDENTIAL_BODY_SIZE_DEFAULT = 65_536; // 64 KB

// ---------------------------------------------------------------------------
// Base Durable Object
// ---------------------------------------------------------------------------

class BaseStorage implements DurableObject {
  protected state: DurableObjectState;

  constructor(state: DurableObjectState, _env: Env) {
    this.state = state;
  }

  async fetch(_request: Request): Promise<Response> {
    return new Response("Not found", { status: 404 });
  }

  /**
   * Cleanup expired data in batches to avoid iterating all keys in one shot.
   */
  async cleanupExpiredData(expirationTime: number): Promise<void> {
    const currentTime = Date.now();
    let cursor: string | undefined;
    let hasMore = true;

    while (hasMore) {
      const entries: Map<string, unknown> = await this.state.storage.list({
        limit: CLEANUP_BATCH_SIZE,
        ...(cursor ? { startAfter: cursor } : {}),
      });

      if (entries.size === 0) break;

      const toDelete: string[] = [];
      let lastKey: string | undefined;

      for (const [key, rawValue] of entries) {
        lastKey = key;
        try {
          const data =
            typeof rawValue === "string" ? JSON.parse(rawValue) : rawValue;
          if (
            data &&
            typeof data === "object" &&
            "lastAccess" in data &&
            typeof (data as { lastAccess: number }).lastAccess === "number" &&
            currentTime - (data as { lastAccess: number }).lastAccess > expirationTime
          ) {
            toDelete.push(key);
          }
          // Also clean up storedAt-based entries (credentials)
          if (
            data &&
            typeof data === "object" &&
            "storedAt" in data &&
            typeof (data as { storedAt: number }).storedAt === "number" &&
            currentTime - (data as { storedAt: number }).storedAt > expirationTime
          ) {
            toDelete.push(key);
          }
        } catch {
          // If the value can't be parsed, skip it
        }
      }

      if (toDelete.length > 0) {
        await this.state.storage.delete(toDelete);
      }

      cursor = lastKey;
      hasMore = entries.size === CLEANUP_BATCH_SIZE;
    }
  }
}

// ---------------------------------------------------------------------------
// ChallengeStatusStorage
// ---------------------------------------------------------------------------

export class ChallengeStatusStorage extends BaseStorage {
  private env: Env;
  private rateLimit: RateLimitConfig;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.env = env;
    this.rateLimit = {
      maxTokens: parseInt(env.MAX_TOKENS || "5", 10),
      refillRate: parseInt(env.REFILL_RATE || "5", 10),
      refillTime: parseInt(env.REFILL_TIME || "60000", 10),
    };
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      switch (url.pathname) {
        case "/getTimestampAndIP": {
          const data =
            await this.state.storage.get<TimestampAndIP>("timestampAndIP");
          if (!data) {
            return new Response(
              JSON.stringify({ error: "No data found" }),
              { status: 404, headers: { "Content-Type": "application/json" } },
            );
          }
          return new Response(JSON.stringify(data), {
            headers: { "Content-Type": "application/json" },
          });
        }

        case "/storeTimestampAndIP": {
          const clientIP = getClientIP(request);
          const timestampAndIP: TimestampAndIP = {
            timestamp: Date.now(),
            ip: clientIP,
          };
          await this.state.storage.put("timestampAndIP", timestampAndIP);
          return new Response("Timestamp and IP stored");
        }

        case "/deleteTimestampAndIP": {
          await this.state.storage.delete("timestampAndIP");
          return new Response("Timestamp and IP deleted", { status: 200 });
        }

        case "/checkRateLimit": {
          return this.checkRateLimit(request);
        }

        default:
          return new Response("Not found", { status: 404 });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      console.error(`Error handling request: ${message}`);
      return new Response(JSON.stringify({ error: message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  /**
   * Rate limiter keyed by IP address (not cookie) to prevent bypass via cookie rotation.
   * Uses token-bucket algorithm.
   */
  private async checkRateLimit(request: Request): Promise<Response> {
    const clientIP = getClientIP(request);
    // Key rate limit by IP only — cookie is attacker-controlled and can be rotated
    const identifier = await hashValue(clientIP);

    let rateLimitInfo =
      await this.state.storage.get<RateLimitInfo>(identifier);
    const currentTime = Date.now();

    if (!rateLimitInfo) {
      // First request: consume one token
      rateLimitInfo = {
        tokens: this.rateLimit.maxTokens - 1,
        nextAllowedRequest: currentTime + this.rateLimit.refillTime,
        lastAccess: currentTime,
      };
      await this.state.storage.put(identifier, rateLimitInfo);
      return new Response("Allowed", { status: 200 });
    }

    rateLimitInfo.lastAccess = currentTime;

    // Refill tokens if the cooldown has passed
    if (currentTime >= rateLimitInfo.nextAllowedRequest) {
      rateLimitInfo.tokens = this.rateLimit.maxTokens;
    }

    // Try to consume a token
    if (rateLimitInfo.tokens > 0) {
      rateLimitInfo.tokens--;
      rateLimitInfo.nextAllowedRequest =
        currentTime + this.rateLimit.refillTime;
      await this.state.storage.put(identifier, rateLimitInfo);
      return new Response("Allowed", { status: 200 });
    }

    // No tokens left — rate limited
    await this.state.storage.put(identifier, rateLimitInfo);
    const cooldownEndTime = new Date(
      rateLimitInfo.nextAllowedRequest,
    ).toISOString();
    return new Response(
      JSON.stringify({ message: "Rate limit exceeded", cooldownEndTime }),
      {
        status: 429,
        headers: { "Content-Type": "application/json" },
      },
    );
  }
}

// ---------------------------------------------------------------------------
// CredentialsStorage — with key persistence and TTL
// ---------------------------------------------------------------------------

export class CredentialsStorage extends BaseStorage {
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/store") {
        // Enforce body size limit
        const maxSize = parseInt(
          this.env.MAX_CREDENTIAL_BODY_SIZE ||
            String(MAX_CREDENTIAL_BODY_SIZE_DEFAULT),
          10,
        );
        const contentLength = request.headers.get("Content-Length");
        if (contentLength && parseInt(contentLength, 10) > maxSize) {
          return new Response(
            JSON.stringify({ error: "Request body too large" }),
            { status: 413, headers: { "Content-Type": "application/json" } },
          );
        }

        const bodyText = await request.text();
        if (bodyText.length > maxSize) {
          return new Response(
            JSON.stringify({ error: "Request body too large" }),
            { status: 413, headers: { "Content-Type": "application/json" } },
          );
        }

        // Validate JSON
        try {
          JSON.parse(bodyText);
        } catch {
          return new Response(
            JSON.stringify({ error: "Invalid JSON body" }),
            { status: 400, headers: { "Content-Type": "application/json" } },
          );
        }

        // Generate key, encrypt, and persist key alongside data
        const key = await generateEncryptionKey();
        const { encryptedData, iv } = await encryptData(key, bodyText);
        const exportedKey = await exportKey(key);

        const stored: StoredCredentials = {
          encryptedData: Array.from(new Uint8Array(encryptedData)),
          iv: Array.from(iv),
          key: exportedKey,
          storedAt: Date.now(),
        };

        await this.state.storage.put("encryptedCredentials", stored);

        // Set an alarm to auto-expire credentials
        const ttl = parseInt(
          this.env.CREDENTIAL_TTL || "300000",
          10,
        );
        await this.state.storage.setAlarm(Date.now() + ttl);

        return new Response("Credentials stored", { status: 200 });
      }

      if (url.pathname === "/retrieve") {
        const stored =
          await this.state.storage.get<StoredCredentials>(
            "encryptedCredentials",
          );
        if (!stored) {
          return new Response(
            JSON.stringify({ error: "No credentials found" }),
            { status: 404, headers: { "Content-Type": "application/json" } },
          );
        }

        // Check TTL
        const ttl = parseInt(this.env.CREDENTIAL_TTL || "300000", 10);
        if (Date.now() - stored.storedAt > ttl) {
          await this.state.storage.delete("encryptedCredentials");
          return new Response(
            JSON.stringify({ error: "Credentials expired" }),
            { status: 410, headers: { "Content-Type": "application/json" } },
          );
        }

        const key = await importKey(stored.key);
        const decryptedData = await decryptData(
          key,
          new Uint8Array(stored.encryptedData),
          new Uint8Array(stored.iv),
        );

        // Delete after single retrieval
        await this.state.storage.delete("encryptedCredentials");

        return new Response(decryptedData, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response("Not found", { status: 404 });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      console.error(`CredentialsStorage error: ${message}`);
      return new Response(JSON.stringify({ error: message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  /**
   * Alarm handler: auto-expire credentials after TTL.
   */
  async alarm(): Promise<void> {
    await this.state.storage.delete("encryptedCredentials");
  }
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------

/**
 * Parse PROTECTED_PATHS env var into an array of path prefixes.
 * Supports "/*" for all routes, or comma-separated prefixes like "/login,/admin".
 */
export function getProtectedPaths(env: Env): string[] {
  const raw = (env.PROTECTED_PATHS || "/login").trim();
  return raw.split(",").map((p) => p.trim()).filter(Boolean);
}

export function isProtectedPath(pathname: string, protectedPaths: string[]): boolean {
  for (const prefix of protectedPaths) {
    if (prefix === "/*") return true;
    if (pathname === prefix || pathname.startsWith(prefix + "/") || pathname.startsWith(prefix + "?")) {
      return true;
    }
    // Also match exact prefix (e.g. "/login" matches "/login")
    if (pathname === prefix) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Worker fetch handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cfClearanceValue = getCfClearanceValue(request);
    const verifyPath = (env.VERIFY_PATH || "/verify").trim();

    // Verification endpoint — always active
    if (url.pathname.startsWith(verifyPath) && request.method === "POST") {
      return handleVerifyRequest(request, env, cfClearanceValue);
    }

    // Check if this path is protected
    const protectedPaths = getProtectedPaths(env);
    if (isProtectedPath(url.pathname, protectedPaths)) {
      return handleProtectedRequest(request, env);
    }

    // Pass through unprotected routes
    return fetch(request);
  },

  /**
   * Scheduled handler for daily cleanup of expired Durable Object data.
   */
  async scheduled(
    _event: ScheduledEvent,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    ctx.waitUntil(
      (async () => {
        // Clean up a well-known DO instance used by the rate limiter
        const rateLimiterId = env.CHALLENGE_STATUS.idFromName("rateLimiter");
        const rateLimiterStub = env.CHALLENGE_STATUS.get(rateLimiterId);
        await rateLimiterStub.fetch(
          new Request("https://internal/cleanupExpiredData"),
        );
      })(),
    );
  },
};

// ---------------------------------------------------------------------------
// Request handlers
// ---------------------------------------------------------------------------

async function handleProtectedRequest(
  request: Request,
  env: Env,
): Promise<Response> {
  const url = new URL(request.url);
  const cfClearance = getCfClearanceValue(request);
  const clientIP = getClientIP(request);

  if (!cfClearance) {
    return serveChallengePage(env, request);
  }

  const rateLimitCheck = await checkRateLimit(env, clientIP);
  if (rateLimitCheck.status === 429) {
    const responseBody = await rateLimitCheck.json<{
      cooldownEndTime: string;
    }>();
    const cooldownEndTime = new Date(responseBody.cooldownEndTime);
    const now = new Date();

    if (now > cooldownEndTime) {
      return serveChallengePage(env, request);
    }
    return serveRateLimitPage(cooldownEndTime, request);
  }

  // POST to the credential store path → encrypt and store credentials
  const credentialStorePath = (env.CREDENTIAL_STORE_PATH || "/api/login").trim();
  if (request.method === "POST" && url.pathname.startsWith(credentialStorePath)) {
    return handlePostLogin(request, env, cfClearance);
  }

  // All other methods (GET, etc.) → verify challenge, then proxy to origin
  return handleGetProtected(request, env, cfClearance);
}

async function handleGetProtected(
  request: Request,
  env: Env,
  cfClearanceValue: string,
): Promise<Response> {
  const isVerified = await verifyChallengeStatus(
    request,
    env,
    cfClearanceValue,
  );
  if (isVerified) {
    return fetch(request);
  }
  return serveChallengePage(env, request);
}

async function handlePostLogin(
  request: Request,
  env: Env,
  cfClearanceValue: string,
): Promise<Response> {
  const isVerified = await verifyChallengeStatus(
    request,
    env,
    cfClearanceValue,
  );
  if (!isVerified) {
    return serveChallengePage(env, request);
  }

  // Enforce body size limit before reading
  const maxSize = parseInt(
    env.MAX_CREDENTIAL_BODY_SIZE ||
      String(MAX_CREDENTIAL_BODY_SIZE_DEFAULT),
    10,
  );
  const contentLength = request.headers.get("Content-Length");
  if (contentLength && parseInt(contentLength, 10) > maxSize) {
    return new Response(
      JSON.stringify({ error: "Request body too large" }),
      { status: 413, headers: { "Content-Type": "application/json" } },
    );
  }

  let requestBody: unknown;
  try {
    requestBody = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid JSON body" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  const requestHeaders = Object.fromEntries(
    [...request.headers].filter(
      ([key]) =>
        !["host", "cookie", "content-length"].includes(key.toLowerCase()),
    ),
  );

  const loginAttemptId = crypto.randomUUID();
  const storage = env.CREDENTIALS_STORAGE.get(
    env.CREDENTIALS_STORAGE.idFromName(loginAttemptId),
  );

  const storeResponse = await storage.fetch(
    "https://challengestorage.internal/store",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        body: requestBody,
        headers: requestHeaders,
        method: request.method,
        url: request.url,
      }),
    },
  );

  if (!storeResponse.ok) {
    const err = await storeResponse.text();
    return new Response(err, { status: storeResponse.status });
  }

  return new Response(
    JSON.stringify({
      message: "Login attempt stored. Please complete the challenge if required.",
      attemptId: loginAttemptId,
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    },
  );
}

async function handleVerifyRequest(
  request: Request,
  env: Env,
  cfClearanceValue: string | null,
): Promise<Response> {
  const response = await verifyChallenge(request, env);
  if (response.status === 302 && cfClearanceValue) {
    const challengeStatusStorage = await getChallengeStatusStorage(
      env,
      cfClearanceValue,
    );
    await challengeStatusStorage.fetch(
      new Request("https://challengestorage.internal/storeTimestampAndIP", {
        headers: { "CF-Connecting-IP": getClientIP(request) },
      }),
    );
  }
  return response;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function getChallengeStatusStorage(
  env: Env,
  cfClearanceValue: string,
): Promise<DurableObjectStub> {
  const hashedCfClearanceValue = await hashValue(cfClearanceValue);
  const challengeStatusStorageId =
    env.CHALLENGE_STATUS.idFromName(hashedCfClearanceValue);
  return env.CHALLENGE_STATUS.get(challengeStatusStorageId);
}

async function verifyChallengeStatus(
  request: Request,
  env: Env,
  cfClearanceValue: string | null,
): Promise<boolean> {
  try {
    if (!cfClearanceValue) {
      return false;
    }

    const challengeStatusStorage = await getChallengeStatusStorage(
      env,
      cfClearanceValue,
    );
    const dataResponse = await challengeStatusStorage.fetch(
      new Request("https://challengestorage.internal/getTimestampAndIP"),
    );

    if (!dataResponse.ok) {
      return false;
    }

    const data = await dataResponse.json<TimestampAndIP>();
    const currentTime = Date.now();
    const timeToChallenge = parseInt(env.TIME_TO_CHALLENGE || "150000", 10);
    const timeDifference = currentTime - data.timestamp;
    const isTimestampValid = timeDifference < timeToChallenge;
    const isIPMatching = data.ip === getClientIP(request);

    if (!isTimestampValid || !isIPMatching) {
      await challengeStatusStorage.fetch(
        new Request(
          "https://challengestorage.internal/deleteTimestampAndIP",
          { method: "POST" },
        ),
      );
      return false;
    }

    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    console.error(`Verification error: ${message}`);
    return false;
  }
}

/**
 * Rate limit check keyed by IP only (prevents bypass via cookie rotation).
 */
async function checkRateLimit(
  env: Env,
  clientIP: string,
): Promise<Response> {
  const rateLimitRequest = new Request(
    "https://challengestorage.internal/checkRateLimit",
    {
      method: "POST",
      headers: new Headers({
        "CF-Connecting-IP": clientIP,
      }),
    },
  );

  const rateLimiterStub = env.CHALLENGE_STATUS.get(
    env.CHALLENGE_STATUS.idFromName("rateLimiter"),
  );
  return rateLimiterStub.fetch(rateLimitRequest);
}
