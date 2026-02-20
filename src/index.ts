import {
  decryptData,
  encryptData,
  exportKey,
  generateEncryptionKey,
  getClearanceCookie,
  getClientIP,
  hashValue,
  importKey,
  generateClearanceCookie,
  verifyClearanceCookie,
  buildSetCookieHeader,
} from "./utils";
import { serveChallengePage, serveRateLimitPage } from "./staticpages";
import { verifyChallenge } from "./siteverify";
import type {
  Env,
  RateLimitConfig,
  RateLimitInfo,
  StoredCredentials,
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
            currentTime - (data as { lastAccess: number }).lastAccess >
              expirationTime
          ) {
            toDelete.push(key);
          }
          if (
            data &&
            typeof data === "object" &&
            "storedAt" in data &&
            typeof (data as { storedAt: number }).storedAt === "number" &&
            currentTime - (data as { storedAt: number }).storedAt >
              expirationTime
          ) {
            toDelete.push(key);
          }
        } catch {
          // skip unparseable values
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
// ChallengeStatusStorage — rate limiting only
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
        case "/checkRateLimit":
          return this.checkRateLimit(request);
        default:
          return new Response("Not found", { status: 404 });
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`Error handling request: ${message}`);
      return new Response(JSON.stringify({ error: message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  /**
   * Token-bucket rate limiter keyed by IP address.
   */
  private async checkRateLimit(request: Request): Promise<Response> {
    const clientIP = getClientIP(request);
    const identifier = await hashValue(clientIP);

    let rateLimitInfo =
      await this.state.storage.get<RateLimitInfo>(identifier);
    const currentTime = Date.now();

    if (!rateLimitInfo) {
      rateLimitInfo = {
        tokens: this.rateLimit.maxTokens - 1,
        nextAllowedRequest: currentTime + this.rateLimit.refillTime,
        lastAccess: currentTime,
      };
      await this.state.storage.put(identifier, rateLimitInfo);
      return new Response("Allowed", { status: 200 });
    }

    rateLimitInfo.lastAccess = currentTime;

    if (currentTime >= rateLimitInfo.nextAllowedRequest) {
      rateLimitInfo.tokens = this.rateLimit.maxTokens;
    }

    if (rateLimitInfo.tokens > 0) {
      rateLimitInfo.tokens--;
      rateLimitInfo.nextAllowedRequest =
        currentTime + this.rateLimit.refillTime;
      await this.state.storage.put(identifier, rateLimitInfo);
      return new Response("Allowed", { status: 200 });
    }

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

        try {
          JSON.parse(bodyText);
        } catch {
          return new Response(
            JSON.stringify({ error: "Invalid JSON body" }),
            { status: 400, headers: { "Content-Type": "application/json" } },
          );
        }

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

        const ttl = parseInt(this.env.CREDENTIAL_TTL || "300000", 10);
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

        await this.state.storage.delete("encryptedCredentials");

        return new Response(decryptedData, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response("Not found", { status: 404 });
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Unknown error";
      console.error(`CredentialsStorage error: ${message}`);
      return new Response(JSON.stringify({ error: message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  async alarm(): Promise<void> {
    await this.state.storage.delete("encryptedCredentials");
  }
}

// ---------------------------------------------------------------------------
// Route matching
// ---------------------------------------------------------------------------

export function getProtectedPaths(env: Env): string[] {
  const raw = (env.PROTECTED_PATHS || "/login").trim();
  return raw
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
}

export function isProtectedPath(
  pathname: string,
  protectedPaths: string[],
): boolean {
  for (const prefix of protectedPaths) {
    if (prefix === "/*") return true;
    if (
      pathname === prefix ||
      pathname.startsWith(prefix + "/") ||
      pathname.startsWith(prefix + "?")
    ) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Worker fetch handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const verifyPath = (env.VERIFY_PATH || "/verify").trim();

    // Verification endpoint — always active
    if (url.pathname.startsWith(verifyPath) && request.method === "POST") {
      return handleVerifyRequest(request, env);
    }

    // Check if this path is protected
    const protectedPaths = getProtectedPaths(env);
    if (isProtectedPath(url.pathname, protectedPaths)) {
      return handleProtectedRequest(request, env);
    }

    // Pass through unprotected routes
    return fetch(request);
  },

  async scheduled(
    _event: ScheduledEvent,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<void> {
    ctx.waitUntil(
      (async () => {
        const rateLimiterId =
          env.CHALLENGE_STATUS.idFromName("rateLimiter");
        const rateLimiterStub =
          env.CHALLENGE_STATUS.get(rateLimiterId);
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
  const clientIP = getClientIP(request);

  // 1. Check for a valid signed clearance cookie
  const clearanceValid = await verifyClearanceFromRequest(request, env);
  if (!clearanceValid) {
    return serveChallengePage(env, request);
  }

  // 2. Rate limit check (by IP)
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

  // 3. POST to credential store path → encrypt and store
  const credentialStorePath = (
    env.CREDENTIAL_STORE_PATH || "/api/login"
  ).trim();
  if (
    request.method === "POST" &&
    url.pathname.startsWith(credentialStorePath)
  ) {
    return handlePostLogin(request, env);
  }

  // 4. All other methods → proxy to origin
  return fetch(request);
}

/**
 * Handle POST /verify — validate Turnstile token, issue signed cookie, redirect.
 */
async function handleVerifyRequest(
  request: Request,
  env: Env,
): Promise<Response> {
  const result = await verifyChallenge(request, env);

  if (!result.success) {
    return new Response(
      JSON.stringify({ error: result.error }),
      {
        status: result.status,
        headers: { "Content-Type": "application/json" },
      },
    );
  }

  // Turnstile verification succeeded — generate signed clearance cookie
  const clientIP = getClientIP(request);
  const cookieValue = await generateClearanceCookie(env.SECRET_KEY, clientIP);
  const challengeTTL = parseInt(env.TIME_TO_CHALLENGE || "150000", 10);
  const maxAgeSec = Math.floor(challengeTTL / 1000);
  const setCookie = buildSetCookieHeader(cookieValue, maxAgeSec);

  return new Response(null, {
    status: 302,
    headers: {
      Location: result.originalUrl!,
      "Set-Cookie": setCookie,
      "Cache-Control": "no-store, max-age=0",
    },
  });
}

async function handlePostLogin(
  request: Request,
  env: Env,
): Promise<Response> {
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
      message: "Login attempt stored.",
      attemptId: loginAttemptId,
    }),
    {
      status: 200,
      headers: { "Content-Type": "application/json" },
    },
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Verify the signed clearance cookie from the request.
 * Checks HMAC signature, IP binding, and timestamp expiry.
 */
async function verifyClearanceFromRequest(
  request: Request,
  env: Env,
): Promise<boolean> {
  const cookieValue = getClearanceCookie(request);
  if (!cookieValue) return false;

  const payload = await verifyClearanceCookie(env.SECRET_KEY, cookieValue);
  if (!payload) return false;

  // Check IP binding
  const clientIP = getClientIP(request);
  if (payload.ip !== clientIP) return false;

  // Check expiry
  const challengeTTL = parseInt(env.TIME_TO_CHALLENGE || "150000", 10);
  if (Date.now() - payload.timestamp > challengeTTL) return false;

  return true;
}

/**
 * Rate limit check keyed by IP only.
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
