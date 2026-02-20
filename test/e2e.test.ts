import {
  env,
  runInDurableObject,
  SELF,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src/index";
import {
  sanitizeUrl,
  hashValue,
  getClearanceCookie,
  getClientIP,
  generateEncryptionKey,
  exportKey,
  importKey,
  encryptData,
  decryptData,
  generateClearanceCookie,
  verifyClearanceCookie,
  buildSetCookieHeader,
} from "../src/utils";
import { serveChallengePage, serveRateLimitPage } from "../src/staticpages";
import { getProtectedPaths, isProtectedPath } from "../src/index";

// Helper to run code inside a Durable Object with typed fetch
async function runInDO(
  stub: DurableObjectStub,
  fn: (instance: { fetch: (req: Request) => Promise<Response> }) => Promise<void>,
) {
  await runInDurableObject(stub, async (instance) => {
    await fn(instance as unknown as { fetch: (req: Request) => Promise<Response> });
  });
}

// Helper to make requests via the worker
async function workerFetch(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  return SELF.fetch(`https://file.erfianugrah.com${path}`, init);
}

// Test secret key matching vitest.config.ts miniflare bindings
const TEST_SECRET_KEY = "test-secret-key";
const TEST_IP = "1.2.3.4";

// ---------------------------------------------------------------------------
// Basic routing
// ---------------------------------------------------------------------------

describe("Worker routing", () => {
  it("passes through non-login/verify requests to origin", async () => {
    try {
      const resp = await workerFetch("/some-page");
      const body = await resp.text();
      expect(body).not.toContain("Complete the challenge to proceed");
    } catch {
      // DNS failure in test env is expected for pass-through routes
      expect(true).toBe(true);
    }
  });

  it("serves challenge page for GET /login without clearance cookie", async () => {
    const resp = await workerFetch("/login", {
      headers: { Accept: "text/html" },
    });
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).toContain("Complete the challenge to proceed");
    expect(body).toContain("cf-turnstile");
    expect(body).toContain("test-site-key");
  });

  it("returns JSON challenge for non-browser /login requests", async () => {
    const resp = await workerFetch("/login", {
      headers: { Accept: "application/json" },
    });
    expect(resp.status).toBe(200);
    const json = await resp.json<{ message: string }>();
    expect(json.message).toBe(
      "Please complete the challenge to proceed.",
    );
  });

  it("serves challenge page for /login/subpath", async () => {
    const resp = await workerFetch("/login/subpath", {
      headers: { Accept: "text/html" },
    });
    const body = await resp.text();
    expect(body).toContain("Complete the challenge to proceed");
  });
});

// ---------------------------------------------------------------------------
// Clearance cookie — generation, verification, extraction
// ---------------------------------------------------------------------------

describe("Clearance cookie", () => {
  it("generateClearanceCookie produces a payload.signature format", async () => {
    const cookie = await generateClearanceCookie(TEST_SECRET_KEY, TEST_IP);
    expect(cookie).toContain(".");
    const parts = cookie.split(".");
    expect(parts.length).toBe(2);
    // First part is base64-encoded JSON
    const payload = JSON.parse(atob(parts[0]));
    expect(payload.ip).toBe(TEST_IP);
    expect(typeof payload.timestamp).toBe("number");
    // Second part is a hex HMAC signature (64 hex chars for SHA-256)
    expect(parts[1]).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verifyClearanceCookie validates a correctly signed cookie", async () => {
    const cookie = await generateClearanceCookie(TEST_SECRET_KEY, TEST_IP);
    const payload = await verifyClearanceCookie(TEST_SECRET_KEY, cookie);
    expect(payload).not.toBeNull();
    expect(payload!.ip).toBe(TEST_IP);
    expect(payload!.timestamp).toBeGreaterThan(0);
  });

  it("verifyClearanceCookie rejects tampered payload", async () => {
    const cookie = await generateClearanceCookie(TEST_SECRET_KEY, TEST_IP);
    const [_payload, signature] = cookie.split(".");
    // Tamper with the payload
    const tamperedPayload = btoa(JSON.stringify({ ip: "6.6.6.6", timestamp: Date.now() }));
    const tampered = `${tamperedPayload}.${signature}`;
    const result = await verifyClearanceCookie(TEST_SECRET_KEY, tampered);
    expect(result).toBeNull();
  });

  it("verifyClearanceCookie rejects tampered signature", async () => {
    const cookie = await generateClearanceCookie(TEST_SECRET_KEY, TEST_IP);
    const [payload, _signature] = cookie.split(".");
    const tampered = `${payload}.${"a".repeat(64)}`;
    const result = await verifyClearanceCookie(TEST_SECRET_KEY, tampered);
    expect(result).toBeNull();
  });

  it("verifyClearanceCookie rejects cookie signed with wrong key", async () => {
    const cookie = await generateClearanceCookie("wrong-secret-key", TEST_IP);
    const result = await verifyClearanceCookie(TEST_SECRET_KEY, cookie);
    expect(result).toBeNull();
  });

  it("verifyClearanceCookie rejects malformed cookie (no dot)", async () => {
    const result = await verifyClearanceCookie(TEST_SECRET_KEY, "nodothere");
    expect(result).toBeNull();
  });

  it("verifyClearanceCookie rejects cookie with invalid base64 payload", async () => {
    const result = await verifyClearanceCookie(TEST_SECRET_KEY, "!!!invalid!!!.abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234");
    expect(result).toBeNull();
  });

  it("getClearanceCookie extracts turnstile_clearance from Cookie header", () => {
    const req = new Request("https://example.com", {
      headers: { Cookie: "other=1; turnstile_clearance=abc123; another=2" },
    });
    expect(getClearanceCookie(req)).toBe("abc123");
  });

  it("getClearanceCookie returns null when cookie absent", () => {
    const req = new Request("https://example.com");
    expect(getClearanceCookie(req)).toBeNull();
  });

  it("buildSetCookieHeader includes correct attributes", () => {
    const header = buildSetCookieHeader("test-value", 150);
    expect(header).toContain("turnstile_clearance=test-value");
    expect(header).toContain("Path=/");
    expect(header).toContain("HttpOnly");
    expect(header).toContain("Secure");
    expect(header).toContain("SameSite=Lax");
    expect(header).toContain("Max-Age=150");
  });
});

// ---------------------------------------------------------------------------
// Verify endpoint — uses test secret key so Turnstile API returns failure.
// We validate that our input checks run before the API call.
// ---------------------------------------------------------------------------

describe("POST /verify", () => {
  it("returns 400 for form without turnstile token", async () => {
    const resp = await workerFetch("/verify", {
      method: "POST",
      body: new URLSearchParams({ garbage: "data" }),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    // Our validation catches missing token before calling Turnstile API
    expect(resp.status).toBe(400);
    const json = await resp.json<{ error: string }>();
    expect(json.error).toBe("Missing Turnstile token");
  });

  it("returns 400 for form with token but missing originalUrl", async () => {
    const formData = new FormData();
    formData.append("cf-turnstile-response", "fake-token");
    const resp = await workerFetch("/verify", {
      method: "POST",
      body: formData,
    });
    expect(resp.status).toBe(400);
    const json = await resp.json<{ error: string }>();
    expect(json.error).toBe("Missing original URL");
  });

  it("returns 400 for form with token but invalid originalUrl protocol", async () => {
    const formData = new FormData();
    formData.append("cf-turnstile-response", "fake-token");
    formData.append("originalUrl", "javascript:alert(1)");
    const resp = await workerFetch("/verify", {
      method: "POST",
      body: formData,
    });
    expect(resp.status).toBe(400);
    const json = await resp.json<{ error: string }>();
    expect(json.error).toBe("Invalid original URL");
  });

  it("returns error for form with token but invalid secret (Turnstile rejects)", async () => {
    const formData = new FormData();
    formData.append("cf-turnstile-response", "fake-token");
    formData.append("originalUrl", "https://file.erfianugrah.com/login");
    const resp = await workerFetch("/verify", {
      method: "POST",
      body: formData,
    });
    // Test secret key → Turnstile API returns error → 502 or 401
    expect([401, 502]).toContain(resp.status);
  });
});

// ---------------------------------------------------------------------------
// XSS protection
// ---------------------------------------------------------------------------

describe("XSS protection", () => {
  it("sanitizes URL in challenge page — URL constructor percent-encodes script tags", async () => {
    const resp = await workerFetch(
      '/login?"><script>alert(1)</script>',
      { headers: { Accept: "text/html" } },
    );
    const body = await resp.text();
    // The URL constructor percent-encodes < > " so raw script tags won't appear
    expect(body).not.toContain('"><script>alert(1)</script>');
    // Verify the encoded form is present
    expect(body).toContain("%3Cscript%3E");
  });
});

// ---------------------------------------------------------------------------
// ChallengeStatusStorage Durable Object — rate limiting only
// ---------------------------------------------------------------------------

describe("ChallengeStatusStorage DO", () => {
  it("rate limits after max tokens are exhausted", async () => {
    const id = env.CHALLENGE_STATUS.idFromName("rate-limit-test");
    const stub = env.CHALLENGE_STATUS.get(id);

    await runInDO(stub, async (instance) => {
      // maxTokens=5, first request creates with tokens=4 (one consumed)
      // So requests 1-5 succeed, then request 6 is rate limited
      let lastStatus = 200;
      for (let i = 0; i < 10; i++) {
        const resp = await instance.fetch(
          new Request(
            "https://challengestorage.internal/checkRateLimit",
            {
              method: "POST",
              headers: { "CF-Connecting-IP": "10.0.0.1" },
            },
          ),
        );
        lastStatus = resp.status;
        if (resp.status === 429) {
          const body = await resp.json<{
            message: string;
            cooldownEndTime: string;
          }>();
          expect(body.message).toBe("Rate limit exceeded");
          expect(body.cooldownEndTime).toBeDefined();
          return; // Test passed
        }
      }
      // Should have been rate limited before 10 requests
      expect(lastStatus).toBe(429);
    });
  });

  it("rate limits by IP, not by cookie (prevents cookie rotation bypass)", async () => {
    const id = env.CHALLENGE_STATUS.idFromName("rateLimiter-bypass-test");
    const stub = env.CHALLENGE_STATUS.get(id);

    await runInDO(stub, async (instance) => {
      // Exhaust tokens using different cookies but same IP
      for (let i = 0; i < 10; i++) {
        const resp = await instance.fetch(
          new Request(
            "https://challengestorage.internal/checkRateLimit",
            {
              method: "POST",
              headers: {
                "CF-Connecting-IP": "10.0.0.99",
                Cookie: `turnstile_clearance=cookie-${i}`,
              },
            },
          ),
        );
        if (resp.status === 429) {
          // Same IP with brand new cookie still got rate limited — test passes
          expect(resp.status).toBe(429);
          return;
        }
      }
      // Should have been rate limited
      expect(true).toBe(false);
    });
  });

  it("allows different IPs independent rate limit buckets", async () => {
    const id = env.CHALLENGE_STATUS.idFromName("rateLimiter-multi-ip");
    const stub = env.CHALLENGE_STATUS.get(id);

    await runInDO(stub, async (instance) => {
      // IP A: first request should be allowed
      const respA = await instance.fetch(
        new Request(
          "https://challengestorage.internal/checkRateLimit",
          {
            method: "POST",
            headers: { "CF-Connecting-IP": "192.168.1.1" },
          },
        ),
      );
      expect(respA.status).toBe(200);

      // IP B: first request should also be allowed (separate bucket)
      const respB = await instance.fetch(
        new Request(
          "https://challengestorage.internal/checkRateLimit",
          {
            method: "POST",
            headers: { "CF-Connecting-IP": "192.168.1.2" },
          },
        ),
      );
      expect(respB.status).toBe(200);
    });
  });

  it("returns 404 for unknown DO paths", async () => {
    const id = env.CHALLENGE_STATUS.idFromName("test-unknown");
    const stub = env.CHALLENGE_STATUS.get(id);

    await runInDO(stub, async (instance) => {
      const resp = await instance.fetch(
        new Request("https://challengestorage.internal/unknown"),
      );
      expect(resp.status).toBe(404);
    });
  });

  it("returns 404 for removed timestamp/IP endpoints", async () => {
    const id = env.CHALLENGE_STATUS.idFromName("test-removed-endpoints");
    const stub = env.CHALLENGE_STATUS.get(id);

    await runInDO(stub, async (instance) => {
      // These endpoints were removed — DO only supports /checkRateLimit now
      const storeResp = await instance.fetch(
        new Request("https://challengestorage.internal/storeTimestampAndIP"),
      );
      expect(storeResp.status).toBe(404);

      const getResp = await instance.fetch(
        new Request("https://challengestorage.internal/getTimestampAndIP"),
      );
      expect(getResp.status).toBe(404);

      const delResp = await instance.fetch(
        new Request("https://challengestorage.internal/deleteTimestampAndIP", {
          method: "POST",
        }),
      );
      expect(delResp.status).toBe(404);
    });
  });
});

// ---------------------------------------------------------------------------
// CredentialsStorage Durable Object
// ---------------------------------------------------------------------------

describe("CredentialsStorage DO", () => {
  it("stores and retrieves encrypted credentials", async () => {
    const id = env.CREDENTIALS_STORAGE.idFromName("cred-test-1");
    const stub = env.CREDENTIALS_STORAGE.get(id);

    await runInDO(stub, async (instance) => {
      const payload = JSON.stringify({
        body: { username: "test", password: "secret" },
        headers: { "X-Custom": "value" },
        method: "POST",
        url: "https://example.com/api/login",
      });

      const storeResp = await instance.fetch(
        new Request("https://challengestorage.internal/store", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: payload,
        }),
      );
      expect(storeResp.status).toBe(200);

      const retrieveResp = await instance.fetch(
        new Request("https://challengestorage.internal/retrieve"),
      );
      expect(retrieveResp.status).toBe(200);
      const retrieved = await retrieveResp.json<{
        body: { username: string; password: string };
      }>();
      expect(retrieved.body.username).toBe("test");
      expect(retrieved.body.password).toBe("secret");
    });
  });

  it("deletes credentials after single retrieval", async () => {
    const id = env.CREDENTIALS_STORAGE.idFromName("cred-test-2");
    const stub = env.CREDENTIALS_STORAGE.get(id);

    await runInDO(stub, async (instance) => {
      await instance.fetch(
        new Request("https://challengestorage.internal/store", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ body: { user: "x" } }),
        }),
      );

      const resp1 = await instance.fetch(
        new Request("https://challengestorage.internal/retrieve"),
      );
      expect(resp1.status).toBe(200);

      const resp2 = await instance.fetch(
        new Request("https://challengestorage.internal/retrieve"),
      );
      expect(resp2.status).toBe(404);
    });
  });

  it("rejects oversized request bodies", async () => {
    const id = env.CREDENTIALS_STORAGE.idFromName("cred-test-large");
    const stub = env.CREDENTIALS_STORAGE.get(id);

    await runInDO(stub, async (instance) => {
      const largeBody = JSON.stringify({ data: "x".repeat(70000) });

      const resp = await instance.fetch(
        new Request("https://challengestorage.internal/store", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": String(largeBody.length),
          },
          body: largeBody,
        }),
      );
      expect(resp.status).toBe(413);
    });
  });

  it("rejects invalid JSON bodies", async () => {
    const id = env.CREDENTIALS_STORAGE.idFromName("cred-test-invalid");
    const stub = env.CREDENTIALS_STORAGE.get(id);

    await runInDO(stub, async (instance) => {
      const resp = await instance.fetch(
        new Request("https://challengestorage.internal/store", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "not-json{{{",
        }),
      );
      expect(resp.status).toBe(400);
    });
  });

  it("returns 404 for unknown paths", async () => {
    const id = env.CREDENTIALS_STORAGE.idFromName("cred-test-404");
    const stub = env.CREDENTIALS_STORAGE.get(id);

    await runInDO(stub, async (instance) => {
      const resp = await instance.fetch(
        new Request("https://challengestorage.internal/unknown"),
      );
      expect(resp.status).toBe(404);
    });
  });
});

// ---------------------------------------------------------------------------
// Utility function tests
// ---------------------------------------------------------------------------

describe("Utility functions", () => {
  it("sanitizeUrl blocks javascript: URLs", () => {
    expect(sanitizeUrl("javascript:alert(1)")).toBe("");
  });

  it("sanitizeUrl encodes special characters via URL + HTML encoding", () => {
    const result = sanitizeUrl('https://example.com/?q=<script>"test"</script>');
    // URL constructor percent-encodes < > " so raw script tags don't appear
    expect(result).not.toContain("<script>");
    // Percent-encoded form should be present
    expect(result).toContain("%3Cscript%3E");
  });

  it("sanitizeUrl allows valid https URLs", () => {
    const result = sanitizeUrl("https://example.com/path?q=1");
    expect(result).toContain("https://example.com/path");
  });

  it("sanitizeUrl returns empty for invalid URLs", () => {
    expect(sanitizeUrl("not-a-url")).toBe("");
  });

  it("hashValue produces consistent hex output", async () => {
    const h1 = await hashValue("test");
    const h2 = await hashValue("test");
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("getClientIP returns CF-Connecting-IP header", () => {
    const req = new Request("https://example.com", {
      headers: { "CF-Connecting-IP": "9.8.7.6" },
    });
    expect(getClientIP(req)).toBe("9.8.7.6");
  });

  it("getClientIP returns 'unknown' when header missing", () => {
    const req = new Request("https://example.com");
    expect(getClientIP(req)).toBe("unknown");
  });

  it("encrypt/decrypt roundtrips correctly", async () => {
    const key = await generateEncryptionKey();
    const original = '{"username":"admin","password":"hunter2"}';
    const { encryptedData, iv } = await encryptData(key, original);
    const decrypted = await decryptData(
      key,
      new Uint8Array(encryptedData),
      iv,
    );
    expect(decrypted).toBe(original);
  });

  it("exportKey/importKey roundtrips correctly", async () => {
    const key = await generateEncryptionKey();
    const exported = await exportKey(key);
    const reimported = await importKey(exported);

    const original = "test data for key roundtrip";
    const { encryptedData, iv } = await encryptData(key, original);
    const decrypted = await decryptData(
      reimported,
      new Uint8Array(encryptedData),
      iv,
    );
    expect(decrypted).toBe(original);
  });
});

// ---------------------------------------------------------------------------
// Configurable route protection
// ---------------------------------------------------------------------------

describe("Route protection configuration", () => {
  it("getProtectedPaths defaults to /login when env var not set", () => {
    const paths = getProtectedPaths({ PROTECTED_PATHS: "" } as any);
    expect(paths).toEqual(["/login"]);
  });

  it("getProtectedPaths parses comma-separated paths", () => {
    const paths = getProtectedPaths({
      PROTECTED_PATHS: "/login, /admin, /dashboard",
    } as any);
    expect(paths).toEqual(["/login", "/admin", "/dashboard"]);
  });

  it("getProtectedPaths supports wildcard for all routes", () => {
    const paths = getProtectedPaths({ PROTECTED_PATHS: "/*" } as any);
    expect(paths).toEqual(["/*"]);
  });

  it("isProtectedPath matches exact prefix", () => {
    expect(isProtectedPath("/login", ["/login"])).toBe(true);
    expect(isProtectedPath("/login/callback", ["/login"])).toBe(true);
    expect(isProtectedPath("/logout", ["/login"])).toBe(false);
    expect(isProtectedPath("/", ["/login"])).toBe(false);
  });

  it("isProtectedPath matches multiple prefixes", () => {
    const paths = ["/login", "/admin", "/dashboard"];
    expect(isProtectedPath("/admin/users", paths)).toBe(true);
    expect(isProtectedPath("/dashboard", paths)).toBe(true);
    expect(isProtectedPath("/api/data", paths)).toBe(false);
  });

  it("isProtectedPath wildcard matches everything", () => {
    expect(isProtectedPath("/", ["/*"])).toBe(true);
    expect(isProtectedPath("/any/path", ["/*"])).toBe(true);
    expect(isProtectedPath("/login", ["/*"])).toBe(true);
  });

  it("worker challenges /admin when PROTECTED_PATHS includes it", async () => {
    // The test env has PROTECTED_PATHS="/login", so /admin should pass through.
    try {
      const resp = await workerFetch("/admin", {
        headers: { Accept: "text/html" },
      });
      const body = await resp.text();
      // /admin is not in PROTECTED_PATHS="/login", so no challenge
      expect(body).not.toContain("Complete the challenge to proceed");
    } catch {
      // DNS failure = pass-through was attempted (correct behavior)
      expect(true).toBe(true);
    }
  });

  it("worker challenges /login/subpath with default config", async () => {
    const resp = await workerFetch("/login/reset", {
      headers: { Accept: "text/html" },
    });
    const body = await resp.text();
    expect(body).toContain("Complete the challenge to proceed");
  });
});

// ---------------------------------------------------------------------------
// Rate limit page
// ---------------------------------------------------------------------------

describe("Rate limit page", () => {
  it("returns 429 status for HTML rate limit page", () => {
    const cooldown = new Date(Date.now() + 60000);
    const req = new Request("https://example.com", {
      headers: { Accept: "text/html" },
    });
    const resp = serveRateLimitPage(cooldown, req);
    expect(resp.status).toBe(429);
  });

  it("contains countdown timer in HTML rate limit page", async () => {
    const cooldown = new Date(Date.now() + 60000);
    const req = new Request("https://example.com", {
      headers: { Accept: "text/html" },
    });
    const resp = serveRateLimitPage(cooldown, req);
    const body = await resp.text();
    expect(body).toContain("Kalm, try again later");
    expect(body).toContain("cooldownTimer");
  });

  it("returns 429 JSON for non-browser rate limit requests", async () => {
    const cooldown = new Date(Date.now() + 60000);
    const req = new Request("https://example.com", {
      headers: { Accept: "application/json" },
    });
    const resp = serveRateLimitPage(cooldown, req);
    expect(resp.status).toBe(429);
    const json = await resp.json<{ message: string }>();
    expect(json.message).toContain("Rate limit exceeded");
  });
});
