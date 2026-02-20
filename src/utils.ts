export async function hashValue(value: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function generateEncryptionKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  ) as Promise<CryptoKey>;
}

export async function exportKey(key: CryptoKey): Promise<number[]> {
  const raw = await crypto.subtle.exportKey("raw", key) as ArrayBuffer;
  return Array.from(new Uint8Array(raw));
}

export async function importKey(rawKey: number[]): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new Uint8Array(rawKey).buffer as ArrayBuffer,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

export async function encryptData(
  key: CryptoKey,
  data: string,
): Promise<{ encryptedData: ArrayBuffer; iv: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  const encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encodedData,
  );

  return { encryptedData, iv };
}

export async function decryptData(
  key: CryptoKey,
  encryptedData: Uint8Array,
  iv: Uint8Array,
): Promise<string> {
  const decryptedData = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    encryptedData,
  );

  return new TextDecoder().decode(decryptedData);
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

const COOKIE_NAME = "turnstile_clearance";

/**
 * Extract the turnstile_clearance cookie value from a request.
 */
export function getClearanceCookie(request: Request): string | null {
  const cookies = request.headers.get("Cookie");
  const re = new RegExp(`${COOKIE_NAME}=([^;]+)`);
  const matches = cookies?.match(re);
  return matches ? matches[1] : null;
}

/**
 * Create an HMAC-SHA256 signature for the given payload using the secret key.
 */
async function hmacSign(secret: string, payload: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Verify an HMAC-SHA256 signature using timing-safe comparison.
 */
async function hmacVerify(
  secret: string,
  payload: string,
  signature: string,
): Promise<boolean> {
  const expected = await hmacSign(secret, payload);
  if (expected.length !== signature.length) return false;
  // Timing-safe comparison via subtle.timingSafeEqual is not available in
  // all Workers runtimes, so we use a constant-time compare.
  const encoder = new TextEncoder();
  const a = encoder.encode(expected);
  const b = encoder.encode(signature);
  if (a.byteLength !== b.byteLength) return false;
  // crypto.subtle.timingSafeEqual is available in workerd
  const aBuffer = a.buffer.slice(a.byteOffset, a.byteOffset + a.byteLength) as ArrayBuffer;
  const bBuffer = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
  try {
    return crypto.subtle.timingSafeEqual(aBuffer, bBuffer);
  } catch {
    // Fallback: constant-time XOR compare
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }
}

export interface ClearancePayload {
  ip: string;
  timestamp: number;
}

/**
 * Generate a signed clearance cookie value: base64(json payload).signature
 */
export async function generateClearanceCookie(
  secretKey: string,
  ip: string,
): Promise<string> {
  const payload: ClearancePayload = {
    ip,
    timestamp: Date.now(),
  };
  const payloadStr = btoa(JSON.stringify(payload));
  const signature = await hmacSign(secretKey, payloadStr);
  return `${payloadStr}.${signature}`;
}

/**
 * Parse and verify a clearance cookie value. Returns the payload if valid, null otherwise.
 */
export async function verifyClearanceCookie(
  secretKey: string,
  cookieValue: string,
): Promise<ClearancePayload | null> {
  const dotIndex = cookieValue.lastIndexOf(".");
  if (dotIndex === -1) return null;

  const payloadStr = cookieValue.substring(0, dotIndex);
  const signature = cookieValue.substring(dotIndex + 1);

  const valid = await hmacVerify(secretKey, payloadStr, signature);
  if (!valid) return null;

  try {
    const payload: ClearancePayload = JSON.parse(atob(payloadStr));
    if (
      typeof payload.ip !== "string" ||
      typeof payload.timestamp !== "number"
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

/**
 * Build a Set-Cookie header value for the clearance cookie.
 */
export function buildSetCookieHeader(
  cookieValue: string,
  maxAgeSec: number,
): string {
  return `${COOKIE_NAME}=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;
}

export function getClientIP(request: Request): string {
  return request.headers.get("CF-Connecting-IP") ?? "unknown";
}

/**
 * Sanitize a URL string to prevent XSS injection in HTML templates.
 * Only allows http/https URLs and HTML-encodes special characters.
 */
export function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return parsed.href
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;");
  } catch {
    return "";
  }
}
