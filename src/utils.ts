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

export function getCfClearanceValue(request: Request): string | null {
  const cookies = request.headers.get("Cookie");
  const matches = cookies?.match(/cf_clearance=([^;]+)/);
  return matches ? matches[1] : null;
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
