/**
 * Hashes a value using SHA-256
 * 
 * @param {string} value - Value to hash
 * @returns {Promise<string>} Hexadecimal hash of the value
 */
export async function hashValue(value) {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join(
    "",
  );
  return hashHex;
}

/**
 * Derive an encryption key from a stable seed and salt
 * 
 * @param {Object} env - Environment object with SECRET_KEY
 * @param {string} identifier - Identifier for this key
 * @returns {Promise<CryptoKey>} Derived encryption key
 */
export async function generateEncryptionKey(env, identifier = "default") {
  // Use a fixed salt for each identifier to ensure we generate the same key each time
  const salt = new TextEncoder().encode(`turnstile-salt-${identifier}`);
  
  // Use the provided secret key as a seed to derive our encryption key
  // This ensures we can regenerate the same key in different instances
  const secretKeyData = new TextEncoder().encode(env.SECRET_KEY);
  
  // First create a key from the secret
  const baseKey = await crypto.subtle.importKey(
    "raw",
    secretKeyData,
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
  
  // Then derive the actual encryption key using PBKDF2
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  
  return key;
}

/**
 * Encrypts data using AES-GCM
 * 
 * @param {CryptoKey} key - Encryption key
 * @param {string} data - Data to encrypt
 * @returns {Promise<Object>} Encrypted data and IV
 */
export async function encryptData(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM requires a 12-byte IV
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  const encryptedData = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    encodedData,
  );

  return { encryptedData, iv };
}

/**
 * Decrypts data using AES-GCM
 * 
 * @param {CryptoKey} key - Decryption key
 * @param {ArrayBuffer} encryptedData - Encrypted data
 * @param {Uint8Array} iv - Initialization vector
 * @returns {Promise<string>} Decrypted data
 */
export async function decryptData(key, encryptedData, iv) {
  try {
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      key,
      encryptedData,
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedData);
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

/**
 * Extracts the cf_clearance cookie value from a request
 * 
 * @param {Request} request - HTTP request
 * @returns {Promise<RegExpMatchArray|null>} Match result with the cookie value
 */
export async function getCfClearanceValue(request) {
  const cookies = request.headers.get("Cookie");
  const matches = cookies?.match(/cf_clearance=([^;]+)/);
  return matches;
}

/**
 * Gets the client IP address from a request
 * 
 * @param {Request} request - HTTP request
 * @returns {string} Client IP address
 */
export function getClientIP(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}