import { getClientIP } from "./utils";
import type { Env } from "./types";

interface TurnstileResponse {
  success: boolean;
  "error-codes"?: string[];
  challenge_ts?: string;
  hostname?: string;
  action?: string;
  cdata?: string;
}

export interface VerifyResult {
  success: boolean;
  originalUrl: string | null;
  error?: string;
  status: number;
}

/**
 * Validate the Turnstile token via Cloudflare's siteverify API.
 * Returns a structured result instead of a raw Response, so the caller
 * can attach a Set-Cookie header on success.
 */
export async function verifyChallenge(
  request: Request,
  env: Env,
): Promise<VerifyResult> {
  let body: FormData;
  try {
    body = await request.formData();
  } catch {
    return { success: false, originalUrl: null, error: "Invalid form data", status: 400 };
  }

  const token = body.get("cf-turnstile-response");
  if (!token || typeof token !== "string") {
    return { success: false, originalUrl: null, error: "Missing Turnstile token", status: 400 };
  }

  const originalUrl = body.get("originalUrl");
  if (!originalUrl || typeof originalUrl !== "string") {
    return { success: false, originalUrl: null, error: "Missing original URL", status: 400 };
  }

  // Validate originalUrl is a valid http(s) URL
  try {
    const parsed = new URL(originalUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("Invalid protocol");
    }
  } catch {
    return { success: false, originalUrl: null, error: "Invalid original URL", status: 400 };
  }

  const ip = getClientIP(request);

  const formData = new FormData();
  formData.append("secret", env.SECRET_KEY);
  formData.append("response", token);
  formData.append("remoteip", ip);

  let outcome: TurnstileResponse;
  try {
    const result = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      { body: formData, method: "POST" },
    );

    if (!result.ok) {
      console.error(`Turnstile API returned status ${result.status}`);
      return {
        success: false,
        originalUrl,
        error: "Challenge verification service unavailable",
        status: 502,
      };
    }

    outcome = await result.json<TurnstileResponse>();
  } catch (err) {
    console.error(`Turnstile verification fetch failed: ${err}`);
    return {
      success: false,
      originalUrl,
      error: "Challenge verification service unavailable",
      status: 502,
    };
  }

  if (outcome.success !== true) {
    const errorCodes = outcome["error-codes"]?.join(", ") ?? "unknown";
    console.error(`Turnstile verification failed: ${errorCodes}`);
    return {
      success: false,
      originalUrl,
      error: "The provided Turnstile token was not valid!",
      status: 401,
    };
  }

  return { success: true, originalUrl, status: 302 };
}
