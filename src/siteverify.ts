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

export async function verifyChallenge(
  request: Request,
  env: Env,
): Promise<Response> {
  let body: FormData;
  try {
    body = await request.formData();
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid form data" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  const token = body.get("cf-turnstile-response");
  if (!token || typeof token !== "string") {
    return new Response(
      JSON.stringify({ error: "Missing Turnstile token" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  const originalUrl = body.get("originalUrl");
  if (!originalUrl || typeof originalUrl !== "string") {
    return new Response(
      JSON.stringify({ error: "Missing original URL" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
  }

  // Validate originalUrl is a valid http(s) URL
  try {
    const parsed = new URL(originalUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("Invalid protocol");
    }
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid original URL" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    );
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
      return new Response(
        JSON.stringify({ error: "Challenge verification service unavailable" }),
        { status: 502, headers: { "Content-Type": "application/json" } },
      );
    }

    outcome = await result.json<TurnstileResponse>();
  } catch (err) {
    console.error(`Turnstile verification fetch failed: ${err}`);
    return new Response(
      JSON.stringify({ error: "Challenge verification service unavailable" }),
      { status: 502, headers: { "Content-Type": "application/json" } },
    );
  }

  if (outcome.success !== true) {
    const errorCodes = outcome["error-codes"]?.join(", ") ?? "unknown";
    console.error(`Turnstile verification failed: ${errorCodes}`);
    return new Response("The provided Turnstile token was not valid!", {
      status: 401,
    });
  }

  return Response.redirect(originalUrl, 302);
}
