import { hashValue, generateEncryptionKey, encryptData, decryptData, getCfClearanceValue} from './utils.js'
import {serveRateLimitPage, serveChallengePage } from './staticpages.js'

export class ChallengeStatusStorage {
  constructor(state, env) {
    this.state = state;
    this.rateLimit = { maxTokens: 5, refillRate: 5, refillTime: 60000 }; // 5 tokens per minute
  }

  async fetch(request) {
    const url = new URL(request.url);
    try {
      switch (url.pathname) {
        case "/getTimestampAndIP":
          const data = await this.state.storage.get("timestampAndIP");
          if (!data) {
            throw new Error("No data found");
          }
          return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });

        case "/storeTimestampAndIP":
          const clientIP = request.headers.get('CF-Connecting-IP');
          const timestampAndIP = { timestamp: Date.now(), ip: clientIP };
          await this.state.storage.put("timestampAndIP", timestampAndIP);
          return new Response("Timestamp and IP stored");

        case "/deleteTimestampAndIP":
          await this.state.storage.delete("timestampAndIP");
          return new Response("Timestamp and IP deleted", { status: 200 });

        case "/checkRateLimit":
          return this.checkRateLimit(request);

        default:
          return new Response("Not found", { status: 404 });
      }
    } catch (error) {
      console.error(`Error handling request: ${error.message}`);
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  }

  async checkRateLimit(request) {
    const clientIP = request.headers.get('CF-Connecting-IP');
    const cfClearanceMatch = await getCfClearanceValue(request);
    if (!cfClearanceMatch) {
      return new Response("cf_clearance cookie is missing", { status: 400 });
    }
    const cfClearance = cfClearanceMatch[1];
    const identifier = `${clientIP}-${cfClearance}`;

    let rateLimitInfo = await this.state.storage.get(identifier);
    if (!rateLimitInfo) {
      rateLimitInfo = { tokens: this.rateLimit.maxTokens, lastRefill: Date.now() };
    } else {
      rateLimitInfo = JSON.parse(rateLimitInfo);
      const timeSinceLastRefill = Date.now() - rateLimitInfo.lastRefill;
      const tokensToAdd = Math.floor(timeSinceLastRefill / this.rateLimit.refillTime) * this.rateLimit.refillRate;
      if (tokensToAdd > 0) { // Only update lastRefill if tokens are actually added
        rateLimitInfo.tokens = Math.min(rateLimitInfo.tokens + tokensToAdd, this.rateLimit.maxTokens);
        rateLimitInfo.lastRefill = Date.now(); // Update lastRefill only here
      }
    }

    if (rateLimitInfo.tokens > 0) {
      rateLimitInfo.tokens--;
      await this.state.storage.put(identifier, JSON.stringify(rateLimitInfo));
      return new Response("Allowed", { status: 200 });
    } else {
      // Calculate the cooldown end time based on the last refill time and refill rate
      const cooldownEndTime = new Date(rateLimitInfo.lastRefill + this.rateLimit.refillTime).toISOString();
      const body = JSON.stringify({ message: "Rate limit exceeded", cooldownEndTime });
      return new Response(body, { status: 429, headers: { 'Content-Type': 'application/json' } });
    }
  }

}


export class CredentialsStorage {
  constructor(state, env) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const key = await generateEncryptionKey(); // Generate a new key for each operation

    if (url.pathname === "/store") {
      const details = await request.json();
      const { encryptedData, iv } = await encryptData(key, JSON.stringify(details));
      await this.state.storage.put("encryptedCredentials", JSON.stringify({ encryptedData: Array.from(new Uint8Array(encryptedData)), iv: Array.from(iv) }));
      return new Response("Credentials stored", { status: 200 });
    } else if (url.pathname === "/retrieve") {
      const { encryptedData, iv } = JSON.parse(await this.state.storage.get("encryptedCredentials"));
      const decryptedData = await decryptData(key, new Uint8Array(encryptedData), new Uint8Array(iv));
      await this.state.storage.delete("encryptedCredentials");
      return new Response(decryptedData, { status: 200 });
    }
    return new Response("Not found", { status: 404 });
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // Correctly await the asynchronous call to getCfClearanceValue
    const cfClearanceValue = await getCfClearanceValue(request);

    if (/^\/login/.test(url.pathname)) {
      return handleLoginRequest(request, env, cfClearanceValue);
    }

    if (/^\/verify/.test(url.pathname) && request.method === "POST") {
      return handleVerifyRequest(request, env, cfClearanceValue);
    }

    return fetch(request);
  }
};


async function getCfClearanceValue(request) {
  const cookies = request.headers.get('Cookie');
  const matches = cookies?.match(/cf_clearance=([^;]+)/);
  return matches ? matches[1] : null;
}

async function handleLoginRequest(request, env) {
  const url = new URL(request.url);
  // Use the existing function to get the cf_clearance value
  const cfClearance = await getCfClearanceValue(request);

  // Extract client IP for rate limiting check
  const clientIP = request.headers.get('CF-Connecting-IP');

  // Ensure cfClearance is available before proceeding
  if (!cfClearance) {
    return new Response("cf_clearance cookie is missing", { status: 400 });
  }

  // Use the refactored function to perform the rate limit check
  const rateLimitCheck = await checkRateLimit(env, clientIP, cfClearance);
  if (rateLimitCheck.status === 429) {
    // Correctly parse the JSON body to get the cooldownEndTime
    const responseBody = await rateLimitCheck.json();
    const cooldownEndTime = new Date(responseBody.cooldownEndTime);
    const now = new Date();

    // If the cooldown period has ended, serve the challenge page to get a new cookie
    if (now > cooldownEndTime) {
      return serveChallengePage(env, request);
    } else {
      // If still within the cooldown period, serve the rate limit page
      return serveRateLimitPage(cooldownEndTime, request);
    }
  }

  // Proceed with the login request handling
  if (request.method === "GET") {
    return handleGetLogin(request, env, cfClearance);
  } else if (url.pathname === "/api/login" && request.method === "POST") {
    return handlePostLogin(request, env, cfClearance);
  }
}


async function handleGetLogin(request, env, cfClearanceValue) {
  const isVerified = await verifyChallengeStatus(request, env, cfClearanceValue);
  if (isVerified) {
    return fetch(request);
  }
  return serveChallengePage(env, request);
}


async function handlePostLogin(request, env, cfClearanceValue) {
  const isVerified = await verifyChallengeStatus(request, env, cfClearanceValue);
  if (!isVerified) {
    return serveChallengePage(env, request);
  }

  // Proceed with storing the login attempt details since the challenge is verified
  const requestBody = await request.json();
  const requestHeaders = Object.fromEntries([...request.headers].filter(([key]) => !["host", "cookie", "content-length"].includes(key.toLowerCase())));
  const loginAttemptId = crypto.randomUUID();

  const storage = env.CREDENTIALS_STORAGE.get(env.CREDENTIALS_STORAGE.idFromName(loginAttemptId));
  await storage.fetch("https://challengestorage.internal/store", {
    method: "POST",
    body: JSON.stringify({ body: requestBody, headers: requestHeaders, method: request.method, url: request.url })
  });

  // Optionally, you might want to redirect the user or take another action after storing the details
  return new Response("Login attempt stored. Please complete the challenge if required.", { status: 200 });
}


async function handleVerifyRequest(request, env, cfClearanceValue) {
  const response = await verifyChallenge(request, env);
  if (response.status === 302 && cfClearanceValue) {
    const challengeStatusStorage = await getChallengeStatusStorage(env, cfClearanceValue);
    await challengeStatusStorage.fetch(new Request("https://challengestorage.internal/storeTimestampAndIP", { headers: { 'CF-Connecting-IP': request.headers.get('CF-Connecting-IP') } }));
  }
  return response;
}

async function getChallengeStatusStorage(env, cfClearanceValue) {
  const hashedCfClearanceValue = await hashValue(cfClearanceValue);
  console.log(hashedCfClearanceValue)
  const challengeStatusStorageId = env.CHALLENGE_STATUS.idFromName(hashedCfClearanceValue);
  console.log(challengeStatusStorageId)
  return env.CHALLENGE_STATUS.get(challengeStatusStorageId);
}

async function verifyChallengeStatus(request, env, cfClearanceValue) {
  try {
    if (!cfClearanceValue) {
      throw new Error("cf_clearance cookie is not present");
    }

    const challengeStatusStorage = await getChallengeStatusStorage(env, cfClearanceValue);
    const dataResponse = await challengeStatusStorage.fetch(new Request("https://challengestorage.internal/getTimestampAndIP"));

    if (!dataResponse.ok) {
      throw new Error("Unable to retrieve challenge status");
    }

    const data = await dataResponse.json();
    const currentTime = Date.now();
    const timeDifference = currentTime - parseInt(data.timestamp, 10);
    const isTimestampValid = timeDifference < 150000; // 2.5 minutes
    const isIPMatching = data.ip === request.headers.get('CF-Connecting-IP');

    if (!isTimestampValid || !isIPMatching) {
      await challengeStatusStorage.fetch(new Request("https://challengestorage.internal/deleteTimestampAndIP"), { method: "POST" });
      throw new Error("Challenge verification failed");
    }

    return true;
  } catch (error) {
    console.error(`Verification error: ${error.message}`);
    return false;
  }
}

async function checkRateLimit(env, clientIP, cfClearance) {
  // Construct a request for the rate limit check
  const rateLimitRequest = new Request("https://challengestorage.internal/checkRateLimit", {
    method: "POST",
    headers: new Headers({
      'CF-Connecting-IP': clientIP,
      'Cookie': `cf_clearance=${cfClearance}`
    })
  });

  // Perform the rate limit check
  const rateLimitCheck = await env.CHALLENGE_STATUS.get(env.CHALLENGE_STATUS.idFromName("rateLimiter")).fetch(rateLimitRequest);
  console.log('Rate limit check status:', rateLimitCheck.status);

  return rateLimitCheck;
}



async function verifyChallenge(request, env) {
  const body = await request.formData();
  const token = body.get('cf-turnstile-response');
  const ip = request.headers.get('CF-Connecting-IP');
  const originalUrl = body.get('originalUrl')

  // Validate the token by calling the "/siteverify" API.
  let formData = new FormData();
  formData.append('secret', env.SECRET_KEY);
  formData.append('response', token);
  formData.append('remoteip', ip);


  const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    body: formData,
    method: 'POST',
  });

  const outcome = await result.json();
  console.log(JSON.stringify(outcome)); // This will log the full response body as a string
  if (!outcome.success) {
    // Handle verification failure
    return new Response('The provided Turnstile token was not valid!', { status: 401 });
  }

  // Redirect the user to the decoded original URL upon successful verification
  return Response.redirect(originalUrl, 302);
}