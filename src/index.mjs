import {
  decryptData,
  encryptData,
  generateEncryptionKey,
  getCfClearanceValue,
  getClientIP,
  hashValue,
} from "./utils.js";
import { serveChallengePage, serveRateLimitPage } from "./staticpages.js";
import { verifyChallenge } from "./siteverify.js";

class BaseStorage {
  constructor(state) {
    this.state = state;
  }

  async cleanupExpiredData(expirationTime) {
    const keys = await this.state.storage.list();
    const currentTime = Date.now();

    for (const key of keys) {
      const data = JSON.parse(await this.state.storage.get(key));
      if (
        data && data.lastAccess &&
        currentTime - data.lastAccess > expirationTime
      ) {
        await this.state.storage.delete(key);
      }
    }
  }
}

export class ChallengeStatusStorage extends BaseStorage {
  constructor(state, env) {
    super(state); // Correctly calling super constructor
    this.env = env;
    this.rateLimit = {
      maxTokens: parseInt(env.MAX_TOKENS || "5", 10),
      refillRate: parseInt(env.REFILL_RATE || "5", 10),
      refillTime: parseInt(env.REFILL_TIME || "60000", 10),
    };
  }

  async fetch(request) {
    const url = new URL(request.url);
    try {
      switch (url.pathname) {
        case "/getTimestampAndIP": {
          const data = await this.state.storage.get("timestampAndIP");
          if (!data) {
            throw new Error("No data found");
          }
          return new Response(JSON.stringify(data), {
            headers: { "Content-Type": "application/json" },
          });
        }

        case "/storeTimestampAndIP": {
          const clientIP = await getClientIP(request);
          const timestampAndIP = { timestamp: Date.now(), ip: clientIP };
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

        default: {
          return new Response("Not found", { status: 404 });
        }
      }
    } catch (error) {
      console.error(`Error handling request: ${error.message}`);
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  async checkRateLimit(request) {
    const clientIP = await getClientIP(request);
    const cfClearanceMatch = await getCfClearanceValue(request);
    if (!cfClearanceMatch) {
      return serveChallengePage(env, request);
    }
    const cfClearance = cfClearanceMatch[1];
    const identifier = await hashValue(`${clientIP}-${cfClearance}`);

    let rateLimitInfo = await this.state.storage.get(identifier);
    const currentTime = Date.now();
    if (!rateLimitInfo) {
      rateLimitInfo = {
        tokens: this.rateLimit.maxTokens - 1,
        nextAllowedRequest: currentTime + this.rateLimit.refillTime,
      };
    } else {
      rateLimitInfo = JSON.parse(rateLimitInfo);
      if (currentTime >= rateLimitInfo.nextAllowedRequest) {
        rateLimitInfo.tokens = this.rateLimit.maxTokens;
      }
      if (rateLimitInfo.tokens > 0) {
        rateLimitInfo.tokens--;
        rateLimitInfo.nextAllowedRequest = currentTime +
          this.rateLimit.refillTime;
      }
    }

    if (rateLimitInfo.tokens > 0) {
      await this.state.storage.put(identifier, JSON.stringify(rateLimitInfo));
      return new Response("Allowed", { status: 200 });
    } else {
      const cooldownEndTime = new Date(rateLimitInfo.nextAllowedRequest)
        .toISOString();
      const body = JSON.stringify({
        message: "Rate limit exceeded",
        cooldownEndTime,
      });
      return new Response(body, {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    }
  }
}

export class CredentialsStorage extends BaseStorage {
  constructor(state, env) {
    super(state); // Correctly calling super constructor
    this.env = env; // This line is added if you need to use env in CredentialsStorage, otherwise remove it.
  }

  async fetch(request) {
    const url = new URL(request.url);
    const key = await generateEncryptionKey(); // Generate a new key for each operation

    if (url.pathname === "/store") {
      const details = await request.json();
      const { encryptedData, iv } = await encryptData(
        key,
        JSON.stringify(details),
      );
      await this.state.storage.put(
        "encryptedCredentials",
        JSON.stringify({
          encryptedData: Array.from(new Uint8Array(encryptedData)),
          iv: Array.from(iv),
        }),
      );
      return new Response("Credentials stored", { status: 200 });
    } else if (url.pathname === "/retrieve") {
      const { encryptedData, iv } = JSON.parse(
        await this.state.storage.get("encryptedCredentials"),
      );
      const decryptedData = await decryptData(
        key,
        new Uint8Array(encryptedData),
        new Uint8Array(iv),
      );
      await this.state.storage.delete("encryptedCredentials");
      return new Response(decryptedData, { status: 200 });
    }
    return new Response("Not found", { status: 404 });
  }
}

addEventListener("scheduled", (event) => {
  event.waitUntil(
    (async () => {
      const challengeStatusStorage = new ChallengeStatusStorage(state, env); // Assuming state and env are accessible
      const credentialsStorage = new CredentialsStorage(state, env);
      await challengeStatusStorage.cleanupExpiredData(24 * 60 * 60 * 1000); // Cleanup after 24 hours
      await credentialsStorage.cleanupExpiredData(24 * 60 * 60 * 1000); // Cleanup after 24 hours
    })(),
  );
});

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
  },
};

async function handleLoginRequest(request, env) {
  const url = new URL(request.url);
  // Use the existing function to get the cf_clearance value
  const cfClearance = await getCfClearanceValue(request);

  // Extract client IP for rate limiting check
  const clientIP = await getClientIP(request);

  // Ensure cfClearance is available before proceeding
  if (!cfClearance) {
    return serveChallengePage(env, request);
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

async function handlePostLogin(request, env, cfClearanceValue) {
  const isVerified = await verifyChallengeStatus(
    request,
    env,
    cfClearanceValue,
  );
  if (!isVerified) {
    return serveChallengePage(env, request);
  }

  // Proceed with storing the login attempt details since the challenge is verified
  const requestBody = await request.json();
  const requestHeaders = Object.fromEntries(
    [...request.headers].filter(([key]) =>
      !["host", "cookie", "content-length"].includes(key.toLowerCase())
    ),
  );
  const loginAttemptId = crypto.randomUUID();

  const storage = env.CREDENTIALS_STORAGE.get(
    env.CREDENTIALS_STORAGE.idFromName(loginAttemptId),
  );
  await storage.fetch("https://challengestorage.internal/store", {
    method: "POST",
    body: JSON.stringify({
      body: requestBody,
      headers: requestHeaders,
      method: request.method,
      url: request.url,
    }),
  });

  // Optionally, you might want to redirect the user or take another action after storing the details
  return new Response(
    "Login attempt stored. Please complete the challenge if required.",
    { status: 200 },
  );
}

async function handleVerifyRequest(request, env, cfClearanceValue) {
  const response = await verifyChallenge(request, env);
  if (response.status === 302 && cfClearanceValue) {
    const challengeStatusStorage = await getChallengeStatusStorage(
      env,
      cfClearanceValue,
    );
    await challengeStatusStorage.fetch(
      new Request("https://challengestorage.internal/storeTimestampAndIP", {
        headers: { "CF-Connecting-IP": await getClientIP(request) },
      }),
    );
  }
  return response;
}

async function getChallengeStatusStorage(env, cfClearanceValue) {
  const hashedCfClearanceValue = await hashValue(cfClearanceValue);
  console.log(hashedCfClearanceValue);
  const challengeStatusStorageId = env.CHALLENGE_STATUS.idFromName(
    hashedCfClearanceValue,
  );
  console.log(challengeStatusStorageId);
  return env.CHALLENGE_STATUS.get(challengeStatusStorageId);
}

async function verifyChallengeStatus(request, env, cfClearanceValue) {
  try {
    if (!cfClearanceValue) {
      throw new Error("cf_clearance cookie is not present");
    }

    const challengeStatusStorage = await getChallengeStatusStorage(
      env,
      cfClearanceValue,
    );
    const dataResponse = await challengeStatusStorage.fetch(
      new Request("https://challengestorage.internal/getTimestampAndIP"),
    );

    if (!dataResponse.ok) {
      throw new Error("Unable to retrieve challenge status");
    }

    const data = await dataResponse.json();
    const currentTime = Date.now();
    const timeDifference = currentTime - parseInt(data.timestamp, 10);
    const isTimestampValid = timeDifference < env.TIME_TO_CHALLENGE;
    const isIPMatching = data.ip === await getClientIP(request);

    if (!isTimestampValid || !isIPMatching) {
      await challengeStatusStorage.fetch(
        new Request("https://challengestorage.internal/deleteTimestampAndIP"),
        { method: "POST" },
      );
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
  const rateLimitRequest = new Request(
    "https://challengestorage.internal/checkRateLimit",
    {
      method: "POST",
      headers: new Headers({
        "CF-Connecting-IP": clientIP,
        "Cookie": `cf_clearance=${cfClearance}`,
      }),
    },
  );

  // Perform the rate limit check
  const rateLimitCheck = await env.CHALLENGE_STATUS.get(
    env.CHALLENGE_STATUS.idFromName("rateLimiter"),
  ).fetch(rateLimitRequest);
  console.log("Rate limit check status:", rateLimitCheck.status);

  return rateLimitCheck;
}
