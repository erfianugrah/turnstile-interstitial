export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookies = request.headers.get('Cookie');
    let cfClearanceValue;

    if (cookies) {
      const matches = cookies.match(/cf_clearance=([^;]+)/);
      if (matches) {
        cfClearanceValue = matches[1];
      }
    }

    if (/^\/login/.test(url.pathname) && request.method === "GET") {
      if (cfClearanceValue) {
        const hashedCfClearanceValue = await hashValue(cfClearanceValue);
        const challengeStatusStorageId = env.CHALLENGE_STATUS.idFromName(hashedCfClearanceValue);
        const challengeStatusStorage = env.CHALLENGE_STATUS.get(challengeStatusStorageId);

        const dataResponse = await challengeStatusStorage.fetch(new Request("https://challengestorage.internal/getTimestampAndIP"));
        if (dataResponse.ok) {
          const data = await dataResponse.json();
          if (data.timestamp && (Date.now() - parseInt(data.timestamp, 10)) < 150000 && data.ip === request.headers.get('CF-Connecting-IP')) {
            return fetch(request);
          }
        }
      }

      return serveChallengePage(env, request);
    }

    // Intercept POST requests to /login for login attempts with JSON payloads
    if (url.pathname === "/api/login" && request.method === "POST") {
      // Check if the challenge has already been passed using cf_clearance or other logic
      if (cfClearanceValue) {
        // Logic to verify cf_clearance and proceed with the request if valid
      } else {
        // Extract the body and headers of the request
        const requestBody = await request.json();
        const requestHeaders = {};
        for (const [key, value] of request.headers) {
          if (!["host", "cookie", "content-length"].includes(key.toLowerCase())) {
            requestHeaders[key] = value;
          }
        }

        // Generate a unique ID for this login attempt
        const loginAttemptId = crypto.randomUUID();

        // Store the login attempt details in a Durable Object
        const storageId = env.CREDENTIALS_STORAGE.idFromName(loginAttemptId);
        const storage = env.CREDENTIALS_STORAGE.get(storageId);
        await storage.fetch("https://challengestorage.internal/store", {
          method: "POST",
          body: JSON.stringify({ body: requestBody, headers: requestHeaders, method: request.method, url: request.url })
        });

        // Serve the challenge page, passing the loginAttemptId to track this attempt
        return serveChallengePage(env, request, loginAttemptId);
      }
    }

    if (/^\/verify/.test(url.pathname) && request.method === "POST") {
      const response = await verifyChallenge(request, env);
      if (response.status === 302 && cfClearanceValue) {
        const hashedCfClearanceValue = await hashValue(cfClearanceValue);
        const challengeStatusStorageId = env.CHALLENGE_STATUS.idFromName(hashedCfClearanceValue);
        const challengeStatusStorage = env.CHALLENGE_STATUS.get(challengeStatusStorageId);

        await challengeStatusStorage.fetch(new Request("https://challengestorage.internal/storeTimestampAndIP", { headers: { 'CF-Connecting-IP': request.headers.get('CF-Connecting-IP') } }));
      }
      return response;
    }
    return fetch(request);
  }
};