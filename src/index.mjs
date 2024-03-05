// Assume hashValue, serveChallengePage, and verifyChallenge functions are defined as before

export class ChallengeStatusStorage {
  constructor(state, env) {
    this.state = state;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const clientIP = request.headers.get('CF-Connecting-IP'); // Get the client's IP address

    switch (url.pathname) {
      case "/getTimestampAndIP":
        const data = await this.state.storage.get("timestampAndIP");
        if (!data) {
          return new Response(JSON.stringify({ error: "No data found" }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        }
        return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });

      case "/storeTimestampAndIP":
        const timestampAndIP = { timestamp: Date.now(), ip: clientIP };
        await this.state.storage.put("timestampAndIP", timestampAndIP);
        return new Response("Timestamp and IP stored");

      default:
        return new Response("Not found", { status: 404 });
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
    const cfClearanceValue = getCfClearanceValue(request);

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

async function handleLoginRequest(request, env, cfClearanceValue) {
  const url = new URL(request.url);

  if (request.method === "GET") {
    return handleGetLogin(request, env, cfClearanceValue);
  } else if (url.pathname === "/api/login" && request.method === "POST") {
    return handlePostLogin(request, env, cfClearanceValue);
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
  const challengeStatusStorageId = env.CHALLENGE_STATUS.idFromName(hashedCfClearanceValue);
  return env.CHALLENGE_STATUS.get(challengeStatusStorageId);
}

async function verifyChallengeStatus(request, env, cfClearanceValue) {
  if (!cfClearanceValue) {
    // If cf_clearance cookie is not present, challenge verification fails
    return false;
  }

  const challengeStatusStorage = await getChallengeStatusStorage(env, cfClearanceValue);
  const dataResponse = await challengeStatusStorage.fetch(new Request("https://challengestorage.internal/getTimestampAndIP"));
  if (!dataResponse.ok) {
    // If unable to retrieve challenge status, challenge verification fails
    return false;
  }

  const data = await dataResponse.json();
  if (data.timestamp && (Date.now() - parseInt(data.timestamp, 10)) < 150000 && data.ip === request.headers.get('CF-Connecting-IP')) {
    // Challenge verification succeeded
    return true;
  }

  // Challenge verification failed
  return false;
}

async function hashValue(value) {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

async function generateEncryptionKey() {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  return key;
}

async function encryptData(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // AES-GCM requires a 12-byte IV
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  const encryptedData = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    encodedData
  );

  return { encryptedData, iv };
}

async function decryptData(key, encryptedData, iv) {
  const decryptedData = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    encryptedData
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedData);
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

async function serveChallengePage(env, request) {
  const url = new URL(request.url);

  const interstitialPageContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login Challenge</title>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>
        <style>
            :root {
                color-scheme: light dark;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background-color: #f0f2f5; /* Light mode background color */
                color: #555; /* Light mode text color */
                transition: background-color 0.3s, color 0.3s;
            }
            @media (prefers-color-scheme: dark) {
                body {
                    background-color: #333; /* Dark mode background color */
                    color: #f0f2f5; /* Dark mode text color */
                }
            }
            .challenge-container {
                text-align: center;
                padding: 50px;
                border-radius: 10px;
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
                max-width: 400px;
                width: 100%;
                background-color: #e0e0e0; /* Lighter grey for the container in light mode */
                transition: background-color 0.3s;
            }
            @media (prefers-color-scheme: dark) {
                .challenge-container {
                    background-color: #3c3c3c; /* Darker grey for the container in dark mode */
                }
            }
            h1 {
                margin-bottom: 30px;
                font-size: 24px;
            }
            .cf-turnstile {
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="challenge-container">
            <h1>Complete the challenge to proceed</h1>
            <form method="POST" action="/verify" id="challenge-form">
                <div class="cf-turnstile" data-sitekey="${env.SITE_KEY}" id="cf-turnstile"></div>
                <input type="hidden" name="originalUrl" value="${url}">
            </form>
            <script>
                function onChallengeSuccess(token) {
                    document.getElementById('challenge-form').submit();
                }
                const turnstileWidget = document.getElementById('cf-turnstile');
                const theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
                turnstileWidget.setAttribute('data-theme', theme);
                turnstileWidget.setAttribute('data-callback', 'onChallengeSuccess');
            </script>
        </div>
    </body>
    </html>
  `;

  // Set headers to prevent caching
  const headers = new Headers({
    'Content-Type': 'text/html',
    'Cache-Control': 'no-store, max-age=0'
  });

  return new Response(interstitialPageContent, { headers: headers });
}