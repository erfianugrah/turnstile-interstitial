import { hashValue, generateEncryptionKey, encryptData, decryptData } from './utils.js'

export class ChallengeStatusStorage {
  constructor(state, env) {
    this.state = state;
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

        default:
          return new Response("Not found", { status: 404 });
      }
    } catch (error) {
      console.error(`Error handling request: ${error.message}`);
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
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