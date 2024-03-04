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


async function hashValue(value) {
  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
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