// main_worker_script.js

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookies = request.headers.get('Cookie');
    let cfClearanceValue;

    // Extract the cf_clearance value from the cookies
    if (cookies) {
      const matches = cookies.match(/cf_clearance=([^;]+)/);
      if (matches) {
        cfClearanceValue = matches[1];
      }
    }

    // Serve the challenge page for GET requests to login paths
    if (/^\/login/.test(url.pathname) && request.method === "GET") {
      if (cfClearanceValue) {
        const challengeStatusStorageId = env.CHALLENGE_STATUS.idFromName(cfClearanceValue);
        const challengeStatusStorage = env.CHALLENGE_STATUS.get(challengeStatusStorageId);
        const timestamp = await challengeStatusStorage.getTimestamp();

        // Check if the timestamp is recent (less than 300 seconds ago)
        if (timestamp && (Date.now() - timestamp) < 300000) {
          // The challenge was recently passed; bypass the challenge
          return fetch(request);
        }
      }
      // Serve the challenge page
      return serveChallengePage(env, request);
    }

    // Handle POST requests for challenge verification
    if (/^\/verify/.test(url.pathname) && request.method === "POST") {
      const response = await verifyChallenge(request, env);
      if (response.status === 302 && cfClearanceValue) { // Assuming 302 means success
        const challengeStatusStorageId = env.CHALLENGE_STATUS.idFromName(cfClearanceValue);
        const challengeStatusStorage = env.CHALLENGE_STATUS.get(challengeStatusStorageId);
        await challengeStatusStorage.storeTimestamp();
      }
      return response;
    }

    // For other requests, proceed with the original request
    return fetch(request);
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


  console.log(originalUrl)
  // Redirect the user to the decoded original URL upon successful verification
  return Response.redirect(originalUrl, 302);
}

async function serveChallengePage(env, request) {
  const url = new URL(request.url);
  url.pathname

  // Capturing the full URL excluding query parameters

  const interstitialPageContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login Challenge</title>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" defer></script>
        <style>
            body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }
            .challenge-container { text-align: center; background-color: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
            h1 { color: #333; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="challenge-container">
            <h1>Complete the challenge to proceed</h1>
            <form method="POST" action="/verify">
                <div class="cf-turnstile" data-sitekey="${env.SITE_KEY}" data-callback="onChallengeSuccess" data-theme="light"></div>
                <input type="hidden" name="originalUrl" value="${url}">
                <script>
                function onChallengeSuccess(token) {
                  
                    document.querySelector('form').submit();

                }
            </script>
            </form>
        </div>
    </body>
    </html>
  `;

  return new Response(interstitialPageContent, { headers: { 'Content-Type': 'text/html' } });
}