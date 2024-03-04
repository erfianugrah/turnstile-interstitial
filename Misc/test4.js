export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cookies = parseCookies(request.headers.get('Cookie'));

    // Check if the cf_clearance cookie is present
    if (cookies.cf_clearance) {
      // cf_clearance cookie is present; the user has passed the challenge
      return fetch(request);
    }

    // Serve the challenge page for GET requests to the login endpoint without the cf_clearance cookie
    if (url.pathname.includes('login') && request.method === "GET") {
      return serveChallengePage(env, url.toString());
    }

    // Handle the verification of the Turnstile response for POST requests to /verify-challenge
    if (url.pathname === '/verify-challenge' && request.method === "POST") {
      return verifyChallenge(request, env);
    }

    // For other requests, proceed with the original request
    return fetch(request);
  }
};

function serveChallengePage(env, originalUrl) {
  const interstitialPageContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login Challenge</title>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <style>
            body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }
            .challenge-container { text-align: center; background-color: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
            h1 { color: #333; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="challenge-container">
            <h1>Complete the challenge to proceed</h1>
            <form id="challenge-form" action="/verify-challenge" method="POST">
                <input type="hidden" name="originalUrl" value="${originalUrl}">
                <div class="cf-turnstile" data-sitekey="${env.SITE_KEY}" data-callback="onChallengeSuccess" data-theme="light"></div>
            </form>
            <script>
                function onChallengeSuccess(token) {
                    document.getElementById("challenge-form").submit();
                }
            </script>
        </div>
    </body>
    </html>
  `;

  return new Response(interstitialPageContent, { headers: { 'Content-Type': 'text/html', 'Cache-Control': 'no-cache, no-store, must-revalidate' } });
}

async function verifyChallenge(request, env) {
  const formData = await request.formData();
  const token = formData.get('cf-turnstile-response');
  const originalUrl = formData.get('originalUrl');
  const ip = request.headers.get('CF-Connecting-IP');

  const verificationResult = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      secret: env.SECRET_KEY, // Use Turnstile secret key from environment variables
      response: token,
      remoteip: ip, // Include the user's IP address in the verification request
    }),
  });

  const outcome = await verificationResult.json();
  if (!outcome.success) {
    return new Response('The provided Turnstile token was not valid!', { status: 401 });
  }

  // Redirect the user to the original URL upon successful verification
  return new Response(null, { status: 302, headers: { 'Location': originalUrl } });
}

function parseCookies(cookieHeader) {
  return cookieHeader?.split(';').reduce((acc, cookie) => {
    const [key, value] = cookie.split('=').map(c => c.trim());
    acc[key] = value;
    return acc;
  }, {}) || {};
}
