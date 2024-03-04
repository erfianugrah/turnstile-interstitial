export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookies = request.headers.get('Cookie');

    // Check if the cf_clearance cookie is present
    if (cookies && cookies.includes('cf_clearance')) {
      // cf_clearance cookie is present; bypass the challenge and proceed with the original request
      return fetch(request);
    }

    // Serve the interstitial challenge page for GET requests to login paths
    if (url.pathname.includes('login') && request.method === "GET") {
      return serveChallengePage(env, url.toString());
    }

    // Handle POST requests for challenge verification
    if (url.pathname.includes('login') && request.method === "POST" && url.searchParams.get('verify') === 'true') {
      return verifyChallenge(request, env);
    }

    // For other requests, proceed with the original request
    return fetch(request);
  }
}

async function serveChallengePage(env, originalUrl) {
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
            <form action="/login?verify=true" method="POST">
                <input type="hidden" name="originalUrl" value="${originalUrl}">
                <div class="cf-turnstile" data-sitekey="${env.SITE_KEY}" data-callback="onChallengeSuccess"></div>
                <script>
                    function onChallengeSuccess(token) {
                        // Append the token to the form as a hidden input
                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'token';
                        input.value = token;
                        document.querySelector('form').appendChild(input);
                        // Submit the form
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

async function verifyChallenge(request, env) {
  const formData = await request.formData();
  const token = formData.get('token');
  const originalUrl = formData.get('originalUrl') || '/';

  const verificationResult = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      secret: env.SECRET_KEY,
      response: token,
      // remoteip: request.headers.get('CF-Connecting-IP'), // Optional: Include if you want to verify the IP as well
    }),
  });

  const outcome = await verificationResult.json();
  if (!outcome.success) {
    // Handle verification failure
    return new Response('The provided Turnstile token was not valid!', { status: 401 });
  }

  // Redirect the user to the original URL upon successful verification
  return Response.redirect(originalUrl, 302);
}
