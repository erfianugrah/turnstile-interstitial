export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cookies = request.headers.get('Cookie');

    // Check if the challenge has already been passed via cookies
    if (cookies && cookies.includes('challenge_passed=true')) {
      // Bypass the challenge and proceed with the original request
      return fetch(request);
    }

    // Serve the interstitial challenge page for paths containing "login"
    if (url.pathname.includes('login') && request.method === "GET") {
      return serveChallengePage(request, env, url.toString());
    } else if (url.pathname.includes('login') && request.method === "POST" && url.searchParams.get('verify') === 'true') {
      // Handle POST requests with a verification query parameter
      return verifyChallenge(request, env);
    }

    // For other requests, proceed with the original request
    return fetch(request);
  }
}

async function verifyChallenge(request, env) {
  const { token, originalUrl } = await request.json();
  const ip = request.headers.get('CF-Connecting-IP');

  let verificationFormData = new FormData();
  verificationFormData.append('secret', env.SECRET_KEY); // Your Turnstile secret key
  verificationFormData.append('response', token);
  verificationFormData.append('remoteip', ip);

  const verificationResult = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: verificationFormData,
  });

  const outcome = await verificationResult.json();
  if (!outcome.success) {
    // Handle verification failure
    return new Response('The provided Turnstile token was not valid!', { status: 401 });
  }

  // Construct the response to set a cookie and redirect to the original URL
  const headers = new Headers({
    'Location': originalUrl,
    'Set-Cookie': 'challenge_passed=true; Max-Age=3600; Path=/; HttpOnly; Secure; SameSite=Strict',
  });
  return new Response(null, { status: 302, headers });
}

function serveChallengePage(request, env, originalUrl) {
  const SITE_KEY = env.SITE_KEY; // Use your Turnstile site key from environment variables

  const interstitialPageContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login Challenge</title>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <style>
            body {
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                background-color: #f0f2f5;
            }
            .challenge-container {
                text-align: center;
                background-color: white;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            h1 {
                color: #333;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="challenge-container">
            <h1>Complete the challenge to proceed</h1>
            <div class="cf-turnstile" data-sitekey="${SITE_KEY}" data-theme="light" data-callback="onChallengeSuccess"></div>
            <script>
                function onChallengeSuccess(token) {
                    // Immediately send the token to the server for verification
                    fetch('/login?verify=true', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ token: token, originalUrl: '${originalUrl}' })
                    }).then(response => {
                        if (response.ok) {
                            // Redirect back to the original page upon successful verification
                            window.location.href = response.url;
                        } else {
                            // Handle verification failure
                            alert('Challenge verification failed. Please try again.');
                        }
                    });
                }
            </script>
        </div>
    </body>
    </html>
  `;

  return new Response(interstitialPageContent, { headers: { 'Content-Type': 'text/html' } });
}
