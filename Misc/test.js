export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const cookies = request.headers.get('Cookie');

        // Check if the cf_clearance cookie is present
        if (!cookies || !cookies.includes('cf_clearance')) {
            // If cf_clearance cookie is not present, serve the challenge page
            return serveChallengePage(request, env, url.toString());
        }

        // Corrected call to verifyChallenge within the fetch handler
        if (url.pathname.includes('login') && request.method === "POST") {
            const requestData = await request.json();
            const token = requestData.token;
            const originalUrl = requestData.originalUrl || url.toString();
            if (token) {
                // Pass the request object as the last argument
                return verifyChallenge(token, originalUrl, env, request);
            } else {
                return new Response('Challenge not completed', { status: 403 });
            }
        }


        // For other requests, proceed with the original request
        return fetch(request);
    }
}
// Adjusted function signature to directly accept required parameters
async function verifyChallenge(token, originalUrl, env, request) {
    const ip = request.headers.get('CF-Connecting-IP');

    let verificationFormData = new FormData();
    verificationFormData.append('secret', env.SECRET_KEY);
    verificationFormData.append('response', token);
    verificationFormData.append('remoteip', ip);

    const verificationResult = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        body: verificationFormData,
    });

    const outcome = await verificationResult.json();
    if (!outcome.success) {
        return new Response('The provided Turnstile token was not valid!', { status: 401 });
    }

    const headers = new Headers({
        'Location': originalUrl,
    });
    return new Response(null, { status: 302, headers });
}


function serveChallengePage(request, env, originalUrl) {
    const SITE_KEY = env.SITE_KEY; // Your Turnstile site key from environment variables

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
                    fetch('${originalUrl}', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ token: token, originalUrl: '${originalUrl}' })
                    }).then(response => {
                        if (response.ok) {
                            // Redirect back to the original page upon successful verification
                            window.location.href = response.headers.get('Location');
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
