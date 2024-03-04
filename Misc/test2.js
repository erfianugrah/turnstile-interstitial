export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const cookies = request.headers.get('Cookie');

        // Serve the challenge page for paths containing "login" if the cf_clearance cookie is not present
        if (url.pathname.includes('login') && (!cookies || !cookies.includes('cf_clearance'))) {
            // For GET requests, serve the challenge page
            if (request.method === "GET") {
                return serveChallengePage(request, env, url.toString());
            }

            // For POST requests, attempt to verify the Turnstile challenge response
            if (request.method === "POST") {
                const { token } = await request.json();
                if (token) {
                    // Use the request URL as the originalUrl for redirection after successful verification
                    const originalUrl = url.toString();
                    return verifyChallenge(token, originalUrl, env, request);
                } else {
                    return new Response('Challenge not completed', { status: 403 });
                }
            }
        }

        // For other requests or if cf_clearance cookie is present, proceed with the original request
        return fetch(request);
    }
};

async function verifyChallenge(token, originalUrl, env, request) {
    const ip = request.headers.get('CF-Connecting-IP');

    const formData = new URLSearchParams();
    formData.append('secret', env.SECRET_KEY);
    formData.append('response', token);
    if (ip) formData.append('remoteip', ip); // Include the IP address if available

    const verificationResult = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData,
    });

    const outcome = await verificationResult.json();
    if (!outcome.success) {
        return new Response('The provided Turnstile token was not valid!', { status: 401 });
    }

    // Redirect the user to the original URL after successful verification
    const headers = new Headers({ 'Location': originalUrl });
    return new Response(null, { status: 302, headers });
}

function serveChallengePage(request, env, originalUrl) {
    const SITE_KEY = env.SITE_KEY; // Your Turnstile site key from environment variables

    // Complete interstitial page content with styles
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
            /* Additional styles can be added here */
        </style>
    </head>
    <body>
        <div class="challenge-container">
            <h1>Complete the challenge to proceed</h1>
            <div class="cf-turnstile" data-sitekey="${SITE_KEY}" data-theme="light" data-callback="onChallengeSuccess"></div>
            <script>
                function onChallengeSuccess(token) {
                    fetch('${originalUrl}', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: token })
                    }).then(response => {
                        if (response.ok) {
                            window.location.href = response.headers.get('Location');
                        } else {
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

