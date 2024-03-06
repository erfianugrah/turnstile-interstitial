export async function serveChallengePage(env, request) {
  const url = new URL(request.url);
  const acceptHeader = request.headers.get('Accept');

  // Check if the request prefers HTML
  if (!acceptHeader || !acceptHeader.includes('text/html')) {
    // Respond with JSON for non-browser clients
    return new Response(JSON.stringify({ message: "Please complete the challenge to proceed." }), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, max-age=0' }
    });
  }
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

export async function serveRateLimitPage(cooldownEndTime, request) {
  // Assuming cooldownEndTime is a Date object
  const cooldownEndTimeString = cooldownEndTime.toLocaleTimeString();
  const acceptHeader = request.headers.get('Accept');

  // Check if the request prefers HTML
  if (!acceptHeader || !acceptHeader.includes('text/html')) {
    // Respond with JSON for non-browser clients
    return new Response(JSON.stringify({ message: "Rate limit exceeded. Please wait until the cooldown period has passed before making another request.", cooldownEndsAt: cooldownEndTimeString }), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store, max-age=0' }
    });
  }

  const rateLimitPageContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rate Limit Exceeded</title>
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
            .rate-limit-container {
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
                .rate-limit-container {
                    background-color: #3c3c3c; /* Darker grey for the container in dark mode */
                }
            }
            h1 {
                margin-bottom: 30px;
                font-size: 24px;
            }
            #cooldownTimer {
                font-size: 20px;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="rate-limit-container">
            <h1>Rate Limit Exceeded</h1>
            <p>You have exceeded the rate limit for requests. Please wait until the cooldown period has passed before making another request.</p>
            <p>Cooldown ends at: <span id="cooldownTimer">${cooldownEndTimeString}</span></p>
        </div>
        <script>
            const cooldownEndTime = new Date("${cooldownEndTime.toISOString()}").getTime();
            const timerElement = document.getElementById('cooldownTimer');

            function updateTimer() {
                const now = new Date().getTime();
                const distance = cooldownEndTime - now;

                if (distance < 0) {
                    clearInterval(interval);
                    timerElement.innerHTML = "Cooldown period has ended. You may now make another request.";
                    return;
                }

                const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((distance % (1000 * 60)) / 1000);

                timerElement.innerHTML = minutes + "m " + seconds + "s ";
            }

            const interval = setInterval(updateTimer, 1000);
            updateTimer(); // Initial update
        </script>
    </body>
    </html>
  `;

  // Set headers to prevent caching
  const headers = new Headers({
    'Content-Type': 'text/html',
    'Cache-Control': 'no-store, max-age=0'
  });

  return new Response(rateLimitPageContent, { headers: headers });
}
