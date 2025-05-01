import { logger } from '../utils/logger.js';

/**
 * Serves the challenge page to the client
 * 
 * @param {Object} env - Environment variables and bindings
 * @param {Request} request - Original HTTP request
 * @returns {Response} HTML challenge page or JSON response for API clients
 */
export async function serveChallengePage(env, request) {
  const url = new URL(request.url);
  const acceptHeader = request.headers.get("Accept");
  const method = request.method;
  let requestId = null;
  
  // Create a scoped logger
  const reqLogger = logger.child({
    function: 'serveChallengePage',
    url: url.pathname,
    method
  });
  
  // If this is a POST request, store the request details for later replay
  if (method === "POST") {
    try {
      // Clone the request to avoid consuming the body
      const requestClone = request.clone();
      
      // Extract the form data or JSON body
      let requestBody;
      const contentType = request.headers.get("Content-Type") || "";
      const contentLength = request.headers.get("Content-Length") || "0";
      
      // Log content information
      reqLogger.debug(
        { contentType, contentLength },
        'Processing request body for storage'
      );
      
      try {
        if (contentType.includes("application/json")) {
          requestBody = await requestClone.json();
          reqLogger.debug('Stored JSON body');
        } else if (contentType.includes("application/x-www-form-urlencoded")) {
          // For URL-encoded form data
          const formData = await requestClone.formData();
          requestBody = {};
          for (const [key, value] of formData.entries()) {
            requestBody[key] = typeof value === 'string' ? value : '[binary data]';
          }
          reqLogger.debug('Stored URL-encoded form data');
        } else if (contentType.includes("multipart/form-data")) {
          // For multipart form data
          try {
            const formData = await requestClone.formData();
            requestBody = {};
            for (const [key, value] of formData.entries()) {
              if (typeof value === 'string') {
                requestBody[key] = value;
              } else if (value instanceof File) {
                // We can't store File objects, so just log that they were present
                requestBody[key] = `[File: ${value.name}, type: ${value.type}, size: ${value.size}]`;
              } else {
                requestBody[key] = '[binary data]';
              }
            }
            reqLogger.debug('Stored multipart form data');
          } catch (formError) {
            // If formData parsing fails, fall back to text
            requestBody = await requestClone.text();
            reqLogger.warn(
              { err: formError.message },
              'Failed to parse multipart form, storing as text'
            );
          }
        } else {
          // For other content types, store as text if the content isn't too large
          const maxTextSize = 1024 * 1024; // 1MB limit for text content
          
          if (parseInt(contentLength, 10) <= maxTextSize) {
            requestBody = await requestClone.text();
            reqLogger.debug('Stored body as text');
          } else {
            requestBody = `[Large body: ${contentLength} bytes]`;
            reqLogger.warn(
              { size: contentLength },
              'Body too large to store as text'
            );
          }
        }
      } catch (bodyError) {
        // If all else fails, just note that we couldn't parse the body
        reqLogger.error(
          { err: bodyError.message },
          'Failed to parse request body'
        );
        requestBody = { error: "Failed to parse request body" };
      }
      
      // Collect headers we want to preserve
      const headersToStore = {};
      for (const [key, value] of request.headers.entries()) {
        // Skip some headers that shouldn't be replayed
        if (!["host", "connection", "content-length", "cf-connecting-ip"].includes(key.toLowerCase())) {
          headersToStore[key] = value;
        }
      }
      
      // Generate a unique ID for this request
      requestId = crypto.randomUUID();
      
      // Store the request details in the CREDENTIALS_STORAGE durable object
      const storage = env.CREDENTIALS_STORAGE.get(
        env.CREDENTIALS_STORAGE.idFromName("request-storage")
      );
      
      const storeResponse = await storage.fetch(`https://challengestorage.internal/store?id=${requestId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: url.toString(),
          method,
          headers: headersToStore,
          body: requestBody,
          timestamp: Date.now(),
          contentType
        })
      });
      
      if (storeResponse.ok) {
        reqLogger.info(
          { requestId },
          'Stored original request for replay after challenge'
        );
      } else {
        reqLogger.error(
          { requestId, status: storeResponse.status },
          'Failed to store original request'
        );
      }
    } catch (error) {
      reqLogger.error(
        { err: error },
        'Failed to store request for replay'
      );
      // Continue even if storage fails - user will have to resubmit
    }
  }

  // Check if the request prefers HTML
  if (!acceptHeader || !acceptHeader.includes("text/html")) {
    // Respond with JSON for non-browser clients
    reqLogger.debug('Returning JSON response for non-browser client');
    return new Response(
      JSON.stringify({ 
        message: "Please complete the challenge to proceed.",
        requestId: requestId // Include the requestId for API clients that might want to check status
      }),
      {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store, max-age=0",
        },
      },
    );
  }
  
  // HTML challenge page with form replay capability
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
            .info-text {
                margin-top: 20px;
                font-size: 14px;
                color: #777;
            }
            @media (prefers-color-scheme: dark) {
                .info-text {
                    color: #aaa;
                }
            }
        </style>
    </head>
    <body>
        <div class="challenge-container">
            <h1>Complete the challenge to proceed</h1>
            <form method="POST" action="/verify" id="challenge-form">
                <div class="cf-turnstile" data-sitekey="${env.SITE_KEY}" id="cf-turnstile"></div>
                <input type="hidden" name="originalUrl" value="${url}">
                ${requestId ? `<input type="hidden" name="requestId" value="${requestId}">` : ''}
                ${method === 'POST' ? '<p class="info-text">Your form submission will continue automatically after verification.</p>' : ''}
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
    "Content-Type": "text/html",
    "Cache-Control": "no-store, max-age=0",
  });

  reqLogger.debug('Returning HTML challenge page');
  return new Response(interstitialPageContent, { headers: headers });
}

/**
 * Serves the rate limit page to the client
 * 
 * @param {Date} cooldownEndTime - When the rate limit expires
 * @param {Request} request - Original HTTP request
 * @returns {Response} HTML rate limit page or JSON response for API clients
 */
export function serveRateLimitPage(cooldownEndTime, request) {
  // Create a scoped logger
  const reqLogger = logger.child({
    function: 'serveRateLimitPage',
    cooldownEndTime: cooldownEndTime.toISOString()
  });
  
  // Assuming cooldownEndTime is a Date object
  const cooldownEndTimeString = cooldownEndTime.toLocaleTimeString();
  const acceptHeader = request.headers.get("Accept");

  // Check if the request prefers HTML
  if (!acceptHeader || !acceptHeader.includes("text/html")) {
    // Respond with JSON for non-browser clients
    reqLogger.debug('Returning JSON response for non-browser client');
    return new Response(
      JSON.stringify({
        message:
          "Rate limit exceeded. Please wait until the cooldown period has passed before making another request.",
        cooldownEndsAt: cooldownEndTime.toISOString(),
      }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store, max-age=0",
        },
      },
    );
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
                    margin-bottom: 20px; /* Add some space above the button */
                }
                #retryButton {
                    font-size: 16px;
                    padding: 10px 20px;
                    color: #fff;
                    background-color: #007bff;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                    transition: background-color 0.2s;
                }
                #retryButton:hover {
                    background-color: #0056b3;
                }
            </style>
        </head>
        <body>
            <div class="rate-limit-container">
                <h1 id="rateLimitTitle">Please try again later</h1>
                <p id="cooldownMessage">You have exceeded the rate limit for requests. Please wait until the cooldown period has passed before making another request.</p>
                <p>Cooldown ends in <span id="cooldownTimer"></span></p>
                <button id="retryButton" style="display:none;">Retry Now</button>
            </div>
                <script>
                    const cooldownEndTime = new Date("${cooldownEndTime.toISOString()}").getTime();
                    const timerElement = document.getElementById('cooldownTimer');
                    const retryButton = document.getElementById('retryButton');
                    const cooldownMessage = document.getElementById('cooldownMessage');
                    const rateLimitTitle = document.getElementById('rateLimitTitle'); // Get the h1 element
                    let redirectTimeout;

                    function updateTimer() {
                        const now = new Date().getTime();
                        const distance = cooldownEndTime - now;

                        if (distance < 0) {
                            clearInterval(interval);
                            // Update the h1 text to indicate the user can try again
                            rateLimitTitle.textContent = "Press the button below or wait 5 seconds";
                            // Hide the cooldown message and timer
                            cooldownMessage.style.display = 'none';
                            timerElement.parentElement.style.display = 'none';
                            // Display the retry button
                            retryButton.style.display = 'inline-block';
                            // Set a timeout for automatic redirection
                            redirectTimeout = setTimeout(function() {
                                window.location.reload(); // Automatically reload the page after 5 seconds
                            }, 5000);
                            return;
                        }

                        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                        const seconds = Math.floor((distance % (1000 * 60)) / 1000);

                        timerElement.innerHTML = minutes + "m " + seconds + "s ";
                    }

                    retryButton.addEventListener('click', function() {
                        clearTimeout(redirectTimeout); // Cancel the auto-redirect
                        window.location.reload(); // Reload the page
                    });

                    const interval = setInterval(updateTimer, 1000);
                    updateTimer(); // Initial update
                </script>

        </body>
        </html>
    `;

  // Set headers to prevent caching
  const headers = new Headers({
    "Content-Type": "text/html",
    "Cache-Control": "no-store, max-age=0",
  });

  reqLogger.debug('Returning HTML rate limit page');
  return new Response(rateLimitPageContent, { 
    status: 429,
    headers: headers 
  });
}