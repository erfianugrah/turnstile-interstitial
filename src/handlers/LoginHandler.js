import { getClientIP } from '../utils/utils.js';
import { RateLimitService } from '../services/rate-limit-service.js';
import { ChallengeService } from '../services/challenge-service.js';
import { serveChallengePage, serveRateLimitPage } from '../services/static-page-service.js';

/**
 * Handles login requests and performs rate limiting
 */
export class LoginHandler {
  /**
   * Handle login requests via GET method
   * @param {Request} request - The HTTP request
   * @param {Object} env - Environment variables and bindings
   * @param {string} cfClearanceValue - Clearance cookie value
   * @returns {Promise<Response>} - Response after handling login
   */
  static async handleGetLogin(request, env, cfClearanceValue) {
    const isVerified = await ChallengeService.verifyChallengeStatus(
      request,
      env,
      cfClearanceValue,
    );
    if (isVerified) {
      return fetch(request);
    }
    return serveChallengePage(env, request);
  }

  /**
   * Handle login requests via POST method
   * @param {Request} request - The HTTP request
   * @param {Object} env - Environment variables and bindings
   * @param {string} cfClearanceValue - Clearance cookie value
   * @returns {Promise<Response>} - Response after handling login
   */
  static async handlePostLogin(request, env, cfClearanceValue) {
    try {
      const isVerified = await ChallengeService.verifyChallengeStatus(
        request,
        env,
        cfClearanceValue,
      );
      if (!isVerified) {
        return serveChallengePage(env, request);
      }

      // Clone the request to avoid consuming the body
      const requestClone = request.clone();
      
      // Proceed with storing the login attempt details since the challenge is verified
      const requestBody = await requestClone.json();
      const requestHeaders = Object.fromEntries(
        [...request.headers].filter(([key]) =>
          !["host", "cookie", "content-length"].includes(key.toLowerCase())
        ),
      );
      const loginAttemptId = crypto.randomUUID();

      // Get the storage instance for this attempt
      const storage = env.CREDENTIALS_STORAGE.get(
        env.CREDENTIALS_STORAGE.idFromName("login-storage"),
      );
      
      // Use our updated storage API with stable key derivation
      const storeResponse = await storage.fetch(`https://challengestorage.internal/store?id=${loginAttemptId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          body: requestBody,
          headers: requestHeaders,
          method: request.method,
          url: request.url,
          timestamp: Date.now(),
        }),
      });
      
      if (!storeResponse.ok) {
        throw new Error(`Failed to store login data: ${storeResponse.status}`);
      }
      
      const result = await storeResponse.json();
      
      // Return the stored credentials ID to the client
      return new Response(
        JSON.stringify({
          message: "Login attempt stored. Please complete the challenge if required.",
          credential_id: result.id,
        }),
        { 
          status: 200,
          headers: {
            "Content-Type": "application/json",
          },
        },
      );
    } catch (error) {
      console.error(`Error handling post login: ${error.message}`);
      
      // Return a graceful error response
      return new Response(
        JSON.stringify({ error: "Failed to process login request" }),
        { 
          status: 500,
          headers: {
            "Content-Type": "application/json",
          },
        },
      );
    }
  }

  /**
   * Main handler for login requests (both GET and POST)
   * @param {Request} request - The HTTP request
   * @param {Object} env - Environment variables and bindings
   * @param {string} cfClearanceValue - Clearance cookie value
   * @returns {Promise<Response>} - Response after handling login
   */
  static async handleLoginRequest(request, env, cfClearanceValue) {
    try {
      const url = new URL(request.url);
      
      // Extract client IP for rate limiting check
      const clientIP = await getClientIP(request);

      // Ensure cfClearance is available before proceeding
      if (!cfClearanceValue) {
        console.log("No clearance cookie found, serving challenge page");
        return serveChallengePage(env, request);
      }

      try {
        // Use the refactored function to perform the rate limit check
        const rateLimitCheck = await RateLimitService.checkRateLimit(env, clientIP, cfClearanceValue);
        
        if (rateLimitCheck.status === 429) {
          try {
            // Correctly parse the JSON body to get the cooldownEndTime
            const responseBody = await rateLimitCheck.json();
            
            if (!responseBody || !responseBody.cooldownEndTime) {
              console.error("Invalid rate limit response: missing cooldownEndTime");
              return serveChallengePage(env, request);
            }
            
            const cooldownEndTime = new Date(responseBody.cooldownEndTime);
            if (isNaN(cooldownEndTime.getTime())) {
              console.error(`Invalid cooldownEndTime: ${responseBody.cooldownEndTime}`);
              return serveChallengePage(env, request);
            }
            
            const now = new Date();

            // If the cooldown period has ended, serve the challenge page to get a new cookie
            if (now > cooldownEndTime) {
              console.log("Cooldown period ended, serving challenge page");
              return serveChallengePage(env, request);
            } else {
              // If still within the cooldown period, serve the rate limit page
              console.log(`Request rate-limited until ${cooldownEndTime.toISOString()}`);
              return serveRateLimitPage(cooldownEndTime, request);
            }
          } catch (parseError) {
            console.error(`Error parsing rate limit response: ${parseError.message}`);
            // If we can't parse the response, default to serving the challenge page
            return serveChallengePage(env, request);
          }
        }

        // Proceed with the login request handling
        if (request.method === "GET") {
          return this.handleGetLogin(request, env, cfClearanceValue);
        } else if ((url.pathname === "/api/login" || url.pathname === "/api/auth/login") && request.method === "POST") {
          return this.handlePostLogin(request, env, cfClearanceValue);
        } else {
          // If not a recognized login endpoint, return a 404
          return new Response(
            JSON.stringify({ error: "Not found" }), 
            { 
              status: 404,
              headers: { "Content-Type": "application/json" }
            }
          );
        }
      } catch (rateLimitError) {
        console.error(`Rate limiting error: ${rateLimitError.message}`);
        // In case of rate limiting errors, serve the challenge page
        return serveChallengePage(env, request);
      }
    } catch (error) {
      console.error(`Login request handling error: ${error.message}`);
      console.error(error.stack);
      
      // For any unhandled error, serve a generic error page
      const acceptHeader = request.headers.get("Accept");
      
      if (!acceptHeader || !acceptHeader.includes("text/html")) {
        return new Response(
          JSON.stringify({ 
            error: "An unexpected error occurred while processing your request" 
          }), 
          { 
            status: 500,
            headers: { 
              "Content-Type": "application/json",
              "Cache-Control": "no-store"
            }
          }
        );
      } else {
        return new Response(
          `<!DOCTYPE html>
          <html>
          <head>
            <title>Error</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
              body { font-family: sans-serif; text-align: center; padding: 20px; }
              .error-container { max-width: 600px; margin: 0 auto; }
              h1 { color: #e74c3c; }
            </style>
          </head>
          <body>
            <div class="error-container">
              <h1>Oops! Something went wrong</h1>
              <p>We encountered an unexpected error while processing your request. Please try again later.</p>
              <p><a href="javascript:window.location.reload()">Refresh the page</a></p>
            </div>
          </body>
          </html>`,
          { 
            status: 500,
            headers: { 
              "Content-Type": "text/html",
              "Cache-Control": "no-store"
            }
          }
        );
      }
    }
  }
}