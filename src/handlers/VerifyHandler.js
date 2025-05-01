import { getClientIP } from '../utils/utils.js';
import { ChallengeService } from '../services/challenge-service.js';

/**
 * Handles verification of challenge responses
 */
export class VerifyHandler {
  /**
   * Handle verification requests for challenges
   * @param {Request} request - The HTTP request
   * @param {Object} env - Environment variables and bindings
   * @param {string} cfClearanceValue - Clearance cookie value
   * @returns {Promise<Response>} - Response after verification
   */
  static async handleVerifyRequest(request, env, cfClearanceValue) {
    try {
      // First, verify the challenge
      const formData = await request.formData();
      const token = formData.get("cf-turnstile-response");
      const ip = await getClientIP(request);
      const originalUrl = formData.get("originalUrl");
      const requestId = formData.get("requestId");

      // Validate inputs
      if (!token) {
        return new Response("Missing Turnstile token", { status: 400 });
      }
      
      if (!originalUrl) {
        return new Response("Missing original URL", { status: 400 });
      }

      // Validate the token by calling the "/siteverify" API
      const verifyFormData = new FormData();
      verifyFormData.append("secret", env.SECRET_KEY);
      verifyFormData.append("response", token);
      verifyFormData.append("remoteip", ip);

      const result = await fetch(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        {
          body: verifyFormData,
          method: "POST",
        },
      );

      const outcome = await result.json();
      console.log("Turnstile verification result:", JSON.stringify(outcome));
      
      if (!outcome.success) {
        // Handle verification failure
        return new Response("The provided Turnstile token was not valid!", {
          status: 401,
          headers: { "Content-Type": "text/plain" }
        });
      }

      // If successful, store the verification result for this clearance value
      if (cfClearanceValue) {
        try {
          // Get the storage for this clearance value
          const challengeStatusStorage = await ChallengeService.getChallengeStatusStorage(
            env,
            cfClearanceValue,
          );
          
          // Store the timestamp and IP for later verification
          const clientIP = await getClientIP(request);
          const storeRequest = new Request(
            "https://challengestorage.internal/storeTimestampAndIP", 
            {
              method: "POST",
              headers: { 
                "CF-Connecting-IP": clientIP,
                "Content-Type": "application/json" 
              }
            }
          );
          
          const storeResponse = await challengeStatusStorage.fetch(storeRequest);
          
          if (!storeResponse.ok) {
            console.error(`Failed to store timestamp and IP: ${storeResponse.status}`);
            // Continue anyway - we want to let the user proceed even if storage failed
          }
        } catch (storageError) {
          // Log the error but don't fail the verification
          console.error(`Error storing verification status: ${storageError.message}`);
          // We still want to return the original response even if storage failed
        }
      }

      // If this was a POST request that we stored for replay
      if (requestId) {
        try {
          console.log(`Attempting to replay request with ID: ${requestId}`);
          
          // Retrieve the original request details
          const storage = env.CREDENTIALS_STORAGE.get(
            env.CREDENTIALS_STORAGE.idFromName("request-storage")
          );
          
          const retrieveResponse = await storage.fetch(
            `https://challengestorage.internal/retrieve?id=${requestId}`,
            { method: "GET" }
          );
          
          if (!retrieveResponse.ok) {
            console.error(`Failed to retrieve request details: ${retrieveResponse.status}`);
            // If retrieval fails, just redirect to the original URL
            return Response.redirect(originalUrl, 302);
          }
          
          // Parse the stored request details
          const originalRequest = JSON.parse(await retrieveResponse.text());
          if (!originalRequest || !originalRequest.method || originalRequest.method !== "POST") {
            console.error("Retrieved request is not a valid POST request");
            return Response.redirect(originalUrl, 302);
          }
          
          // Reconstruct the request headers
          const headers = new Headers();
          if (originalRequest.headers) {
            for (const [key, value] of Object.entries(originalRequest.headers)) {
              headers.set(key, value);
            }
          }
          
          // Add some headers to indicate this is a replayed request
          headers.set("X-Request-Replayed", "true");
          headers.set("X-Original-Timestamp", originalRequest.timestamp || Date.now());
          
          // Reconstruct the request body based on content type
          let body;
          const contentType = originalRequest.contentType || "";
          
          if (contentType.includes("application/json")) {
            body = JSON.stringify(originalRequest.body);
          } else if (contentType.includes("application/x-www-form-urlencoded")) {
            // Create a URLSearchParams object for form data
            const params = new URLSearchParams();
            for (const [key, value] of Object.entries(originalRequest.body)) {
              params.append(key, value);
            }
            body = params.toString();
          } else if (contentType.includes("multipart/form-data")) {
            // Create a FormData object
            const formData = new FormData();
            for (const [key, value] of Object.entries(originalRequest.body)) {
              formData.append(key, value);
            }
            body = formData;
          } else {
            // For other content types, use the body as-is
            body = originalRequest.body;
          }
          
          console.log(`Replaying ${originalRequest.method} request to ${originalRequest.url}`);
          
          // Replay the original request
          return fetch(originalRequest.url, {
            method: originalRequest.method,
            headers,
            body,
            redirect: "follow"
          });
        } catch (replayError) {
          console.error(`Error replaying request: ${replayError.message}`);
          // If replay fails, redirect to the original URL
          return Response.redirect(originalUrl, 302);
        }
      }

      // For non-replay requests, just redirect to the original URL
      return Response.redirect(originalUrl, 302);
    } catch (error) {
      console.error(`Error in verifyChallenge: ${error.message}`);
      return new Response(`Verification error: ${error.message}`, { 
        status: 500,
        headers: { "Content-Type": "text/plain" }
      });
    }
  }
}