import { hashValue } from '../utils/utils.js';
import { logger } from '../utils/logger.js';

/**
 * Service for handling challenge verification and storage
 */
export class ChallengeService {
  /**
   * Gets the storage object for a specific clearance cookie
   * 
   * @param {Object} env - Environment variables and bindings
   * @param {string} cfClearanceValue - Clearance cookie value
   * @returns {Promise<Object>} - Challenge status storage object
   */
  static async getChallengeStatusStorage(env, cfClearanceValue) {
    const hashedCfClearanceValue = await hashValue(cfClearanceValue);
    const challengeStatusStorageId = env.CHALLENGE_STATUS.idFromName(
      hashedCfClearanceValue,
    );
    return env.CHALLENGE_STATUS.get(challengeStatusStorageId);
  }

  /**
   * Store a successful verification for the given clearance value
   * 
   * @param {Object} env - Environment variables and bindings
   * @param {string} cfClearanceValue - Clearance cookie value
   * @param {string} clientIP - Client IP address
   * @returns {Promise<boolean>} Success status
   */
  static async storeSuccessfulVerification(env, cfClearanceValue, clientIP) {
    try {
      const challengeStorage = await this.getChallengeStatusStorage(
        env,
        cfClearanceValue
      );
      
      // Store the timestamp and IP for future verification
      const storeRequest = new Request(
        "https://challengestorage.internal/storeTimestampAndIP",
        {
          method: "POST",
          headers: {
            "CF-Connecting-IP": clientIP,
            "Content-Type": "application/json",
          },
        }
      );
      
      const storeResponse = await challengeStorage.fetch(storeRequest);
      
      if (!storeResponse.ok) {
        logger.error(
          { status: storeResponse.status },
          'Failed to store verification timestamp and IP'
        );
        return false;
      }
      
      return true;
    } catch (error) {
      logger.error(
        { err: error },
        'Error storing verification status'
      );
      return false;
    }
  }

  /**
   * Verifies the challenge status for a request
   * 
   * @param {Request} request - The HTTP request
   * @param {Object} env - Environment variables and bindings
   * @param {string} cfClearanceValue - Clearance cookie value
   * @returns {Promise<boolean>} - Whether the challenge is verified
   */
  static async verifyChallengeStatus(request, env, cfClearanceValue) {
    const reqLogger = logger.child({ 
      function: 'verifyChallengeStatus',
      cfClearance: cfClearanceValue ? cfClearanceValue.substring(0, 5) + '...' : 'none' 
    });
    
    try {
      // Validate the clearance cookie is present
      if (!cfClearanceValue) {
        reqLogger.warn('Challenge verification failed: cf_clearance cookie is not present');
        return false;
      }

      try {
        // Get the storage object for this clearance value
        const challengeStatusStorage = await this.getChallengeStatusStorage(
          env,
          cfClearanceValue,
        );
        
        // Try to get the stored timestamp and IP
        const dataResponse = await challengeStatusStorage.fetch(
          new Request("https://challengestorage.internal/getTimestampAndIP", {
            method: "GET",
            headers: {
              "Content-Type": "application/json"
            }
          }),
        );

        if (!dataResponse.ok) {
          reqLogger.warn(
            { status: dataResponse.status },
            'Challenge status retrieval failed'
          );
          return false;
        }

        // Parse the response data
        let data;
        try {
          data = await dataResponse.json();
        } catch (parseError) {
          reqLogger.error(
            { err: parseError },
            'Failed to parse challenge status data'
          );
          return false;
        }

        // Verify the timestamp is within the allowed window
        const currentTime = Date.now();
        const timeToChallenge = parseInt(env.TIME_TO_CHALLENGE || "150000", 10);
        
        // Check if timestamp is valid and properly formatted
        if (!data.timestamp || isNaN(parseInt(data.timestamp, 10))) {
          reqLogger.warn('Challenge verification failed: Invalid timestamp format');
          return false;
        }
        
        const timeDifference = currentTime - parseInt(data.timestamp, 10);
        const isTimestampValid = timeDifference < timeToChallenge;
        
        // Check if IP matches the current request's IP
        const currentIP = request.headers.get("CF-Connecting-IP");
        const isIPMatching = data.ip === currentIP;

        if (!isTimestampValid || !isIPMatching) {
          // Log the specific reason for failure
          if (!isTimestampValid) {
            reqLogger.warn(
              { 
                timeDifference,
                timeToChallenge,
                timestamp: data.timestamp
              },
              'Challenge verification failed: Timestamp expired'
            );
          }
          if (!isIPMatching) {
            reqLogger.warn(
              { 
                storedIP: data.ip, 
                currentIP
              },
              'Challenge verification failed: IP mismatch'
            );
          }
          
          try {
            // Delete the expired or invalid entry
            await challengeStatusStorage.fetch(
              new Request("https://challengestorage.internal/deleteTimestampAndIP", {
                method: "POST"
              }),
            );
          } catch (deleteError) {
            reqLogger.error(
              { err: deleteError },
              'Failed to delete invalid challenge data'
            );
            // Continue even if deletion fails
          }
          
          return false;
        }

        // If we get here, verification succeeded
        reqLogger.info(
          { storedIP: data.ip.substring(0, 7) + '...' },
          'Challenge verification successful'
        );
        return true;
      } catch (storageError) {
        reqLogger.error(
          { err: storageError },
          'Challenge storage error'
        );
        return false;
      }
    } catch (error) {
      reqLogger.error(
        { err: error },
        'Verification error'
      );
      return false;
    }
  }

  /**
   * Attempts to replay a previously stored request
   * 
   * @param {Object} env - Environment variables and bindings  
   * @param {string} requestId - ID of the stored request
   * @returns {Promise<Object>} Result of the replay attempt
   */
  static async replayOriginalRequest(env, requestId) {
    const reqLogger = logger.child({ 
      function: 'replayOriginalRequest',
      requestId 
    });
    
    try {
      // Retrieve the original request details
      const storage = env.CREDENTIALS_STORAGE.get(
        env.CREDENTIALS_STORAGE.idFromName("request-storage")
      );
      
      const retrieveResponse = await storage.fetch(
        `https://challengestorage.internal/retrieve?id=${requestId}`,
        { method: "GET" }
      );
      
      if (!retrieveResponse.ok) {
        reqLogger.error(
          { status: retrieveResponse.status },
          'Failed to retrieve request details'
        );
        return { 
          success: false, 
          error: `Failed to retrieve request details: ${retrieveResponse.status}` 
        };
      }
      
      // Parse the stored request details
      const originalRequest = JSON.parse(await retrieveResponse.text());
      
      if (!originalRequest || !originalRequest.method || originalRequest.method !== "POST") {
        reqLogger.error(
          { requestData: originalRequest },
          'Retrieved request is not a valid POST request'
        );
        return { 
          success: false, 
          error: 'Retrieved request is not a valid POST request' 
        };
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
      
      // Log original request details for debugging
      reqLogger.debug(
        { contentType, bodyKeys: Object.keys(originalRequest.body || {}) },
        'Request data for replay'
      );
      
      if (contentType.includes("application/json")) {
        // Use JSON.stringify for JSON data
        body = JSON.stringify(originalRequest.body);
        reqLogger.debug('Using JSON body for replay');
      } else if (contentType.includes("application/x-www-form-urlencoded")) {
        // Create a URLSearchParams object for form data
        const params = new URLSearchParams();
        for (const [key, value] of Object.entries(originalRequest.body || {})) {
          params.append(key, String(value));
        }
        body = params.toString();
        reqLogger.debug('Using URL-encoded form body for replay');
      } else if (contentType.includes("multipart/form-data")) {
        // Create a FormData object
        const formData = new FormData();
        for (const [key, value] of Object.entries(originalRequest.body || {})) {
          formData.append(key, String(value));
        }
        body = formData;
        
        // Don't use the Content-Type header for FormData
        // The browser will set the appropriate boundary
        headers.delete('Content-Type');
        reqLogger.debug('Using multipart form data body for replay');
      } else if (typeof originalRequest.body === 'string') {
        // For raw text body
        body = originalRequest.body;
        reqLogger.debug('Using raw string body for replay');
      } else if (originalRequest.body) {
        // For other types, try to stringify
        try {
          body = JSON.stringify(originalRequest.body);
          reqLogger.debug('Using stringified object body for replay');
        } catch (e) {
          reqLogger.warn(
            { err: e.message },
            'Failed to stringify body, using raw body'
          );
          body = originalRequest.body;
        }
      }
      
      reqLogger.info(
        { 
          method: originalRequest.method,
          url: originalRequest.url
        },
        'Replaying original request'
      );
      
      // Create fetch options
      const fetchOptions = {
        method: originalRequest.method,
        headers,
        body,
        redirect: "follow"
      };
      
      // Log fetch details
      reqLogger.debug({
        url: originalRequest.url,
        method: originalRequest.method,
        headers: Object.fromEntries(headers.entries()),
        hasBody: !!body,
      }, 'Fetch parameters for replay request');
      
      // Replay the original request
      const response = await fetch(originalRequest.url, fetchOptions);
      
      // Log response details
      reqLogger.debug({
        status: response.status,
        statusText: response.statusText,
        responseHeaders: Object.fromEntries(response.headers.entries()),
      }, 'Replay response received');
      
      return { 
        success: true, 
        status: response.status,
        response 
      };
    } catch (error) {
      reqLogger.error(
        { err: error },
        'Error replaying request'
      );
      return { 
        success: false, 
        error: error.message 
      };
    }
  }
}