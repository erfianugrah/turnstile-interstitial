import { BaseStorage } from './base-storage.js';
import { getCfClearanceValue, getClientIP, hashValue } from '../utils/utils.js';
import { logger } from '../utils/logger.js';

/**
 * Durable Object for managing challenge verification status and rate limiting
 */
export class ChallengeStatusStorage extends BaseStorage {
  constructor(state, env) {
    super(state);
    this.env = env;
    this.rateLimit = {
      maxTokens: parseInt(env.MAX_TOKENS || "5", 10),
      refillRate: parseInt(env.REFILL_RATE || "5", 10),
      refillTime: parseInt(env.REFILL_TIME || "60000", 10),
    };
    
    // Create a logger instance for this durable object
    this.logger = logger.child({
      durableObject: 'ChallengeStatusStorage',
      id: state.id.toString().substring(0, 8) + '...'
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    try {
      // Create a request-scoped logger
      const reqLogger = this.logger.child({ path: url.pathname });
      
      switch (url.pathname) {
        case "/getTimestampAndIP": {
          reqLogger.debug('Getting timestamp and IP');
          const data = await this.state.storage.get("timestampAndIP");
          if (!data) {
            reqLogger.info('No timestamp and IP data found');
            return new Response(JSON.stringify({ error: "No data found" }), {
              status: 404,
              headers: { "Content-Type": "application/json" },
            });
          }
          return new Response(JSON.stringify(data), {
            headers: { "Content-Type": "application/json" },
          });
        }

        case "/storeTimestampAndIP": {
          const clientIP = await getClientIP(request);
          const timestampAndIP = { timestamp: Date.now(), ip: clientIP, lastAccess: Date.now() };
          await this.state.storage.put("timestampAndIP", timestampAndIP);
          this.logger.info(
            { ip: clientIP.substring(0, 8) + '...' },
            'Stored verification timestamp and IP'
          );
          return new Response("Timestamp and IP stored");
        }

        case "/deleteTimestampAndIP": {
          await this.state.storage.delete("timestampAndIP");
          this.logger.info('Deleted verification timestamp and IP');
          return new Response("Timestamp and IP deleted", { status: 200 });
        }

        case "/checkRateLimit": {
          return this.checkRateLimit(request);
        }
        
        case "/cleanup": {
          // Parse the expiration time from request body or use default (24 hours)
          let expirationTime = 24 * 60 * 60 * 1000;
          try {
            const body = await request.json();
            if (body && body.expirationTime) {
              expirationTime = parseInt(body.expirationTime, 10);
            }
          } catch (e) {
            // If parsing fails, use the default
          }
          
          const cleanedCount = await this.cleanupExpiredData(expirationTime);
          return new Response(JSON.stringify({ cleanedCount }), {
            headers: { "Content-Type": "application/json" },
          });
        }

        default: {
          return new Response("Not found", { status: 404 });
        }
      }
    } catch (error) {
      const errorDetails = {
        message: error.message,
        stack: error.stack,
        name: error.name
      };
      
      this.logger.error(
        { err: errorDetails, path: url.pathname },
        'Error handling request'
      );
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  async checkRateLimit(request) {
    try {
      // Extract identifier from query parameters or body
      let identifier;
      let limits = this.rateLimit;
      
      try {
        // Try to get identifier and limits from JSON body
        const body = await request.json();
        identifier = body.identifier;
        
        if (body.limits) {
          limits = {
            maxTokens: parseInt(body.limits.maxTokens || this.rateLimit.maxTokens, 10),
            refillRate: parseInt(body.limits.refillRate || this.rateLimit.refillRate, 10),
            refillTime: parseInt(body.limits.refillTime || this.rateLimit.refillTime, 10),
          };
        }
      } catch (e) {
        // Fallback to extracting from headers
        const clientIP = await getClientIP(request);
        const cfClearanceMatch = await getCfClearanceValue(request);
        
        if (!cfClearanceMatch) {
          return new Response(JSON.stringify({ error: "Missing clearance cookie" }), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }
        
        const cfClearance = cfClearanceMatch[1];
        identifier = await hashValue(`${clientIP}-${cfClearance}`);
      }
      
      if (!identifier) {
        return new Response(JSON.stringify({ error: "Missing identifier" }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
      
      // Use a transactional update pattern to prevent race conditions
      // This will retry the operation if another request modifies the data concurrently
      let retries = 0;
      const maxRetries = 5;
      
      // Create a logger with the identifier
      const reqLogger = this.logger.child({
        function: 'checkRateLimit',
        identifier: identifier.substring(0, 8) + '...'
      });
      
      while (retries < maxRetries) {
        try {
          // Get the current token count
          const currentTime = Date.now();
          const storedData = await this.state.storage.get(identifier);
          
          let rateLimitInfo;
          let originalValue = null;
          
          if (!storedData) {
            // Initialize rate limit info for new clients
            rateLimitInfo = {
              tokens: limits.maxTokens - 1, // Consume one token for this request
              nextAllowedRequest: currentTime + limits.refillTime,
              lastAccess: currentTime,
            };
            
            reqLogger.info(
              { tokens: rateLimitInfo.tokens },
              'New rate limit entry created'
            );
          } else {
            // Store the original value for compare-and-swap operation
            originalValue = storedData;
            rateLimitInfo = JSON.parse(storedData);
            
            // Refill tokens if enough time has passed
            if (currentTime >= rateLimitInfo.nextAllowedRequest) {
              rateLimitInfo.tokens = limits.maxTokens;
              reqLogger.debug('Tokens refilled after cooldown period');
            }
            
            // Consume a token if available
            if (rateLimitInfo.tokens > 0) {
              rateLimitInfo.tokens--;
              rateLimitInfo.nextAllowedRequest = currentTime + limits.refillTime;
              
              reqLogger.debug(
                { tokens: rateLimitInfo.tokens, nextAllowedRequest: new Date(rateLimitInfo.nextAllowedRequest).toISOString() },
                'Token consumed'
              );
            }
            
            // Update last access time
            rateLimitInfo.lastAccess = currentTime;
          }
          
          // Use atomic compare-and-swap operation to prevent race conditions
          const success = await this.atomicUpdate(
            identifier, 
            JSON.stringify(rateLimitInfo), 
            originalValue
          );
          
          if (success || !originalValue) {
            // Successfully updated or created new entry
            if (rateLimitInfo.tokens > 0) {
              reqLogger.debug('Request allowed');
              return new Response("Allowed", { status: 200 });
            } else {
              const cooldownEndTime = new Date(rateLimitInfo.nextAllowedRequest).toISOString();
              const body = JSON.stringify({
                message: "Rate limit exceeded",
                cooldownEndTime,
              });
              
              reqLogger.info(
                { cooldownEndTime },
                'Rate limit exceeded'
              );
              
              return new Response(body, {
                status: 429,
                headers: { "Content-Type": "application/json" },
              });
            }
          }
          
          // If we reach here, our update failed due to a concurrent modification
          // We'll retry the operation
          retries++;
          reqLogger.debug(
            { retry: retries },
            'Rate limit check retry due to concurrent modification'
          );
          
          // Short exponential backoff
          await new Promise(r => setTimeout(r, 5 * Math.pow(2, retries)));
        } catch (error) {
          reqLogger.error(
            { err: error, retry: retries },
            'Error in rate limit check retry'
          );
          
          retries++;
          // If we hit an error, add a short delay before retrying
          await new Promise(r => setTimeout(r, 10));
        }
      }
      
      // If we've exhausted retries, fall back to allowing the request
      // This is safer than potentially blocking legitimate traffic
      reqLogger.error(
        { maxRetries },
        'Rate limit check failed after max retries'
      );
      
      return new Response("Allowed (fallback)", { status: 200 });
    } catch (error) {
      this.logger.error(
        { err: error },
        'Rate limiting error'
      );
      
      // In case of unexpected errors, allow the request rather than blocking
      return new Response("Allowed (error fallback)", { status: 200 });
    }
  }
  
  // Helper method for atomic updates with retry logic
  async atomicUpdate(key, newValue, expectedValue) {
    if (!expectedValue) {
      // If there's no existing value, we can just put the new value
      await this.state.storage.put(key, newValue);
      return true;
    }
    
    // Try to atomically update using a compare-and-swap operation
    // This operation only succeeds if the current value matches expectedValue
    const currentValue = await this.state.storage.get(key);
    
    if (currentValue === expectedValue) {
      await this.state.storage.put(key, newValue);
      return true;
    }
    
    // Value was changed by another request
    return false;
  }
}