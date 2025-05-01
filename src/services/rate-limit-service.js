import { hashValue } from '../utils/utils.js';
import { logger } from '../utils/logger.js';

/**
 * Service for rate limiting requests
 */
export class RateLimitService {
  /**
   * Creates a new rate limit service
   * 
   * @param {Object} options - Service options
   * @param {Object} options.env - Environment variables
   * @param {Object} options.defaultLimits - Default rate limit settings
   */
  constructor({ env, defaultLimits }) {
    this.env = env;
    this.defaultLimits = defaultLimits || {
      maxTokens: 5,
      refillRate: 5,
      refillTime: 60000, // 1 minute
    };
  }

  /**
   * Check if a request is rate limited
   * 
   * @param {Object} options - Rate limit check options
   * @param {string} options.identifier - Unique identifier for the client
   * @param {Object} options.limits - Rate limit settings to apply
   * @returns {Promise<Object>} Rate limit check result
   */
  async checkRateLimit({ identifier, limits }) {
    const reqLogger = logger.child({ 
      function: 'checkRateLimit',
      identifier: identifier.substring(0, 10) + '...' 
    });
    
    try {
      // Use provided limits or defaults
      const rateLimits = limits || this.defaultLimits;
      
      // Hash the identifier for privacy
      const hashedIdentifier = await hashValue(identifier);
      
      // Get the rate limiter durable object
      const rateLimiter = this.env.CHALLENGE_STATUS.get(
        this.env.CHALLENGE_STATUS.idFromName("rateLimiter")
      );
      
      // Create the request for checking the rate limit
      const rateLimitRequest = new Request(
        "https://challengestorage.internal/checkRateLimit",
        {
          method: "POST",
          headers: new Headers({
            "Content-Type": "application/json",
          }),
          body: JSON.stringify({
            identifier: hashedIdentifier,
            limits: rateLimits,
          }),
        }
      );
      
      // Perform the check
      const rateLimitResponse = await rateLimiter.fetch(rateLimitRequest);
      
      if (rateLimitResponse.status === 200) {
        reqLogger.debug('Request is within rate limits');
        return {
          allowed: true,
          remaining: null, // Could parse from response if included
        };
      } else if (rateLimitResponse.status === 429) {
        try {
          const responseBody = await rateLimitResponse.json();
          const cooldownEndTime = new Date(responseBody.cooldownEndTime).getTime();
          const now = Date.now();
          const remainingTime = Math.max(0, cooldownEndTime - now);
          
          reqLogger.info(
            { remainingTimeMs: remainingTime },
            'Rate limit exceeded'
          );
          
          return {
            allowed: false,
            remainingTime,
            cooldownEndTime: responseBody.cooldownEndTime,
          };
        } catch (parseError) {
          reqLogger.error(
            { err: parseError },
            'Failed to parse rate limit response'
          );
          
          // Default to allowing the request if we can't parse the response
          return { allowed: true };
        }
      } else {
        reqLogger.error(
          { status: rateLimitResponse.status },
          'Unexpected response from rate limiter'
        );
        
        // Default to allowing the request on unexpected response
        return { allowed: true };
      }
    } catch (error) {
      reqLogger.error({ err: error }, 'Rate limit check failed');
      
      // Default to allowing the request if rate limiting fails
      return { allowed: true };
    }
  }
}