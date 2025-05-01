import { getClientIP, getCfClearanceValue } from '../utils/utils.js';
import { ChallengeService } from '../services/challenge-service.js';
import { serveChallengePage, serveRateLimitPage } from '../services/static-page-service.js';
import { RateLimitService } from '../services/rate-limit-service.js';
import { RouteMatcher } from '../utils/route-matcher.js';

/**
 * Creates the interstitial challenge middleware
 * Protects routes based on configuration and handles rate limiting
 * 
 * @param {Object} options - Middleware options
 * @param {Object} options.config - Challenge configuration
 * @param {Object} options.env - Environment variables
 * @returns {Function} Hono middleware
 */
export function createInterstitialMiddleware({ config, env }) {
  // Create a route matcher from config
  const routeMatcher = new RouteMatcher(config.routes);
  
  // Create rate limit service
  const rateLimitService = new RateLimitService({
    env,
    defaultLimits: config.rateLimit
  });
  
  return async (c, next) => {
    const logger = c.get('logger');
    const request = c.req.raw;
    const path = c.req.path;
    const method = c.req.method;
    
    // Check if this route should be protected
    const matchedRoute = routeMatcher.match(path, method);
    
    // If not a protected route, pass through
    if (!matchedRoute) {
      return next();
    }
    
    // Extract clearance cookie
    const cfClearanceMatch = await getCfClearanceValue(request);
    const cfClearanceValue = cfClearanceMatch ? cfClearanceMatch[1] : null;
    
    // Extract client IP
    const clientIP = getClientIP(request);
    
    // If no clearance cookie, show challenge
    if (!cfClearanceValue) {
      logger.info({ path, method }, 'No clearance cookie, serving challenge');
      return serveChallengePage(env, request);
    }
    
    // Check if the challenge has been verified for this clearance cookie
    const isVerified = await ChallengeService.verifyChallengeStatus(
      request, 
      env, 
      cfClearanceValue
    );
    
    if (!isVerified) {
      logger.info(
        { path, method, cfClearance: cfClearanceValue.substring(0, 5) + '...' },
        'Challenge not verified, serving challenge page'
      );
      return serveChallengePage(env, request);
    }
    
    // Get the rate limit settings for this route
    const rateLimitSettings = matchedRoute.rateLimit || config.rateLimit;
    
    // Check rate limit
    const rateLimitResult = await rateLimitService.checkRateLimit({
      identifier: `${clientIP}-${cfClearanceValue}`,
      limits: rateLimitSettings
    });
    
    if (!rateLimitResult.allowed) {
      logger.info(
        { 
          path, 
          method, 
          ip: clientIP.substring(0, 8) + '...',
          remainingTime: rateLimitResult.remainingTime 
        },
        'Rate limit exceeded'
      );
      
      const cooldownEndTime = new Date(Date.now() + rateLimitResult.remainingTime);
      return serveRateLimitPage(cooldownEndTime, request);
    }
    
    // If we got here, the request is allowed to proceed
    logger.debug(
      { path, method },
      'Request passed challenge and rate limit checks'
    );
    
    // Mark the request as verified in the headers
    // This allows the origin server to know the challenge was completed
    c.req.raw.headers.set('X-Turnstile-Verified', 'true');
    
    // Remove CF-Worker header to ensure origin content is preserved
    // This header can sometimes trigger different behavior in Cloudflare
    c.req.raw.headers.delete('CF-Worker');
    
    return next();
  };
}