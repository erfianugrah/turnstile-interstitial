import { Hono } from 'hono';
import { getClientIP } from '../utils/utils.js';
import { ChallengeService } from '../services/challenge-service.js';

const verifyRouter = new Hono();

/**
 * Handle verification of challenge responses
 * Processes the Turnstile challenge verification, stores successful verifications,
 * and handles request replay if needed
 */
verifyRouter.post('/', async (c) => {
  const { env } = c;
  const logger = c.get('logger');
  
  try {
    const formData = await c.req.formData();
    const token = formData.get("cf-turnstile-response");
    const ip = await getClientIP(c.req.raw);
    const originalUrl = formData.get("originalUrl");
    const requestId = formData.get("requestId");
    
    logger.debug(
      { token: token ? 'present' : 'missing', originalUrl, requestId },
      'Verify challenge form data'
    );

    // Validate inputs
    if (!token) {
      logger.warn('Missing Turnstile token in verification request');
      return c.text('Missing Turnstile token', 400);
    }
    
    if (!originalUrl) {
      logger.warn('Missing original URL in verification request');
      return c.text('Missing original URL', 400);
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
    logger.debug(
      { outcome, ip, originalUrl }, 
      'Turnstile verification result'
    );
    
    if (!outcome.success) {
      logger.warn(
        { outcome, ip }, 
        'Turnstile challenge verification failed'
      );
      return c.text('The provided Turnstile token was not valid!', 401);
    }

    // Get the cf_clearance value if present
    const cookies = c.req.raw.headers.get('Cookie');
    const cfMatch = cookies?.match(/cf_clearance=([^;]+)/);
    const cfClearanceValue = cfMatch ? cfMatch[1] : null;

    // If successful, store the verification result for this clearance value
    if (cfClearanceValue) {
      try {
        await ChallengeService.storeSuccessfulVerification(
          env, 
          cfClearanceValue, 
          ip
        );
        logger.info(
          { cfClearanceValue: cfClearanceValue.substring(0, 8) + '...' }, 
          'Stored successful verification'
        );
      } catch (storageError) {
        logger.error(
          { err: storageError }, 
          'Failed to store successful verification'
        );
      }
    }

    // If this was a POST request that we stored for replay
    if (requestId) {
      logger.info({ requestId }, 'Attempting to replay original request');
      
      try {
        // Attempt to replay the original request
        const replayResult = await ChallengeService.replayOriginalRequest(
          env, 
          requestId
        );
        
        if (replayResult.success) {
          logger.info(
            { requestId, status: replayResult.status }, 
            'Successfully replayed original request'
          );
          return replayResult.response;
        } else {
          logger.warn(
            { requestId, reason: replayResult.error }, 
            'Failed to replay original request'
          );
        }
      } catch (replayError) {
        logger.error(
          { err: replayError, requestId }, 
          'Error during request replay'
        );
      }
    }

    // If replay wasn't attempted or failed, redirect to the original URL
    logger.info({ redirectUrl: originalUrl }, 'Redirecting to original URL');
    return c.redirect(originalUrl, 302);
  } catch (error) {
    logger.error({ err: error }, 'Error handling verification');
    return c.text('Verification error', 500);
  }
});

export default verifyRouter;