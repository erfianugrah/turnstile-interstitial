import { createRequestLogger } from '../utils/logger.js';

/**
 * Middleware to add request logging to Hono
 * Creates a request-scoped logger and attaches it to the context
 * 
 * @returns {Function} Hono middleware
 */
export function loggerMiddleware() {
  return async (c, next) => {
    const start = Date.now();
    const requestId = crypto.randomUUID();
    
    // Create a request-scoped logger
    const reqLogger = createRequestLogger(c.req.raw, requestId);
    
    // Attach logger to the context
    c.set('requestId', requestId);
    c.set('logger', reqLogger);
    
    // Log the incoming request
    reqLogger.info({
      msg: `${c.req.method} ${c.req.path} - Request received`,
    });
    
    try {
      // Pass to the next handler
      await next();
      
      // Calculate request duration
      const responseTime = Date.now() - start;
      
      // Log completion with response code and time
      reqLogger.info({
        msg: `${c.req.method} ${c.req.path} - Response sent`,
        res: {
          status: c.res.status,
          responseTime: `${responseTime}ms`
        }
      });
    } catch (error) {
      // Calculate request duration even for errors
      const responseTime = Date.now() - start;
      
      // Log error
      reqLogger.error({
        msg: `${c.req.method} ${c.req.path} - Request failed`,
        err: {
          message: error.message,
          stack: error.stack,
          name: error.name
        },
        res: {
          status: error.status || 500,
          responseTime: `${responseTime}ms`
        }
      });
      
      // Re-throw to let error handlers deal with it
      throw error;
    }
  };
}