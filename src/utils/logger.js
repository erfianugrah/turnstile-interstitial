import pino from 'pino';

/**
 * Creates a configured logger instance
 * 
 * @param {Object} options - Logger configuration options
 * @param {string} options.name - Name for this logger instance
 * @param {Object} options.env - Environment object for contextual data
 * @param {boolean} options.development - Whether to use pretty printing (development mode)
 * @returns {Object} Configured Pino logger
 */
export function createLogger({ name = 'turnstile-interstitial', env = {}, development = false }) {
  // Extract relevant environment info for the logger context
  const { ENVIRONMENT = 'production' } = env;
  
  const loggerOptions = {
    level: development ? 'debug' : 'info',
    base: {
      env: ENVIRONMENT,
      service: name,
    },
    timestamp: () => `,"time":"${new Date().toISOString()}"`,
    formatters: {
      // Add Cloudflare-specific request ID if available
      level: (label) => {
        return { level: label };
      }
    },
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'body.password',
        'body.token',
        'body.secret'
      ],
      censor: '[REDACTED]'
    }
  };

  return pino(loggerOptions);
}

/**
 * Default logger instance
 */
export const logger = createLogger({ name: 'turnstile-interstitial' });

/**
 * Create a request-scoped logger with request context
 * 
 * @param {Request} request - The HTTP request
 * @param {string} requestId - Unique identifier for the request
 * @returns {Object} Logger with request context
 */
export function createRequestLogger(request, requestId) {
  const url = new URL(request.url);
  
  return logger.child({
    req: {
      id: requestId,
      method: request.method,
      url: url.pathname,
      query: Object.fromEntries(url.searchParams.entries()),
      ip: request.headers.get('CF-Connecting-IP') || 'unknown',
      cf_ray: request.headers.get('CF-Ray') || 'unknown',
      user_agent: request.headers.get('User-Agent') || 'unknown'
    }
  });
}

/**
 * Log error with structured details
 * 
 * @param {Object} logger - Pino logger instance 
 * @param {Error} error - Error object
 * @param {string} message - Optional custom message
 */
export function logError(logger, error, message = 'An error occurred') {
  logger.error({
    err: {
      message: error.message,
      stack: error.stack,
      name: error.name,
      code: error.code
    },
    msg: message
  });
}