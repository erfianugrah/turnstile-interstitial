import { logError } from '../utils/logger.js';

/**
 * Global error handler middleware for Hono
 * 
 * @returns {Function} Hono middleware
 */
export function errorHandlerMiddleware() {
  return async (c, next) => {
    try {
      await next();
    } catch (error) {
      const logger = c.get('logger');
      
      // Log the error with full details
      logError(logger, error, 'Request handler error');
      
      // Determine appropriate response format (JSON vs HTML)
      const acceptHeader = c.req.header('Accept') || '';
      const wantsHtml = acceptHeader.includes('text/html');
      
      // Set appropriate status code
      c.status(error.status || 500);
      
      // Generate appropriate response based on client's Accept header
      if (wantsHtml) {
        return c.html(
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
          </html>`
        );
      } else {
        return c.json({
          error: 'An unexpected error occurred',
          requestId: c.get('requestId')
        });
      }
    }
  };
}