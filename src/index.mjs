import { Hono } from 'hono';
import { ScheduledService } from './services/scheduled-service.js';
import { ConfigService } from './services/config-service.js';
import { logger, createRequestLogger } from './utils/logger.js';
import { loggerMiddleware } from './middleware/logger.js';
import { errorHandlerMiddleware } from './middleware/error-handler.js';
import { createInterstitialMiddleware } from './middleware/interstitial.js';

// Import routes
import verifyRouter from './routes/verify.js';
import adminRouter from './routes/admin.js';

// Import Durable Objects
export { ChallengeStatusStorage } from './durable-objects/challenge-status-storage.js';
export { CredentialsStorage } from './durable-objects/credentials-storage.js';

// Scheduled cleanup task - runs once per day (see wrangler.toml or jsonc cron setting)
addEventListener("scheduled", (event) => {
  event.waitUntil(
    (async () => {
      try {
        await ScheduledService.handleScheduledCleanup(event.env);
      } catch (error) {
        logger.error(
          { err: error },
          'Unhandled error in scheduled cleanup'
        );
      }
    })(),
  );
});

// Setup the worker entry point
export default {
  async fetch(request, env, ctx) {
    // Create a new Hono app instance for each request
    const app = new Hono();
    
    // Create the config service
    const configService = new ConfigService({
      kv: env.TURNSTILE_CONFIG,
      env,
    });
    
    // Get the configuration
    const config = await configService.getConfig();
    
    // Apply the interstitial middleware to the app based on configuration
    const interstitialMiddleware = createInterstitialMiddleware({
      config,
      env,
    });
    
    // Setup global middleware first
    app.use('*', loggerMiddleware());
    app.use('*', errorHandlerMiddleware());
    
    // Add the interstitial middleware to all routes
    app.use('*', async (c, next) => {
      // Make config service available to handlers
      c.set('configService', configService);
      
      // Apply the interstitial middleware
      return interstitialMiddleware(c, next);
    });
    
    // Admin routes - protected with basic auth
    app.use('/admin/*', async (c, next) => {
      // Skip auth check for debug endpoint in development
      const isDev = c.env.ENVIRONMENT === 'development';
      const isDebugEndpoint = c.req.path === '/admin/debug';
      
      // Skip auth for debug endpoint in development or allow auth fallback
      if (isDev && isDebugEndpoint) {
        return next();
      }
      
      // Simple admin protection using a basic auth check
      const authHeader = c.req.header('Authorization');
      
      if (!authHeader || !authHeader.startsWith('Basic ')) {
        return new Response('Unauthorized', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'Basic realm="Admin Area"',
          },
        });
      }
      
      // Decode the credentials
      const credentials = atob(authHeader.substring(6));
      const [username, password] = credentials.split(':');
      
      // Check if credentials are valid or use fallback for development
      const validAdmin = username === 'admin' && password === c.env.ADMIN_PASSWORD;
      const validFallback = isDev && username === 'admin' && password === 'development';
      
      if (!validAdmin && !validFallback) {
        return new Response('Unauthorized', {
          status: 401,
          headers: {
            'WWW-Authenticate': 'Basic realm="Admin Area"',
          },
        });
      }
      
      return next();
    });
    
    // Register routes
    app.route('/verify', verifyRouter);
    app.route('/admin', adminRouter);
    
    // Add a catch-all handler for proxying requests to the origin
    app.all('*', async (c) => {
      const logger = c.get('logger');
      
      // Check if the request has passed interstitial checks
      // If we've reached here, it means all middleware has been passed
      logger.info(
        { path: c.req.path, method: c.req.method },
        'Proxying request to origin'
      );
      
      // Clone the original request and pass it through
      try {
        // Get the original fetch method to avoid intercepting
        const originalFetch = globalThis.fetch;
        
        // Create a new request based on the original
        const url = new URL(c.req.url);
        
        // Use the same request method, headers, and body
        const proxyRequest = new Request(url.toString(), {
          method: c.req.method,
          headers: c.req.raw.headers,
          body: c.req.method !== 'GET' && c.req.method !== 'HEAD' ? await c.req.raw.clone().arrayBuffer() : undefined,
          redirect: 'manual' // Don't follow redirects automatically
        });
        
        // Forward the request to the origin
        const response = await originalFetch(proxyRequest);
        
        // Return the response from origin
        return response;
      } catch (error) {
        logger.error(
          { err: error, path: c.req.path },
          'Error proxying request to origin'
        );
        
        return c.text(`Error proxying request: ${error.message}`, 500);
      }
    });
    
    // Handle the request
    return app.fetch(request, env, ctx);
  }
};