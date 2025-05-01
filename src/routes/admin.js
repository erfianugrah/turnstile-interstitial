import { Hono } from 'hono';
import { parseConfig } from '../schemas/config.js';

const adminRouter = new Hono();

/**
 * Get current configuration
 */
adminRouter.get('/config', async (c) => {
  const logger = c.get('logger');
  const configService = c.get('configService');
  
  try {
    const config = await configService.getConfig();
    logger.info('Admin requested current configuration');
    return c.json(config);
  } catch (error) {
    logger.error({ err: error }, 'Failed to retrieve configuration');
    return c.json({ error: 'Failed to retrieve configuration' }, 500);
  }
});

/**
 * Update configuration
 */
adminRouter.put('/config', async (c) => {
  const logger = c.get('logger');
  const configService = c.get('configService');
  
  try {
    const newConfig = await c.req.json();
    
    // Validate the new config
    try {
      parseConfig(newConfig);
    } catch (validationError) {
      logger.warn(
        { err: validationError, config: newConfig },
        'Invalid configuration submitted'
      );
      return c.json({ error: validationError.message }, 400);
    }
    
    // Update the config
    const success = await configService.updateConfig(newConfig);
    
    if (success) {
      logger.info('Configuration updated successfully');
      return c.json({ success: true });
    } else {
      logger.error('Failed to update configuration');
      return c.json({ error: 'Failed to update configuration' }, 500);
    }
  } catch (error) {
    logger.error({ err: error }, 'Error processing config update');
    return c.json({ error: 'Error processing config update' }, 500);
  }
});

/**
 * Debug route to check KV namespace status
 */
adminRouter.get('/debug', async (c) => {
  const logger = c.get('logger');
  const configService = c.get('configService');
  const env = c.env;
  
  try {
    // Check if KV namespace is accessible
    const kvStatus = {
      namespaceExists: !!env.TURNSTILE_CONFIG,
      bindingType: typeof env.TURNSTILE_CONFIG,
      listKeys: []
    };
    
    // List keys if namespace exists
    if (env.TURNSTILE_CONFIG) {
      try {
        const listResult = await env.TURNSTILE_CONFIG.list();
        kvStatus.listKeys = listResult.keys.map(key => key.name);
      } catch (listError) {
        kvStatus.listError = listError.message;
      }
    }
    
    return c.json({
      debug: {
        kvStatus,
        currentConfig: await configService.getConfig(),
        env: {
          MAX_TOKENS: env.MAX_TOKENS,
          REFILL_RATE: env.REFILL_RATE,
          REFILL_TIME: env.REFILL_TIME,
          TIME_TO_CHALLENGE: env.TIME_TO_CHALLENGE,
          // Don't include sensitive values
          HAS_SITE_KEY: !!env.SITE_KEY,
          HAS_SECRET_KEY: !!env.SECRET_KEY,
          HAS_ADMIN_PASSWORD: !!env.ADMIN_PASSWORD
        }
      }
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to get debug information');
    return c.json({ error: 'Failed to retrieve debug information' }, 500);
  }
});

export default adminRouter;