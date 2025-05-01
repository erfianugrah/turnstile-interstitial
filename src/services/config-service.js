import { parseConfig, defaultConfig } from '../schemas/config.js';
import { logger } from '../utils/logger.js';

/**
 * Configuration service for managing and retrieving app config
 */
export class ConfigService {
  /**
   * Creates a new configuration service
   * 
   * @param {Object} options - Service options
   * @param {KVNamespace} options.kv - Cloudflare KV namespace for configuration storage
   * @param {Object} options.env - Environment variables
   */
  constructor({ kv, env }) {
    this.kv = kv;
    this.env = env;
    this.cachedConfig = null;
    this.cacheTime = 0;
    this.cacheTtl = 60 * 1000; // 1 minute cache TTL
  }

  /**
   * Retrieves configuration from KV or uses the default config
   * Implements caching to reduce KV reads
   * If no configuration exists in KV, it will attempt to initialize it with the default config
   * 
   * @returns {Promise<Object>} The parsed and validated configuration
   */
  async getConfig() {
    // Check if we have a valid cached config
    if (this.cachedConfig && (Date.now() - this.cacheTime < this.cacheTtl)) {
      return this.cachedConfig;
    }

    try {
      // Try to get config from KV
      let config;
      
      // Get from KV if available
      if (this.kv) {
        const storedConfig = await this.kv.get('config', { type: 'json' });
        
        if (storedConfig) {
          logger.debug('Retrieved configuration from KV');
          config = storedConfig;
        } else {
          logger.info('No configuration found in KV, using default');
          config = defaultConfig;
          
          // Try to initialize the KV with default config
          try {
            await this.kv.put('config', JSON.stringify(defaultConfig));
            logger.info('Initialized KV store with default configuration');
          } catch (initError) {
            logger.error(
              { err: initError }, 
              'Failed to initialize KV with default config'
            );
          }
        }
      } else {
        // If KV is not available, use default config
        logger.warn('KV namespace not available, using default configuration');
        config = defaultConfig;
      }
      
      // Merge config with env vars if available
      config = this.mergeWithEnvVars(config);

      // Parse and validate
      const validatedConfig = parseConfig(config);
      
      // Update cache
      this.cachedConfig = validatedConfig;
      this.cacheTime = Date.now();
      
      return validatedConfig;
    } catch (error) {
      logger.error({ err: error }, 'Error loading configuration, falling back to defaults');
      
      // In case of any error, use the default config
      const validatedConfig = parseConfig(defaultConfig);
      
      // Update cache even for default config to prevent repeated failures
      this.cachedConfig = validatedConfig;
      this.cacheTime = Date.now();
      
      return validatedConfig;
    }
  }

  /**
   * Updates the configuration in KV
   * 
   * @param {Object} newConfig - New configuration object
   * @returns {Promise<boolean>} Success status
   */
  async updateConfig(newConfig) {
    try {
      if (!this.kv) {
        logger.error('Cannot update config: KV namespace not available');
        return false;
      }
      
      // Validate before storing
      const validatedConfig = parseConfig(newConfig);
      
      // Store in KV
      await this.kv.put('config', JSON.stringify(validatedConfig));
      
      // Update cache
      this.cachedConfig = validatedConfig;
      this.cacheTime = Date.now();
      
      logger.info('Configuration updated successfully');
      return true;
    } catch (error) {
      logger.error({ err: error }, 'Failed to update configuration');
      return false;
    }
  }

  /**
   * Merges configuration with environment variables if available
   * Environment variables take precedence over stored config
   * 
   * @param {Object} config - Base configuration
   * @returns {Object} Merged configuration
   */
  mergeWithEnvVars(config) {
    // Deep clone the config to avoid mutations
    const mergedConfig = JSON.parse(JSON.stringify(config));
    
    // Override with environment variables if available
    if (this.env.MAX_TOKENS) {
      mergedConfig.rateLimit.maxTokens = parseInt(this.env.MAX_TOKENS, 10);
    }
    
    if (this.env.REFILL_RATE) {
      mergedConfig.rateLimit.refillRate = parseInt(this.env.REFILL_RATE, 10);
    }
    
    if (this.env.REFILL_TIME) {
      mergedConfig.rateLimit.refillTime = parseInt(this.env.REFILL_TIME, 10);
    }
    
    if (this.env.TIME_TO_CHALLENGE) {
      mergedConfig.challengeValidityTime = parseInt(this.env.TIME_TO_CHALLENGE, 10);
    }
    
    return mergedConfig;
  }
}