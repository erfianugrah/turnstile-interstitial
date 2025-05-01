import { z } from 'zod';

/**
 * Route configuration schema
 * Defines the schema for a protected route
 */
export const RouteSchema = z.object({
  /**
   * Path pattern for the route (supports regex-like syntax)
   * Examples: '/api/auth/login', '/api/*', '/admin/*'
   */
  pattern: z.string().min(1),
  
  /**
   * HTTP methods to protect (defaults to all)
   */
  methods: z.array(
    z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'])
  ).default(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']),
  
  /**
   * Rate limit settings specific to this route
   */
  rateLimit: z.object({
    /**
     * Maximum number of requests allowed in the time window
     */
    maxTokens: z.number().int().positive().default(5),
    
    /**
     * Number of tokens to refill
     */
    refillRate: z.number().int().positive().default(5),
    
    /**
     * Time window in milliseconds
     */
    refillTime: z.number().int().positive().default(60000),
  }).optional(),
  
  /**
   * Whether to bypass the challenge for API requests
   * When true, API requests get JSON responses instead of HTML challenge
   */
  apiBypass: z.boolean().default(false),
});

/**
 * Global configuration schema
 */
export const ConfigSchema = z.object({
  /**
   * Array of routes to protect
   */
  routes: z.array(RouteSchema).min(1),
  
  /**
   * Global rate limit settings (applied to all routes unless overridden)
   */
  rateLimit: z.object({
    /**
     * Maximum number of requests allowed in the time window
     */
    maxTokens: z.number().int().positive().default(5),
    
    /**
     * Number of tokens to refill
     */
    refillRate: z.number().int().positive().default(5),
    
    /**
     * Time window in milliseconds
     */
    refillTime: z.number().int().positive().default(60000),
  }),
  
  /**
   * Time window for challenge validity in milliseconds
   */
  challengeValidityTime: z.number().int().positive().default(150000),
});

/**
 * Parses and validates configuration
 * 
 * @param {Object} config - Raw configuration object
 * @returns {Object} Validated configuration with defaults applied
 * @throws {Error} If configuration is invalid
 */
export function parseConfig(config) {
  try {
    return ConfigSchema.parse(config);
  } catch (error) {
    if (error.errors) {
      // Format Zod validation errors nicely
      const formattedErrors = error.errors.map(err => 
        `${err.path.join('.')}: ${err.message}`
      ).join('; ');
      
      throw new Error(`Invalid configuration: ${formattedErrors}`);
    }
    throw error;
  }
}

/**
 * Default configuration
 */
export const defaultConfig = {
  routes: [
    {
      pattern: '/api/auth/login',
      methods: ['POST'],
    },
    {
      pattern: '/login',
      methods: ['GET', 'POST'],
    }
  ],
  rateLimit: {
    maxTokens: 5,
    refillRate: 5,
    refillTime: 60000, // 1 minute
  },
  challengeValidityTime: 150000, // 2.5 minutes
};