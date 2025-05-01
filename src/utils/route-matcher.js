import { logger } from './logger.js';

/**
 * Utility for matching request paths against configured route patterns
 */
export class RouteMatcher {
  /**
   * Creates a new route matcher
   * 
   * @param {Array} routes - Array of route configuration objects
   */
  constructor(routes = []) {
    this.routes = routes.map(this.prepareRoute);
    
    // Debug log the routes we're matching against
    logger.debug(
      { routes: this.routes.map(r => ({ pattern: r.originalPattern, methods: r.methods })) },
      'Initialized route matcher'
    );
  }

  /**
   * Prepares a route for matching by converting pattern to regex
   * 
   * @param {Object} route - Route configuration
   * @returns {Object} Prepared route with regex
   */
  prepareRoute(route) {
    const { pattern, methods, ...rest } = route;
    
    // Convert glob-style patterns to regex patterns
    // * -> [^/]*
    // ** -> .*
    let regexPattern = pattern
      .replace(/\./g, '\\.')          // Escape dots
      .replace(/\*/g, '([^/]*)')      // Convert * to non-slash matcher
      .replace(/\(\[.*?\]\)/g, '.*'); // Convert ** => ([^/]*) => .*
    
    // Add anchor and ensure leading slash
    if (!regexPattern.startsWith('^')) {
      regexPattern = '^' + (regexPattern.startsWith('/') ? '' : '/') + regexPattern;
    }
    
    return {
      originalPattern: pattern,
      regex: new RegExp(regexPattern),
      methods: methods || ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
      ...rest
    };
  }

  /**
   * Checks if a request matches any of the configured routes
   * 
   * @param {string} path - Request URL path
   * @param {string} method - HTTP method
   * @returns {Object|null} Matching route or null if no match
   */
  match(path, method) {
    for (const route of this.routes) {
      // Check method first (faster than regex)
      if (route.methods.includes(method)) {
        if (route.regex.test(path)) {
          logger.debug(
            { path, method, pattern: route.originalPattern },
            'Request matches protected route'
          );
          return route;
        }
      }
    }
    
    return null;
  }

  /**
   * Updates the routes for this matcher
   * 
   * @param {Array} routes - New routes configuration
   */
  updateRoutes(routes) {
    this.routes = routes.map(this.prepareRoute);
    
    logger.info(
      { routeCount: this.routes.length },
      'Route matcher configuration updated'
    );
  }
}