import { logger } from '../utils/logger.js';

/**
 * Base storage class for Durable Objects
 * Provides common functionality like cleaning up expired data
 */
export class BaseStorage {
  constructor(state) {
    this.state = state;
  }

  /**
   * Cleans up data that has expired based on a specified time threshold
   * @param {number} expirationTime - Time in milliseconds after which data is considered expired
   * @returns {Promise<number>} Number of items cleaned up
   */
  async cleanupExpiredData(expirationTime) {
    try {
      const keys = await this.state.storage.list();
      const currentTime = Date.now();
      let cleanedCount = 0;

      for (const key of keys) {
        try {
          const rawData = await this.state.storage.get(key);
          if (!rawData) continue;
          
          const data = JSON.parse(rawData);
          if (
            data && data.lastAccess &&
            currentTime - data.lastAccess > expirationTime
          ) {
            await this.state.storage.delete(key);
            cleanedCount++;
          }
        } catch (keyError) {
          logger.error(
            { err: keyError, key },
            'Error cleaning up specific key'
          );
          // Continue processing other keys even if one fails
        }
      }
      
      logger.info(
        { cleanedCount, expirationTimeMs: expirationTime },
        'Cleaned up expired entries'
      );
      return cleanedCount;
    } catch (error) {
      logger.error(
        { err: error },
        'Failed to clean up expired data'
      );
      throw error; // Re-throw to allow caller to handle
    }
  }
}