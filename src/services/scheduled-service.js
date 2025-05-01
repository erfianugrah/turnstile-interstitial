import { logger } from '../utils/logger.js';

/**
 * Service for handling scheduled tasks
 */
export class ScheduledService {
  /**
   * Handle scheduled cleanup tasks
   * 
   * @param {Object} env - Environment variables and bindings
   * @returns {Promise<void>}
   */
  static async handleScheduledCleanup(env) {
    const taskLogger = logger.child({ function: 'handleScheduledCleanup' });
    
    try {
      taskLogger.info('Starting scheduled cleanup task');
      const expirationTime = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
      let challengeCount = 0;
      let credentialsCount = 0;
      
      // Create a single cleanup request we can reuse
      const cleanupRequest = new Request("https://internal/cleanup", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ expirationTime }),
      });
      
      // Get a sample instance to run cleanup for all CHALLENGE_STATUS objects
      const challengeStatusCleanup = env.CHALLENGE_STATUS.get(
        env.CHALLENGE_STATUS.idFromName("cleanup-task")
      );
      
      taskLogger.debug('Running challenge status cleanup');
      const challengeResponse = await challengeStatusCleanup.fetch(cleanupRequest);
      if (challengeResponse.ok) {
        const result = await challengeResponse.json();
        challengeCount = result.cleanedCount || 0;
        taskLogger.info(
          { count: challengeCount },
          'Challenge status cleanup completed'
        );
      } else {
        taskLogger.error(
          { status: challengeResponse.status },
          'Challenge status cleanup failed'
        );
      }
      
      // Get a sample instance to run cleanup for all CREDENTIALS_STORAGE objects 
      const credentialsStorageCleanup = env.CREDENTIALS_STORAGE.get(
        env.CREDENTIALS_STORAGE.idFromName("cleanup-task")
      );
      
      taskLogger.debug('Running credentials storage cleanup');
      const credentialsResponse = await credentialsStorageCleanup.fetch(cleanupRequest);
      if (credentialsResponse.ok) {
        const result = await credentialsResponse.json();
        credentialsCount = result.cleanedCount || 0;
        taskLogger.info(
          { count: credentialsCount },
          'Credentials storage cleanup completed'
        );
      } else {
        taskLogger.error(
          { status: credentialsResponse.status },
          'Credentials storage cleanup failed'
        );
      }
      
      taskLogger.info(
        { 
          challengeCount,
          credentialsCount,
          totalRemoved: challengeCount + credentialsCount
        },
        'Scheduled cleanup completed successfully'
      );
    } catch (error) {
      taskLogger.error(
        { err: error },
        'Error during scheduled cleanup'
      );
    }
  }
}