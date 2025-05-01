import { BaseStorage } from './base-storage.js';
import { generateEncryptionKey, encryptData, decryptData } from '../utils/utils.js';
import { logger } from '../utils/logger.js';

/**
 * Durable Object for securely storing and retrieving credentials and request data
 */
export class CredentialsStorage extends BaseStorage {
  constructor(state, env) {
    super(state);
    this.env = env;
    
    // Create a logger instance for this durable object
    this.logger = logger.child({
      durableObject: 'CredentialsStorage',
      id: state.id.toString().substring(0, 8) + '...'
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    
    try {
      if (url.pathname === "/store") {
        // Extract request ID from URL or use a default
        const requestId = url.searchParams.get('id') || crypto.randomUUID();
        
        // Generate a stable key based on the request ID for this credential
        const key = await generateEncryptionKey(this.env, requestId);
        const details = await request.json();
        
        // Encrypt the data with the derived key
        const { encryptedData, iv } = await encryptData(
          key,
          JSON.stringify(details),
        );
        
        // Store the data with a lastAccess timestamp and the request ID
        await this.state.storage.put(
          requestId, // Use the request ID as the storage key
          JSON.stringify({
            encryptedData: Array.from(new Uint8Array(encryptedData)),
            iv: Array.from(iv),
            lastAccess: Date.now(),
            id: requestId,
          }),
        );
        
        this.logger.info(
          { requestId },
          'Stored encrypted data'
        );
        
        // Return the ID to the caller so they can retrieve it later
        return new Response(JSON.stringify({ id: requestId }), { 
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      } else if (url.pathname === "/retrieve") {
        // Get the credential ID from query params
        const credentialId = url.searchParams.get('id');
        
        if (!credentialId) {
          this.logger.warn('Retrieve request missing credential ID');
          return new Response(JSON.stringify({ error: "Missing credential ID" }), {
            status: 400,
            headers: { "Content-Type": "application/json" },
          });
        }
        
        // Get the stored data for this credential ID
        const encryptedStorage = await this.state.storage.get(credentialId);
        
        if (!encryptedStorage) {
          this.logger.warn(
            { credentialId },
            'No credentials found with provided ID'
          );
          
          return new Response(JSON.stringify({ error: "No credentials found with that ID" }), {
            status: 404,
            headers: { "Content-Type": "application/json" },
          });
        }
        
        try {
          // Generate the same key we used for encryption
          const key = await generateEncryptionKey(this.env, credentialId);
          
          const { encryptedData, iv } = JSON.parse(encryptedStorage);
          const decryptedData = await decryptData(
            key,
            new Uint8Array(encryptedData),
            new Uint8Array(iv),
          );
          
          // Delete after retrieval for security
          await this.state.storage.delete(credentialId);
          
          this.logger.info(
            { credentialId },
            'Successfully retrieved and deleted credential data'
          );
          
          return new Response(decryptedData, { 
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        } catch (decryptError) {
          this.logger.error(
            { err: decryptError, credentialId },
            'Failed to decrypt credential data'
          );
          
          return new Response(JSON.stringify({ error: "Failed to decrypt data" }), {
            status: 500,
            headers: { "Content-Type": "application/json" },
          });
        }
      } else if (url.pathname === "/cleanup") {
        // Parse the expiration time from request body or use default (24 hours)
        let expirationTime = 24 * 60 * 60 * 1000;
        try {
          const body = await request.json();
          if (body && body.expirationTime) {
            expirationTime = parseInt(body.expirationTime, 10);
          }
        } catch (e) {
          // If parsing fails, use the default
        }
        
        const cleanedCount = await this.cleanupExpiredData(expirationTime);
        return new Response(JSON.stringify({ cleanedCount }), {
          headers: { "Content-Type": "application/json" },
        });
      } else if (url.pathname === "/list") {
        // List all stored credentials (ids only for security) 
        const keys = await this.state.storage.list();
        const credentialIds = [...keys.keys()];
        
        this.logger.info(
          { count: credentialIds.length },
          'Listed stored credential IDs'
        );
        
        return new Response(JSON.stringify({ 
          count: credentialIds.length,
          ids: credentialIds 
        }), {
          headers: { "Content-Type": "application/json" },
        });
      }
      
      return new Response("Not found", { status: 404 });
    } catch (error) {
      this.logger.error(
        { err: error, path: url.pathname },
        'Error in CredentialsStorage'
      );
      
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }
}