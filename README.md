# Turnstile Interstitial

This document explains the implementation of an authentication system using Cloudflare Workers and Durable Objects. The system employs a challenge-response mechanism for user verification, encrypts and stores credentials using Durable Objects, and handles login attempts with real-time IP address verification. It leverages Cloudflare's edge computing capabilities for security and performance.

## Overview

The implementation is divided into several parts:

- **ChallengeStatusStorage**: Manages the storage and retrieval of timestamp and IP address associated with a challenge verification using Durable Objects.
- **CredentialsStorage**: Handles the encryption, storage, and retrieval of user credentials using Durable Objects.
- **Main Fetch Handler**: Orchestrates the handling of different request paths, including login and verification processes.
- **Utility Functions**: Includes functions for encryption, decryption, hashing, and challenge verification.

### ChallengeStatusStorage

This Durable Object class is responsible for storing and retrieving the timestamp and IP address when a user completes a challenge, ensuring real-time verification.

- **/getTimestampAndIP**: Retrieves the stored timestamp and IP address.
- **/storeTimestampAndIP**: Stores the current timestamp and the client's IP address.

```javascript
class ChallengeStatusStorage {
  constructor(state, env) {
    this.state = state;
  }

  async fetch(request) {
    // Implementation...
  }
}
```

### CredentialsStorage

Manages user credentials securely by encrypting data before storage and decrypting it upon retrieval, using Durable Objects for secure and isolated storage.

- **/store**: Encrypts and stores user credentials.
- **/retrieve**: Retrieves and decrypts user credentials, then deletes them from storage.

```javascript
class CredentialsStorage {
  constructor(state, env) {
    this.state = state;
  }

  async fetch(request) {
    // Implementation...
  }
}
```

### Main Fetch Handler

The primary entry point for handling requests. It routes requests based on their path and method, integrating with the challenge verification and login processes.

```javascript
async fetch(request, env, ctx) {
  // Implementation...
}
```

### Utility Functions

- **generateEncryptionKey**: Generates an AES-GCM encryption key.
- **encryptData**: Encrypts data using the generated key and a random IV.
- **decryptData**: Decrypts data using the provided key and IV.
- **hashValue**: Generates a SHA-256 hash of a given value.
- **getCfClearanceValue**: Extracts the `cf_clearance` cookie value from a request.
- **handleLoginRequest**: Handles GET and POST requests to `/login` and `/api/login`.
- **verifyChallengeStatus**: Verifies the challenge status by comparing stored data with the current request.
- **verifyChallenge**: Verifies the challenge response using Cloudflare's Turnstile API.
- **serveChallengePage**: Serves a challenge page with Cloudflare's Turnstile widget for user verification.

## Security Considerations

- **Encryption**: User credentials are encrypted before storage, ensuring data confidentiality.
- **IP Verification**: The challenge verification process includes IP address checking to prevent replay attacks.
- **Challenge Mechanism**: Utilizes Cloudflare's Turnstile to protect against bots and automated attacks.

## Dependencies

- **Cloudflare Workers**: The implementation is designed to run on Cloudflare's edge computing platform.
- **Durable Objects**: Used for storing timestamps, IP addresses, and encrypted credentials, providing strong consistency and isolation for data storage.
- **Cloudflare Turnstile**: Provides the challenge-response mechanism for user verification.

## Limitations
- **Client-side JS**: This is still required if the login endpoint is an API endpoint, form is rendered by JS, therefore no strict HTML forms that can be used/manipulated

