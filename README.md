# Turnstile Interstitial

This system is designed to enforce rate limiting on web requests while providing a mechanism for users to verify themselves via a challenge when they exceed the rate limit. It utilizes Cloudflare Workers and Durable Objects to track request counts and cooldown periods for clients based on their IP address and `cf_clearance` cookie.

## Features

- **Rate Limiting**: Limits the number of requests a user can make within a specified time frame, helping to protect against abuse and excessive traffic.
- **Challenge Verification**: Presents a challenge to users who exceed the rate limit, allowing legitimate users to continue after successful verification.
- **Durable Storage**: Utilizes Durable Objects for persistent storage of rate limit counters and timestamps, ensuring consistency across requests.
- **Flexible Response**: Serves either HTML or JSON responses based on the client's `Accept` header, accommodating both browser-based and API clients.

## Components

### `ChallengeStatusStorage` Durable Object

Responsible for tracking rate limit counters and timestamps for each client IP and `cf_clearance` cookie pair.

#### Endpoints

- `/getTimestampAndIP`: Retrieves the stored timestamp and IP address.
- `/storeTimestampAndIP`: Stores or updates the timestamp and IP address.
- `/deleteTimestampAndIP`: Deletes the stored timestamp and IP address.
- `/checkRateLimit`: Checks if the client has exceeded the rate limit.

### `CredentialsStorage` Durable Object

Manages encrypted storage of sensitive data, such as credentials or verification details.

#### Endpoints

- `/store`: Encrypts and stores data.
- `/retrieve`: Decrypts and retrieves stored data, then deletes it from storage.

### Main Worker Script

Handles incoming requests, directing them to the appropriate Durable Object or function based on the request path.

#### Functions

- `getCfClearanceValue`: Extracts the `cf_clearance` cookie value from the request.
- `handleLoginRequest`: Processes login requests, checking rate limits and serving challenges as necessary.
- `handleGetLogin` and `handlePostLogin`: Handle specific login request methods, verifying challenges or storing login attempts.
- `handleVerifyRequest`: Processes challenge verification responses.
- `serveChallengePage`: Serves the challenge page to the client, with logic to respond with JSON for non-browser clients.
- `serveRateLimitPage`: Informs the client they have exceeded the rate limit, with logic to respond with JSON for non-browser clients.

## Usage

1. **Rate Limit Checking**: Upon receiving a request, the system checks if the client has exceeded their rate limit using the `/checkRateLimit` endpoint of the `ChallengeStatusStorage` Durable Object.
2. **Serving Challenges**: If the rate limit is exceeded, the client is served a challenge page (or JSON message for API clients) to verify themselves.
3. **Verification and Access**: After successful verification, the client's rate limit counter is reset, allowing them to continue making requests.

## Deployment

1. Deploy the Durable Objects (`ChallengeStatusStorage` and `CredentialsStorage`) to your Cloudflare Workers environment.
2. Deploy the main worker script, ensuring it's configured to route requests to the appropriate Durable Object or function based on the URL path.
3. Configure rate limit settings (max tokens, refill rate, and refill time) as needed for your application's requirements.

## Security Considerations

- Ensure that the challenge mechanism is robust and capable of distinguishing between legitimate users and automated traffic.
- Regularly rotate the encryption key used by `CredentialsStorage` to secure stored data.
- Monitor for unusual patterns of traffic or verification attempts that may indicate attempts to bypass the rate limiting system.

## Limitations

- **Client-side JS**: This is still required if the login endpoint is an API endpoint, form is rendered by JS, therefore no strict HTML forms that can be used/manipulated.

---

*README Generated by Phind cause I'm lazy*