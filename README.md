# Turnstile Interstitial

A powerful, configurable Cloudflare Worker for implementing Turnstile challenge interstitials and rate limiting with automatic replay of POST requests.

## Features

- **Rate Limiting**: Configurable token-bucket based rate limiting with automatic cooldown
- **Challenge Verification**: Presents a Turnstile challenge to users who exceed the rate limit
- **Request Replay**: Automatically captures and replays POST requests after successful verification
- **Dynamic Configuration**: Routes and settings can be configured via KV or environment variables
- **Structured Logging**: Comprehensive logging with Pino for better debugging and monitoring
- **Modern Architecture**: Built with Hono framework for routing and middleware

## Architecture

The system is built on Cloudflare Workers with the following components:

### Core Components

- **Hono Framework**: For routing, middleware, and request handling
- **Pino Logger**: For structured, level-based logging
- **Zod**: For configuration schema validation
- **Durable Objects**: For stateful operations like rate limiting and credential storage
- **KV Storage**: For persistent configuration

### File Structure

```
src/
├── durable-objects/        # Durable Object implementations
│   ├── base-storage.js     # Base class with common functionality
│   ├── challenge-status-storage.js
│   └── credentials-storage.js
├── middleware/             # Hono middleware
│   ├── error-handler.js    # Global error handling
│   ├── interstitial.js     # Challenge interstitial middleware
│   └── logger.js           # Request logging middleware
├── routes/                 # Route handlers
│   ├── admin.js            # Admin API for configuration
│   └── verify.js           # Challenge verification endpoints
├── schemas/                # Zod schemas
│   └── config.js           # Configuration schema and validation
├── services/               # Business logic services
│   ├── challenge-service.js
│   ├── config-service.js
│   ├── rate-limit-service.js
│   ├── scheduled-service.js
│   └── static-page-service.js
├── utils/                  # Utility functions
│   ├── logger.js           # Logger configuration
│   ├── route-matcher.js    # Route pattern matching
│   └── utils.js            # General utilities
└── index.mjs               # Main entry point
```

## Configuration

The system can be configured through the KV storage or environment variables. Configuration includes:

### Route Configuration

Routes that should be protected by the interstitial are configurable:

```json
{
  "routes": [
    {
      "pattern": "/api/auth/login",
      "methods": ["POST"],
      "rateLimit": {
        "maxTokens": 5,
        "refillRate": 5,
        "refillTime": 60000
      }
    },
    {
      "pattern": "/login",
      "methods": ["GET", "POST"]
    }
  ],
  "rateLimit": {
    "maxTokens": 5,
    "refillRate": 5,
    "refillTime": 60000
  },
  "challengeValidityTime": 150000
}
```

### Route Pattern Matching

Routes can be defined with glob-style patterns:

- `/api/auth/login` - Exact match
- `/api/*` - Match anything under `/api/` (single level)
- `/admin/**` - Match anything under `/admin/` (multiple levels)

### Environment Variables

- `MAX_TOKENS`: Maximum number of tokens for rate limiting (default: 5)
- `REFILL_RATE`: Number of tokens to refill (default: 5)
- `REFILL_TIME`: Time in milliseconds between refills (default: 60000)
- `TIME_TO_CHALLENGE`: Time in milliseconds that a challenge is valid (default: 150000)
- `SITE_KEY`: Cloudflare Turnstile site key
- `SECRET_KEY`: Cloudflare Turnstile secret key
- `ADMIN_PASSWORD`: Password for admin API access

## Administration

The system includes an admin API for managing configuration:

- `GET /admin/config` - Get the current configuration
- `PUT /admin/config` - Update the configuration

Admin endpoints are protected with basic authentication.

## Rate Limiting

Rate limiting is implemented using a token bucket algorithm:

1. Each client (identified by IP + Cloudflare clearance cookie) has a bucket of tokens
2. Each request consumes one token from the bucket
3. Tokens are refilled at a configurable rate
4. When a client runs out of tokens, they must complete a Turnstile challenge

## Challenge Flow

1. User makes a request to a protected endpoint
2. If they've exceeded their rate limit, they're presented with a Turnstile challenge
3. Upon successful verification, the original request is replayed automatically
4. For POST requests, the original request body and headers are preserved

## Deployment

1. Create a KV namespace for configuration:
   ```
   wrangler kv:namespace create CONFIG_KV
   ```

2. Update the `wrangler.jsonc` file with your KV namespace ID

3. Set the required secrets:
   ```
   wrangler secret put SITE_KEY
   wrangler secret put SECRET_KEY
   wrangler secret put ADMIN_PASSWORD
   ```

4. Deploy the worker:
   ```
   npm run deploy
   ```

## Local Development

1. Install dependencies:
   ```
   npm install
   ```

2. Run locally:
   ```
   npm start
   ```

## License

MIT