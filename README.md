# Turnstile Interstitial

A Cloudflare Worker that protects routes with [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/) challenges, token-bucket rate limiting, and encrypted credential storage. Built on [Durable Objects](https://developers.cloudflare.com/durable-objects/) for persistent state with zero external dependencies.

## How It Works

```
Client Request
      |
      v
  Is this a protected path?  ──no──> Pass through to origin
      |
     yes
      |
      v
  Has valid turnstile_clearance   ──no──> Serve Turnstile challenge page
  cookie? (HMAC + IP + expiry)
      |
     yes
      |
      v
  Rate limit check (by IP)  ──exceeded──> Serve rate limit page with countdown
      |
    allowed
      |
      v
  Proxy request to origin
```

1. **Interception** -- The Worker intercepts requests matching configured path prefixes. Everything else passes through to the origin.
2. **Challenge** -- Users without a valid `turnstile_clearance` cookie are served an interstitial page with a Turnstile widget. Non-browser clients receive a JSON response instead.
3. **Verification** -- On completing the challenge, the Turnstile token is validated against Cloudflare's siteverify API. On success, the Worker issues a self-managed `turnstile_clearance` cookie containing an HMAC-SHA256-signed payload with the client IP and timestamp.
4. **Cookie Validation** -- Subsequent requests verify the signed cookie: HMAC signature must be valid (using `SECRET_KEY`), the embedded IP must match the current client IP, and the timestamp must be within the `TIME_TO_CHALLENGE` window. No Durable Object lookup is needed for challenge state.
5. **Rate Limiting** -- Each request to a protected path consumes a token from a per-IP token bucket (stored in a Durable Object). When tokens are exhausted, a rate limit page with a live countdown timer is served.
6. **Credential Storage** -- POST requests to the credential store path have their payload encrypted with AES-256-GCM and stored in a separate Durable Object. Data is deleted after a single retrieval and auto-expires via DO alarms.
7. **Cleanup** -- A daily cron job purges expired Durable Object entries older than 24 hours.

### Why Not `cf_clearance`?

Cloudflare Turnstile does **not** issue a `cf_clearance` cookie by default — that only happens with [Turnstile pre-clearance](https://developers.cloudflare.com/turnstile/tutorials/pre-clearance-support/) enabled in the dashboard. Pre-clearance delegates challenge state to Cloudflare's edge, which makes it easier to bypass. Instead, this Worker issues its own HMAC-signed cookie that it fully controls: the signature binds to the `SECRET_KEY`, the payload is IP-bound, and expiry is enforced server-side.

## Use Cases

### Protect login endpoints (default)

```jsonc
"PROTECTED_PATHS": "/login"
```

### Protect against scraping (all routes)

```jsonc
"PROTECTED_PATHS": "/*"
```

Every request to the domain must pass a Turnstile challenge before reaching the origin. This is the interstitial pattern used by manga/pirate sites and similar to Cloudflare's JS Challenge (JSD).

### Protect multiple sections

```jsonc
"PROTECTED_PATHS": "/login,/admin,/dashboard"
```

## Configuration

All configuration is in `wrangler.jsonc`. Secrets are set via `wrangler secret put`.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PROTECTED_PATHS` | `"/login"` | Comma-separated path prefixes to protect, or `"/*"` for all routes |
| `CREDENTIAL_STORE_PATH` | `"/api/login"` | Path prefix for POST requests that store encrypted credentials |
| `VERIFY_PATH` | `"/verify"` | Path for the Turnstile verification callback |
| `MAX_TOKENS` | `"5"` | Maximum tokens in the rate limit bucket |
| `REFILL_RATE` | `"5"` | Number of tokens refilled per interval |
| `REFILL_TIME` | `"60000"` | Refill interval in milliseconds (60s) |
| `TIME_TO_CHALLENGE` | `"150000"` | Challenge validity window in milliseconds (2.5 min) |
| `MAX_CREDENTIAL_BODY_SIZE` | `"65536"` | Maximum POST body size in bytes for credential storage (64 KB) |
| `CREDENTIAL_TTL` | `"300000"` | Credential auto-expiry in milliseconds (5 min) |

### Secrets

Set via `wrangler secret put`:

| Secret | Description |
|---|---|
| `SITE_KEY` | Cloudflare Turnstile site key |
| `SECRET_KEY` | Cloudflare Turnstile secret key |

You can use the [Turnstile test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/) during development.

### Route Matching

`PROTECTED_PATHS` accepts comma-separated path prefixes. A prefix matches the exact path and any subpaths:

- `"/login"` matches `/login`, `/login/callback`, `/login/reset`
- `"/admin"` matches `/admin`, `/admin/users`, `/admin/settings`
- `"/*"` matches every path (full-site protection)

The verify path (`VERIFY_PATH`) is always active regardless of `PROTECTED_PATHS`.

## Project Structure

```
src/
  index.ts          Main Worker entry point, Durable Objects, routing
  types.ts          TypeScript interfaces (Env, DO types, configs)
  utils.ts          Crypto helpers, cookie/IP parsing, URL sanitization
  siteverify.ts     Turnstile token verification against Cloudflare API
  staticpages.ts    HTML/JSON response generators (challenge + rate limit pages)
test/
  e2e.test.ts       End-to-end tests (49 tests)
  env.d.ts          Type declarations for test environment
wrangler.jsonc      Cloudflare Workers configuration
tsconfig.json       TypeScript configuration
vitest.config.ts    Vitest configuration with @cloudflare/vitest-pool-workers
Misc/               Historical development iterations (kept for reference)
```

## Durable Objects

### ChallengeStatusStorage

Manages per-IP rate limiting. Challenge state is no longer stored in DOs — it lives entirely in the signed `turnstile_clearance` cookie.

| Endpoint | Method | Description |
|---|---|---|
| `/checkRateLimit` | POST | Token-bucket rate limit check (keyed by IP) |

### CredentialsStorage

Encrypts and stores login payloads with AES-256-GCM. The encryption key is persisted alongside the ciphertext. Data is deleted after a single retrieval and auto-expires via a Durable Object alarm.

| Endpoint | Method | Description |
|---|---|---|
| `/store` | POST | Encrypt and store credentials (enforces body size limit) |
| `/retrieve` | GET | Decrypt, return, and delete stored credentials |

## Development

### Prerequisites

- Node.js 18+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Setup

```bash
npm install
```

### Local Development

```bash
npm start
# Starts wrangler dev server
```

### Type Checking

```bash
npm run typecheck
```

### Testing

```bash
npm test
# Runs 49 e2e tests via @cloudflare/vitest-pool-workers
```

Tests cover:
- Worker routing (protected vs pass-through paths)
- Turnstile verification endpoint (input validation, URL validation, error handling)
- Clearance cookie (HMAC generation/verification, tamper detection, wrong-key rejection, IP binding, Set-Cookie format)
- XSS protection (URL sanitization in challenge page)
- ChallengeStatusStorage DO (rate limiting, IP-only keying, cookie rotation resistance, independent IP buckets, removed endpoints return 404)
- CredentialsStorage DO (encrypt/decrypt roundtrip, single-read deletion, body size limits, JSON validation)
- Utility functions (hashing, crypto key export/import, cookie parsing)
- Rate limit page (429 status, HTML countdown, JSON response)
- Configurable route protection (path parsing, prefix matching, wildcard)

### Deploy

```bash
npm run deploy
# Runs wrangler deploy
```

Before deploying, set your Turnstile secrets:

```bash
wrangler secret put SITE_KEY
wrangler secret put SECRET_KEY
```

## Security

- **Self-managed signed cookie** -- The `turnstile_clearance` cookie is HMAC-SHA256-signed with `SECRET_KEY`, IP-bound, and timestamp-checked. No Durable Object lookup is needed to verify challenge state, eliminating a per-request DO roundtrip.
- **Timing-safe signature verification** -- HMAC comparison uses `crypto.subtle.timingSafeEqual` (with XOR fallback) to prevent timing attacks.
- **Cookie attributes** -- The clearance cookie is set with `HttpOnly; Secure; SameSite=Lax; Path=/` to prevent XSS exfiltration and CSRF.
- **Rate limiting is keyed by IP only** -- not by cookie. This prevents attackers from bypassing rate limits by rotating cookies.
- **Turnstile verification includes error handling** -- network failures to the siteverify API return 502 instead of crashing. Invalid tokens, missing fields, and malformed URLs are rejected with appropriate 400-level responses.
- **URL sanitization** -- The `originalUrl` embedded in the challenge page is sanitized to prevent XSS injection. Only `http`/`https` URLs are allowed, and HTML special characters are escaped.
- **Credential encryption** -- Login payloads are encrypted with AES-256-GCM using a per-request key. The key is persisted alongside the ciphertext (not returned to the caller). Data is single-read and auto-expires via DO alarms.
- **Body size limits** -- POST bodies to credential storage are capped at `MAX_CREDENTIAL_BODY_SIZE` (default 64 KB) to prevent abuse.
- **Dual response format** -- Both challenge and rate limit pages detect the `Accept` header: browsers get styled HTML (with dark mode), API clients get JSON.
- **Scheduled cleanup** -- A daily cron purges all DO entries older than 24 hours using batched deletes.

## Limitations

- **Client-side JS required** -- The Turnstile widget and rate limit countdown timer require JavaScript. Non-JS clients receive JSON responses instead.
- **Single-origin** -- The Worker proxies to a single origin defined by the route pattern. Multi-origin routing would require additional configuration.
- **DO storage scalability** -- Rate limit state is stored in Durable Objects. Extremely high-traffic scenarios may benefit from additional sharding strategies.
