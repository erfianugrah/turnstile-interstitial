import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
        miniflare: {
          bindings: {
            SITE_KEY: "test-site-key",
            SECRET_KEY: "test-secret-key",
            PROTECTED_PATHS: "/login",
            CREDENTIAL_STORE_PATH: "/api/login",
            VERIFY_PATH: "/verify",
            MAX_TOKENS: "5",
            REFILL_RATE: "5",
            REFILL_TIME: "60000",
            TIME_TO_CHALLENGE: "150000",
            MAX_CREDENTIAL_BODY_SIZE: "65536",
            CREDENTIAL_TTL: "300000",
          },
        },
      },
    },
  },
});
