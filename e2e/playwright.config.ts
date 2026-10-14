import { defineConfig } from '@playwright/test';

// Runs the built binary directly: UI on loopback, Caddy on high ports (ACME fails offline; the UI does not care).
const UI = '127.0.0.1:28081';

export default defineConfig({
  testDir: './tests',
  workers: 1,
  use: { baseURL: `http://${UI}` },
  webServer: {
    command: 'rm -rf data && ../bin/caretakarr',
    url: `http://${UI}/login`,
    reuseExistingServer: false,
    env: {
      CLOUDFLARE_API_TOKEN: 'e2e0000000000000000000000000000000000000',
      CARETAKARR_HOST: 'caretakarr.example.com',
      ACME_EMAIL: 'e2e@example.com',
      ACME_STAGING: 'true',
      ADMIN_PASSWORD: 'e2e-pass',
      UI_LISTEN: UI,
      HTTP_PORT: '28080',
      HTTPS_PORT: '28443',
      DATA_DIR: './data',
    },
  },
});
