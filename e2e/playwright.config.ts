import { defineConfig } from '@playwright/test';

// Runs the built binary directly: UI on loopback, Caddy on high ports (ACME fails offline; the UI does not care).
// Cloudflare is mocked by cf-mock.ts.
const UI = '127.0.0.1:28081';
// A second server started with no CLOUDFLARE_API_TOKEN: no DNS management, default ACME challenges.
const UI_NOCF = '127.0.0.1:28091';

export default defineConfig({
  testDir: './tests',
  workers: 1,
  use: { baseURL: `http://${UI}`, launchOptions: { args: ['--host-resolver-rules=MAP *.gate.example.test 127.0.0.1, MAP *.static.example.test 127.0.0.1'] } },
  projects: [
    { name: 'cloudflare', testIgnore: '**/nocf/**' },
    { name: 'nocf', testMatch: '**/nocf/**/*.spec.ts', use: { baseURL: `http://${UI_NOCF}` } },
  ],
  webServer: [
    {
      command: 'rm -rf data-nocf && ../bin/servanago',
      url: `http://${UI_NOCF}/login`,
      reuseExistingServer: false,
      env: {
        SERVANAGO_HOST: 'nocf.example.com',
        ACME_EMAIL: 'e2e@example.com',
        ACME_STAGING: 'true',
        ADMIN_PASSWORD: 'e2e-pass',
        UI_LISTEN: UI_NOCF,
        HTTP_PORT: '28090',
        HTTPS_PORT: '28444',
        DATA_DIR: './data-nocf',
        ACME_ISSUER: 'internal',
      },
    },
    {
      command: 'bun cf-mock.ts',
      url: 'http://127.0.0.1:28099/user/tokens/verify',
      reuseExistingServer: false,
    },
    {
      command: 'bun smtp-mock.ts',
      url: 'http://127.0.0.1:28098/ping',
      reuseExistingServer: false,
    },
    {
      command: 'rm -rf data && ../bin/servanago',
      url: `http://${UI}/login`,
      reuseExistingServer: false,
      env: {
        CLOUDFLARE_API_TOKEN: 'e2e0000000000000000000000000000000000000',
        CLOUDFLARE_BASE_URL: 'http://127.0.0.1:28099',
        SERVANAGO_HOST: 'servanago.example.com',
        SERVANAGO_HOST_IP: '192.168.25.165',
        ACME_EMAIL: 'e2e@example.com',
        ACME_STAGING: 'true',
        ADMIN_PASSWORD: 'e2e-pass',
        SERVANAGO_SECRET_KEY: 'e2e-secret-key-0123456789abcdef-e2e',
        UI_LISTEN: UI,
        HTTP_PORT: '28080',
        HTTPS_PORT: '28443',
        DATA_DIR: './data',
        ACME_ISSUER: 'internal',
      },
    },
  ],
});
