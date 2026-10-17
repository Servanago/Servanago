import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { test, expect } from '@playwright/test';
import { login } from './helpers';

// Caddy serves the site over HTTPS from the internal issuer on 28443 (ACME_ISSUER=internal), and Chromium's
// host-resolver-rules (playwright.config.ts) maps *.static.example.test to 127.0.0.1.
const SITE = 'https://files.static.example.test:28443';

test.use({ ignoreHTTPSErrors: true });

test('static site: serve a folder, no dotfiles, no listing', async ({ page }) => {
  const root = mkdtempSync(join(tmpdir(), 'servanago-static-'));
  writeFileSync(join(root, 'index.html'), 'STATIC-OK');
  writeFileSync(join(root, '.secret'), 'SECRET');

  await login(page);
  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('files.static.example.test');
  await page.getByLabel('Kind').selectOption('static');
  await expect(page.getByLabel('Upstream port')).toBeHidden();
  await page.getByLabel('Folder', { exact: true }).fill(root);
  await expect(page.locator('#preview')).toContainText('serves the files');
  await page.getByRole('button', { name: 'Add site' }).click();

  const row = page.getByRole('row', { name: /files\.static\.example\.test/ });
  await expect(row.getByText(root, { exact: false })).toBeVisible();

  // Navigate (not page.request): only the browser applies the host-resolver rule for *.static.example.test.
  expect((await page.goto(`${SITE}/`))!.status()).toBe(200);
  await expect(page.locator('body')).toHaveText('STATIC-OK');
  expect((await page.goto(`${SITE}/.secret`))!.status()).toBe(404);
  expect((await page.goto(`${SITE}/missing`))!.status()).toBe(404);

  // A folder ServanaGo refuses is refused in the form.
  await page.goto('http://127.0.0.1:28081/');
  await row.getByRole('link', { name: 'Edit' }).click();
  await expect(page.getByLabel('Kind')).toHaveValue('static');
  await page.getByLabel('Folder', { exact: true }).fill('/etc');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'not allowed' })).toBeVisible();

  // Shared server: remove the site again.
  await page.getByRole('button', { name: 'Delete site' }).click();
  await page.getByRole('dialog').getByLabel('Also delete the DNS record').check();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByRole('cell', { name: /files\.static\.example\.test/ })).toHaveCount(0);
});
