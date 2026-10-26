import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from '../helpers';

// Runs against a server started with no CLOUDFLARE_API_TOKEN (the "nocf" project in playwright.config.ts).
test('without Cloudflare: add a domain and a site, and no DNS appears anywhere', async ({ page }) => {
  await login(page);
  await expect(page.getByText('Cloudflare token')).toHaveCount(0);
  await expect(page.getByText('UI host')).toHaveCount(0);

  await page.goto('/domains');
  await expect(page.getByLabel('Default IP')).toHaveCount(0);
  await page.getByLabel('Domain', { exact: true }).fill('nocf.example.net');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'nocf.example.net' })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'per_host' })).toBeVisible();

  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('app.nocf.example.net');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.40');
  await page.getByLabel('Upstream port').fill('9300');
  await expect(page.locator('#preview')).toContainText('in your DNS yourself');
  await page.getByRole('button', { name: 'Add site' }).click();

  const row = await openRow(siteRow(page, /app\.nocf\.example\.net/));
  await expect(row.locator('.target')).toHaveText('192.168.1.40:9300');
  await expect(row.getByText('DNS', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Resync' })).toHaveCount(0);
});

test('without Cloudflare: a hostname under no domain is served without one', async ({ page }) => {
  await login(page);
  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('app.unknown.example.org');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.41');
  await page.getByLabel('Upstream port').fill('9301');
  await page.getByRole('button', { name: 'Add site' }).click();
  await expect(page).toHaveURL(/\/$/);
  const row = await openRow(siteRow(page, /app\.unknown\.example\.org/));
  await expect(row).toBeVisible();
  await expect(row.getByText('DNS', { exact: true })).toHaveCount(0);
});
