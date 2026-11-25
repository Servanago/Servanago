import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

// Caddy serves the sites over HTTPS from the internal issuer on 28443; Chromium maps *.static.example.test to 127.0.0.1.
const HOST = 'guard.static.example.test';
const SITE = `https://${HOST}:28443`;
const PAGE_HOST = 'parked.static.example.test';

test.use({ ignoreHTTPSErrors: true });

async function removeSite(page, host: string) {
  await page.goto('http://127.0.0.1:28081/');
  await (await openRow(siteRow(page, host))).getByRole('link', { name: 'Edit' }).click();
  await page.getByRole('button', { name: 'Delete site' }).click();
  await page.getByRole('dialog').getByLabel('Also delete the DNS record').check();
  await page.getByRole('dialog').getByLabel('Type the site name to confirm deletion').fill(host);
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await page.waitForURL(/28081\/$/);
  await expect(siteRow(page, host)).toHaveCount(0);
}

test('protection: under-attack challenge solved by the browser, traffic log, bans, a parked page', async ({ page }) => {
  const root = mkdtempSync(join(tmpdir(), 'servanago-guard-'));
  writeFileSync(join(root, 'index.html'), 'GUARD-OK');

  await login(page);
  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill(HOST);
  await page.getByLabel('Kind').selectOption('static');
  await page.getByLabel('Folder', { exact: true }).fill(root);
  await page.getByRole('button', { name: 'Add site' }).click();
  await openRow(siteRow(page, HOST)).then(row => row.getByRole('link', { name: 'Edit' }).click());
  await page.locator('nav[aria-label="Site sections"]').getByRole('link', { name: 'Protection' }).click();

  // the tab saves and survives a reload
  await page.locator('select[name="ch_difficulty"]').selectOption('low');
  await page.getByLabel('Ban addresses that keep getting error responses').check();
  const saved = page.waitForResponse(r => r.url().includes('/protection') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Save protection' }).click();
  expect((await saved).status()).toBe(200);
  await page.reload();
  await expect(page.locator('select[name="ch_difficulty"]')).toHaveValue('low');
  await expect(page.getByLabel('Ban addresses that keep getting error responses')).toBeChecked();
  // an invalid paywall line is refused with its reason
  await page.locator('textarea[name="x402_routes"]').fill('/api/ cheap all request');
  const refused = page.waitForResponse(r => r.url().includes('/protection') && r.request().method() === 'POST');
  await page.getByRole('button', { name: 'Save protection' }).click();
  expect((await refused).status()).toBe(422);
  await page.locator('textarea[name="x402_routes"]').fill('');

  // normal traffic first, then under-attack mode: the browser must solve the proof of work to see the page
  expect((await page.goto(`${SITE}/`))!.status()).toBe(200);
  await page.goto('/');
  await (await openRow(siteRow(page, HOST))).getByRole('link', { name: 'Edit' }).click();
  await page.locator('nav[aria-label="Site sections"]').getByRole('link', { name: 'Protection' }).click();
  await page.getByRole('button', { name: 'Turn under-attack mode on' }).click();
  await expect(page.getByRole('button', { name: 'Turn under-attack mode off' })).toBeVisible();

  await page.goto(`${SITE}/`);
  await expect(page.locator('body')).toHaveText('GUARD-OK', { timeout: 30000 });

  await page.goto('http://127.0.0.1:28081/');
  await (await openRow(siteRow(page, HOST))).getByRole('link', { name: 'Edit' }).click();
  await page.locator('nav[aria-label="Site sections"]').getByRole('link', { name: 'Protection' }).click();
  await page.getByRole('button', { name: 'Turn under-attack mode off' }).click();
  await expect(page.getByRole('button', { name: 'Turn under-attack mode on' })).toBeVisible();

  // the request log shows what was served (it is flushed every two seconds)
  await expect.poll(async () => {
    await page.goto('http://127.0.0.1:28081/traffic?site=guard');
    return await page.locator('#rows').innerText();
  }, { timeout: 15000 }).toContain(`${HOST}:28443/`);
  await expect(page.getByText('Last minute')).toBeVisible();

  // bans: add one for a documentation address, lift it again
  await page.goto('http://127.0.0.1:28081/bans');
  await page.getByLabel('IP address, or an IPv6 /64').fill('203.0.113.5');
  await page.getByRole('button', { name: 'Ban', exact: true }).click();
  await expect(page.getByRole('cell', { name: '203.0.113.5' })).toBeVisible();
  page.once('dialog', d => d.accept());
  await page.getByRole('button', { name: 'Unban' }).click();
  await expect(page.getByRole('cell', { name: '203.0.113.5' })).toHaveCount(0);

  // a page site answers its status and text
  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill(PAGE_HOST);
  await page.getByLabel('Kind').selectOption('page');
  await page.locator('input[name="page_title"]').fill('Back soon');
  await page.locator('textarea[name="page_message"]').fill('Maintenance in progress');
  await page.getByRole('button', { name: 'Add site' }).click();
  // the certificate of a new name is issued in the background: retry until the first handshake works
  await expect.poll(async () => {
    try { return (await page.goto(`https://${PAGE_HOST}:28443/`))!.status(); } catch { return 0; }
  }, { timeout: 20000 }).toBe(503);
  await expect(page.getByRole('heading', { name: 'Back soon' })).toBeVisible();

  await removeSite(page, PAGE_HOST);
  await removeSite(page, HOST);
});

test('alerts: a destination is stored sealed and listed', async ({ page }) => {
  await login(page);
  await page.goto('/alerts');
  await page.getByLabel('Name').fill('e2e phone');
  await page.getByLabel('Kind').selectOption('pushover');
  await page.getByLabel('Address').fill('user-key-e2e');
  await page.getByLabel('Secret').fill('app-token-e2e');
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'e2e phone' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText('user-key-e2e');
  page.once('dialog', d => d.accept());
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByRole('cell', { name: 'e2e phone' })).toHaveCount(0);
});
