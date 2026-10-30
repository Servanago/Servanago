import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

// Same setup as static.spec.ts: Caddy serves *.static.example.test over HTTPS on 28443.
const SITE = 'https://snip.static.example.test:28443';

test.use({ ignoreHTTPSErrors: true });

test('snippets: add, refuse a bad one, attach to a site, block paths, detach, delete', async ({ page }) => {
  const root = mkdtempSync(join(tmpdir(), 'servanago-snip-'));
  writeFileSync(join(root, 'index.html'), 'SNIP-OK');
  writeFileSync(join(root, 'composer.lock'), 'LOCK');

  await login(page);
  await page.goto('/snippets');
  const add = page.locator('form[hx-post="/snippets"]');

  // A directive that would serve or proxy is refused with the reason, and nothing is stored.
  await add.getByLabel('Name').fill('e2e_bad');
  await add.getByLabel('Directives').fill('reverse_proxy 127.0.0.1:9');
  await add.getByRole('button', { name: 'Add snippet' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'not allowed' })).toBeVisible();

  await add.getByLabel('Name').fill('e2e_block');
  await add.getByLabel('Directives').fill('@lock path /composer.lock\nrespond @lock 404');
  await add.getByRole('button', { name: 'Add snippet' }).click();
  const row = page.getByRole('row', { name: /^e2e_block / });
  await expect(row).toContainText('no site');
  await expect(page.getByRole('row', { name: /^e2e_bad / })).toHaveCount(0);

  // Attach it to a static site: the path answers 404, the rest is served.
  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('snip.static.example.test');
  await page.getByLabel('Kind').selectOption('static');
  await page.getByLabel('Folder', { exact: true }).fill(root);
  await page.getByLabel('e2e_block').check();
  await page.getByRole('button', { name: 'Add site' }).click();
  await expect(siteRow(page, /snip\.static\.example\.test/)).toBeVisible();

  expect((await page.goto(`${SITE}/`))!.status()).toBe(200);
  expect((await page.goto(`${SITE}/composer.lock`))!.status()).toBe(404);

  // In use: Remove is refused and names the site.
  await page.goto('http://127.0.0.1:28081/snippets');
  page.once('dialog', (d) => d.accept());
  await page.getByRole('row', { name: /^e2e_block / }).getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'snip.static.example.test' })).toBeVisible();

  // Shared server: detach, delete the snippet, delete the site.
  await page.goto('http://127.0.0.1:28081/');
  await (await openRow(siteRow(page, /snip\.static\.example\.test/))).getByRole('link', { name: 'Edit' }).click();
  await page.locator('nav[aria-label="Site sections"]').getByRole('link', { name: 'Snippets' }).click();
  await page.getByLabel('e2e_block').uncheck();
  await page.getByRole('button', { name: 'Save snippets' }).click();
  await expect(page.getByText('Saved and applied.').first()).toBeVisible();
  expect((await page.goto(`${SITE}/composer.lock`))!.status()).toBe(200);

  await page.goto('http://127.0.0.1:28081/snippets');
  page.once('dialog', (d) => d.accept());
  await page.getByRole('row', { name: /^e2e_block / }).getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByRole('row', { name: /^e2e_block / })).toHaveCount(0);

  await page.goto('http://127.0.0.1:28081/');
  await (await openRow(siteRow(page, /snip\.static\.example\.test/))).getByRole('link', { name: 'Edit' }).click();
  await page.getByRole('button', { name: 'Delete site' }).click();
  await page.getByRole('dialog').getByLabel('Also delete the DNS record').check();
  await page.getByRole('dialog').getByLabel('Type the site name to confirm deletion').fill('snip.static.example.test');
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(siteRow(page, /snip\.static\.example\.test/)).toHaveCount(0);
});
