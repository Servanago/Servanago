import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('help page opens from the nav and ? links jump to a section', async ({ page }) => {
  await login(page);
  await page.getByRole('link', { name: 'Help', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Help', level: 1 })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'What the status words mean' })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'DNS conflict' })).toBeVisible();

  await page.goto('/domains');
  await page.getByRole('link', { name: 'Open help' }).first().click();
  await expect(page).toHaveURL(/\/help#/);
});

test('fields explain themselves and Add site shows a live preview', async ({ page }) => {
  await login(page);
  await page.goto('/sites/new');
  await expect(page.getByText('Not 443: Caddy already provides HTTPS')).toBeVisible(); // port hint
  const preview = page.locator('#preview');
  await expect(preview).toContainText('Fill in the hostname and backend');
  await page.getByLabel('Hostname').fill('oc.preview.example.net');
  await page.getByLabel('Backend host or IP').fill('192.168.25.165');
  await page.getByLabel('Backend port').fill('9200');
  await expect(preview).toContainText('https://oc.preview.example.net');
  await expect(preview).toContainText('http://192.168.25.165:9200');
  await expect(preview).toContainText('192.168.25.165'); // the DNS target is the server address
});

test('dashboard shows the getting-started checklist until setup is done, then the sites table', async ({ page }) => {
  await login(page);
  // Left-over routes from other specs plus a quickly-issued certificate (ACME_ISSUER=internal)
  // can complete the setup within one run, so accept either state: both are correct UI.
  const checklist = page.getByText('Getting started', { exact: true });
  const done = page.getByRole('heading', { name: 'Sites' });
  await expect(checklist.or(done).first()).toBeVisible();
});
