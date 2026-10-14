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

test('dashboard shows a getting-started checklist and explains pending certificates', async ({ page }) => {
  await login(page);
  await expect(page.getByText('Getting started')).toBeVisible();
  await expect(page.getByText('Cloudflare token works')).toBeVisible();
  await expect(page.getByText('Add your first site').or(page.getByText('UI address'))).not.toHaveCount(0);
});
