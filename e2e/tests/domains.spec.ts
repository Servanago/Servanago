import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('add a domain and see it listed, then remove it', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('example.org');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'example.org' })).toBeVisible();

  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByText('No domains yet.')).toBeVisible();
});

test('rejects .local domains with a message', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('nas.local');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('alert').filter({ hasText: '.local' })).toBeVisible();
});

test('unknown zone shows the Cloudflare lookup error', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('missing.example.com');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'not found' })).toBeVisible();
});
