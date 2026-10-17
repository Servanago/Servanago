import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('UI host record card shows synced', async ({ page }) => {
  await login(page);
  const card = page.locator('#ui-host');
  await expect(card).toContainText('servanago.example.com');
  await expect(card).toContainText('192.168.25.165');
  await expect(card.getByText('synced')).toBeVisible();
});

test('a site named like the UI host is rejected', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('example.com');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'example.com', exact: true })).toBeVisible();

  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('servanago.example.com');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.20');
  await page.getByLabel('Upstream port').fill('8080');
  await page.getByRole('button', { name: 'Add site' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'ServanaGo UI host' })).toBeVisible();
});

test('public IPs are accepted for domains, loopback is not', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('public.example.net');
  await page.getByLabel('Default IP').fill('127.0.0.1');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'usable IPv4' })).toBeVisible();

  await page.getByLabel('Default IP').fill('8.8.8.8');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'public.example.net' })).toBeVisible();
  await expect(page.getByRole('cell', { name: '8.8.8.8' })).toBeVisible();
});
