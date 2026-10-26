import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

test('site shows DNS synced; delete asks with the record named', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('dns.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'dns.example.net' })).toBeVisible();

  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('radarr.dns.example.net');
  await page.getByLabel('Upstream port').fill('7878');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.21');
  await page.getByRole('button', { name: 'Add site' }).click();
  const row = await openRow(siteRow(page, /radarr\.dns\.example\.net/));
  await expect(row.getByText('synced')).toBeVisible();

  await row.getByRole('button', { name: 'Resync' }).click();
  await expect(row.getByText('synced')).toBeVisible();

  await row.getByRole('link', { name: 'Edit' }).click();
  await page.getByRole('button', { name: 'Delete site' }).click();
  await expect(page.getByRole('dialog')).toContainText('radarr.dns.example.net');
  await page.getByRole('dialog').getByLabel('Also delete the DNS record').check();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(siteRow(page, 'radarr.dns.example.net')).toHaveCount(0);
});
