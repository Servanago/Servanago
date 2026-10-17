import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('site shows DNS synced; delete asks with the record named', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('dns.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'dns.example.net' })).toBeVisible();

  await page.goto('/sites/new/full');
  await page.locator('select[name=domain_id]').selectOption('dns.example.net');
  await page.getByLabel('Subdomain').fill('radarr');
  await page.getByLabel('Upstream port').fill('7878');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.21');
  await page.getByRole('button', { name: 'Add site' }).click();
  const row = page.getByRole('row', { name: /radarr\.dns\.example\.net/ });
  await expect(row.getByText('synced')).toBeVisible();

  await row.getByRole('button', { name: 'Resync' }).click();
  await expect(row.getByText('synced')).toBeVisible();

  await row.getByRole('link', { name: 'Edit' }).click();
  let message = '';
  page.once('dialog', (d) => {
    message = d.message();
    return d.accept();
  });
  await page.getByRole('button', { name: 'Delete site' }).click();
  await expect(page.getByRole('cell', { name: 'radarr.dns.example.net' })).toHaveCount(0);
  expect(message).toContain('also deletes the A record radarr.dns.example.net');
});
