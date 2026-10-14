import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('status badges render for upstream, certificate and DNS', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('status.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'status.example.net' })).toBeVisible();

  // the UI's own listener is a guaranteed-open upstream
  await page.goto('/routes/new');
  await page.locator('select[name=domain_id]').selectOption('status.example.net');
  await page.getByLabel('Subdomain').fill('self');
  await page.getByLabel('Upstream host or IP').fill('127.0.0.1');
  await page.getByLabel('Upstream port').fill('28081');
  await page.getByRole('button', { name: 'Add route' }).click();

  const row = page.getByRole('row', { name: /self\.status\.example\.net/ });
  await expect(row.getByText('up', { exact: true })).toBeVisible();
  await expect(row.getByText('pending').first()).toBeVisible(); // no cert: ACME cannot run offline
  await expect(row.getByText('synced')).toBeVisible();

  await row.getByRole('link', { name: 'Edit' }).click();
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Delete route' }).click();
  await expect(page.getByRole('cell', { name: 'self.status.example.net' })).toHaveCount(0);
});
