import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('streaming and upload limit: set, badge, edit, reject bad size', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('tuning.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'tuning.example.net' })).toBeVisible();

  await page.goto('/routes/new');
  await page.locator('select[name=domain_id]').selectOption('tuning.example.net');
  await page.getByLabel('Subdomain').fill('term');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.23');
  await page.getByLabel('Upstream port').fill('8788');
  await page.getByLabel('Send responses as they arrive').check();
  await page.getByLabel('Upload limit').fill('2GB');
  await page.getByRole('button', { name: 'Add route' }).click();

  const row = page.getByRole('row', { name: /term\.tuning\.example\.net/ });
  await expect(row.getByText('stream', { exact: true })).toBeVisible();
  await expect(row.getByText('max 2GB')).toBeVisible();

  await row.getByRole('link', { name: 'Edit' }).click();
  await expect(page.getByLabel('Send responses as they arrive')).toBeChecked();
  await expect(page.getByLabel('Upload limit')).toHaveValue('2GB');
  await page.getByLabel('Upload limit').fill('500GB');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'upload limit' })).toBeVisible();
});
