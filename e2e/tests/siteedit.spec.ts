import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('add a site, edit it, delete it', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('routes.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'routes.example.net' })).toBeVisible();

  await page.goto('/sites/new');
  await expect(page.getByLabel('Preset')).toHaveCount(0);
  await page.getByLabel('Hostnames').fill('sonarr.routes.example.net');
  await page.getByLabel('Upstream port').fill('8989');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.20');
  await page.getByRole('button', { name: 'Add site' }).click();
  await expect(page).toHaveURL(/\/$/);
  const row = page.getByRole('row', { name: /sonarr\.routes\.example\.net/ });
  await expect(row.getByRole('cell', { name: '192.168.1.20:8989' })).toBeVisible();

  await row.getByRole('link', { name: 'Edit' }).click();
  await page.getByLabel('Enabled').uncheck();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved and applied.')).toBeVisible();
  await page.goto('/');
  await expect(row.getByRole('cell', { name: 'disabled' })).toBeVisible();

  await row.getByRole('link', { name: 'Edit' }).click();
  await page.getByRole('button', { name: 'Delete site' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'sonarr.routes.example.net' })).toHaveCount(0);
});
