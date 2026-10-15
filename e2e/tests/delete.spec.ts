import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('list row delete panel: cancel keeps the route, delete asks about the DNS record', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('delrow.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'delrow.example.net' })).toBeVisible();

  await page.goto('/routes/new');
  await page.locator('select[name=domain_id]').selectOption('delrow.example.net');
  await page.getByLabel('Preset').selectOption('Lidarr');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.24');
  await page.getByRole('button', { name: 'Add route' }).click();
  const row = page.getByRole('row', { name: /lidarr\.delrow\.example\.net/ });
  await expect(row.getByText('synced')).toBeVisible();

  await row.getByRole('button', { name: 'Delete', exact: true }).click();
  const panel = page.getByRole('dialog');
  await expect(panel.getByText('Delete lidarr.delrow.example.net?')).toBeVisible();
  await expect(panel.getByLabel('Also delete the DNS record')).not.toBeChecked();
  await panel.getByRole('button', { name: 'Cancel' }).click();
  await expect(panel).toBeHidden();
  await expect(row).toBeVisible();

  await row.getByRole('button', { name: 'Delete', exact: true }).click();
  await page.getByRole('dialog').getByLabel('Also delete the DNS record').check();
  // The route list refreshes every 10s; an open dialog and its ticked box must survive that.
  await page.waitForResponse((r) => r.url().endsWith('/status') && r.status() === 200, { timeout: 15000 });
  await expect(page.getByRole('dialog').getByLabel('Also delete the DNS record')).toBeChecked();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'lidarr.delrow.example.net' })).toHaveCount(0);
});
