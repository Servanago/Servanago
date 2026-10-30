import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

test('status badges render for upstream, certificate and DNS', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('status.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'status.example.net' })).toBeVisible();

  // the UI's own listener is a guaranteed-open upstream
  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('self.status.example.net');
  await page.getByLabel('Upstream host or IP').fill('127.0.0.1');
  await page.getByLabel('Upstream port').fill('28081');
  await page.getByRole('button', { name: 'Add site' }).click();

  const row = await openRow(siteRow(page, /self\.status\.example\.net/));
  await expect(row.getByText('up', { exact: true })).toBeVisible();
  // Issuer-dependent: ACME_ISSUER=internal (e2e) issues quickly and 12h certs also read as
  // "expiring soon"; staging never finishes offline and stays "pending".
  await expect(row.getByText('pending').first()
    .or(row.getByText('issued').first())
    .or(row.getByText('expiring soon').first())).toBeVisible();
  await expect(row.getByText('synced').first()).toBeVisible();

  await row.getByRole('link', { name: 'Edit' }).click();
  await page.getByRole('button', { name: 'Delete site' }).click();
  await page.getByRole('dialog').getByLabel('Type the site name to confirm deletion').fill('self.status.example.net');
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(siteRow(page, 'self.status.example.net')).toHaveCount(0);
});
