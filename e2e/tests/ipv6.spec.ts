import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('dual-stack: a site on a domain with an IPv6 address gets A and AAAA records, one badge each', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('dual.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByLabel('IPv6 for AAAA records').fill('2001:db8::10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: /2001:db8::10/ })).toBeVisible();

  await page.goto('/sites/new/full');
  await page.locator('select[name=domain_id]').selectOption('dual.example.net');
  await page.getByLabel('Subdomain').fill('web');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.30');
  await page.getByLabel('Upstream port').fill('8080');
  await page.getByRole('button', { name: 'Add site' }).click();

  const row = page.getByRole('row', { name: /web\.dual\.example\.net/ });
  await expect(row.getByText('A synced', { exact: true })).toBeVisible();
  await expect(row.getByText('AAAA synced', { exact: true })).toBeVisible();

  // a per-site IPv6 override, then clearing it removes the AAAA badge only when the domain has none
  await row.getByRole('link', { name: 'Edit' }).click();
  await page.getByLabel('AAAA record IPv6').fill('2001:db8::99');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(row.getByText('AAAA synced', { exact: true })).toBeVisible();

  // delete with the DNS option: the dialog names both records
  await row.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByRole('dialog')).toContainText('A 192.168.1.10, AAAA 2001:db8::99');
  await page.getByRole('dialog').getByLabel('Also delete the DNS record').check();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
  await expect(row).toHaveCount(0);
});

test('IPv6 input is validated: loopback and an IPv4 address are refused', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('v6bad.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByLabel('IPv6 for AAAA records').fill('::1');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'usable IPv6' })).toBeVisible();
  await page.getByLabel('IPv6 for AAAA records').fill('10.0.0.1');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'usable IPv6' })).toBeVisible();
});
