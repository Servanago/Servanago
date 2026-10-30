import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

test('toggle a site and edit allowlist and basic auth', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('controls.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.10');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'controls.example.net' })).toBeVisible();

  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('bazarr.controls.example.net');
  await page.getByLabel('Upstream port').fill('6767');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.22');
  await page.getByText('IP allowlist').click(); // access features start closed on a new site
  await page.getByLabel('Allowed sources').fill('192.168.0.0/16');
  await page.getByText('Basic authentication').click();
  await page.getByLabel('User', { exact: true }).fill('alice');
  await page.getByLabel('Password', { exact: true }).fill('s3cret');
  await page.getByRole('button', { name: 'Add site' }).click();
  const row = await openRow(siteRow(page, /bazarr\.controls\.example\.net/));
  await expect(row).toBeVisible();
  await expect(row.locator('.state')).not.toHaveText('Disabled');

  await row.getByRole('button', { name: 'Disable' }).click();
  await expect(row.locator('.state')).toHaveText('Disabled');
  await row.getByRole('button', { name: 'Enable' }).click();
  await expect(row.locator('.state')).not.toHaveText('Disabled');

  await row.getByRole('link', { name: 'Edit' }).click();
  await page.locator('nav[aria-label="Site sections"]').getByRole('link', { name: 'Gate' }).click();
  await expect(page).toHaveURL(/\/sites\/\d+\/gate$/);
  await expect(page.getByLabel('Allowed sources')).toHaveValue('192.168.0.0/16');
  await expect(page.getByLabel('User', { exact: true })).toHaveValue('alice');
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
  await page.getByLabel('Allowed sources').fill('not-a-cidr');
  await page.getByRole('button', { name: 'Save allowlist and basic auth' }).click();
  await expect(page.getByText('not-a-cidr')).toBeVisible();
});
