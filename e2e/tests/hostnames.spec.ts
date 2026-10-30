import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

test('a domain can be edited, and a site can have several hostnames with a changeable main one', async ({ page }) => {
  await login(page);
  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('multi.example.net');
  await page.getByLabel('Default IP').fill('192.168.1.60');
  await page.getByRole('button', { name: 'Add domain' }).click();
  const drow = page.getByRole('row', { name: /multi\.example\.net/ });
  await expect(drow).toBeVisible();

  await drow.getByText('Edit', { exact: true }).click();
  await drow.getByLabel('A record IP', { exact: true }).fill('192.168.1.61');
  await drow.getByLabel('Certificate mode').selectOption('per_host');
  await drow.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('row', { name: /multi\.example\.net/ })).toContainText('192.168.1.61');
  await expect(page.getByRole('row', { name: /multi\.example\.net/ })).toContainText('per_host');

  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('www.multi.example.net\nshop.multi.example.net');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.62');
  await page.getByLabel('Upstream port').fill('8062');
  await page.getByRole('button', { name: 'Add site' }).click();

  const row = await openRow(siteRow(page, /www\.multi\.example\.net/));
  await expect(row).toContainText('shop.multi.example.net'); // the alias sits under the main name
  await expect(row.getByText('synced')).toHaveCount(3); // summary chip + one detail line per hostname (A and AAAA)
  await row.getByRole('link', { name: 'Edit' }).click();
  await expect(page.getByRole('heading', { name: /www\.multi\.example\.net/ })).toBeVisible();

  // Make the other name the main one: it is saved in place, and the dashboard lists it first.
  await page.getByLabel('Hostnames').fill('shop.multi.example.net\nwww.multi.example.net');
  await expect(page.getByText('The main address changed')).toBeVisible();
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Saved and applied.').first()).toBeVisible();
  await page.goto('/');
  const moved = siteRow(page, /shop\.multi\.example\.net/);
  await expect(moved.locator('.host')).toContainText('www.multi.example.net');
  await openRow(moved);

  // Shared server: remove the site and domain again.
  await moved.getByRole('button', { name: 'Delete' }).click();
  await page.getByRole('dialog').getByLabel('Also delete the DNS record').check();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(siteRow(page, /shop\.multi\.example\.net/)).toHaveCount(0);
});
