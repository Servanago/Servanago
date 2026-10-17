import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('Add site asks for hostname and a separate backend port, and creates domain, site and record', async ({ page }) => {
  await login(page);
  await page.getByRole('link', { name: 'Add site' }).first().click();
  await expect(page.getByLabel('Upstream port')).toBeVisible();

  await page.getByLabel('Hostnames').fill('oc.sitesflow.example.net');
  await page.getByLabel('Upstream host or IP').fill('192.168.25.165');
  await page.getByLabel('Upstream port').fill('9200');
  await page.getByRole('button', { name: 'Add site' }).click();

  const row = page.getByRole('row', { name: /oc\.sitesflow\.example\.net/ });
  await expect(row.getByRole('cell', { name: '192.168.25.165:9200' })).toBeVisible();
  await expect(row.getByText('synced')).toBeVisible();

  await page.goto('/domains');
  await expect(page.getByRole('cell', { name: 'sitesflow.example.net', exact: true })).toBeVisible(); // auto-created
});

test('Add site will not submit without a valid port and creates nothing', async ({ page }) => {
  await login(page);
  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('nope.sitesflow2.example.net');
  await page.getByLabel('Upstream host or IP').fill('192.168.25.165');
  const port = page.getByLabel('Upstream port');
  await port.fill('70000'); // above max=65535: the browser blocks the request
  await page.getByRole('button', { name: 'Add site' }).click();
  expect(await port.evaluate((el: HTMLInputElement) => el.validity.valid)).toBe(false);
  await expect(page).toHaveURL(/\/sites\/new$/);
  await port.fill('');
  await page.getByRole('button', { name: 'Add site' }).click();
  expect(await port.evaluate((el: HTMLInputElement) => el.validity.valueMissing)).toBe(true); // port is required
  await page.goto('/domains');
  await expect(page.getByRole('cell', { name: 'sitesflow2.example.net' })).toHaveCount(0);
});

test('top bar spans the full page width with inset content', async ({ page }) => {
  await page.setViewportSize({ width: 1500, height: 800 });
  await login(page);
  const bar = await page.locator('header.topbar').boundingBox();
  const brand = await page.locator('header.topbar .brand').boundingBox();
  const main = await page.locator('main').boundingBox();
  expect(bar!.x).toBe(0);
  expect(Math.round(bar!.width)).toBe(1500);
  expect(brand!.x).toBeGreaterThanOrEqual(20); // padded, not flush with the edge
  expect(main!.width).toBeLessThan(1300); // page content stays in its centered column
});
