import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

test('Add site asks for hostname and a separate backend port, and creates domain, site and record', async ({ page }) => {
  await login(page);
  await page.getByRole('link', { name: 'Add site' }).first().click();
  await expect(page.getByLabel('Upstream port')).toBeVisible();

  await page.getByLabel('Hostnames').fill('oc.sitesflow.example.net');
  await page.getByLabel('Upstream host or IP').fill('192.168.25.165');
  await page.getByLabel('Upstream port').fill('9200');
  await page.getByRole('button', { name: 'Add site' }).click();

  const row = siteRow(page, /oc\.sitesflow\.example\.net/);
  await openRow(row); // the target now reads in the opened detail
  await expect(row.getByText('192.168.25.165:9200')).toBeVisible();
  await expect(row.getByText('synced').first()).toBeVisible();

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

test('a left sidebar holds the navigation beside content that fills the window', async ({ page }) => {
  await page.setViewportSize({ width: 1500, height: 800 });
  await login(page);
  const side = await page.locator('aside.sidebar').boundingBox();
  const brand = await page.locator('aside.sidebar .brand').boundingBox();
  const main = await page.locator('main').boundingBox();
  expect(side!.x).toBe(0); // pinned to the left edge
  expect(side!.width).toBe(240);
  expect(brand!.x).toBeGreaterThanOrEqual(8); // padded, not flush with the edge
  expect(main!.x).toBeGreaterThanOrEqual(240); // content sits beside it, not under it
  expect(main!.width).toBeGreaterThan(1100); // and uses the rest of the window
  await expect(page.locator('aside.sidebar').getByRole('link', { name: 'Domains' })).toBeVisible();
  await expect(page.locator('.usermenu summary')).toBeVisible(); // the account menu stays in the header
});

test('below 860px the sidebar is a drawer opened from the Menu button', async ({ page }) => {
  await page.setViewportSize({ width: 600, height: 800 });
  await login(page);
  await expect(page.locator('aside.sidebar')).not.toBeInViewport();
  await page.locator('.navtoggle').click();
  await expect(page.locator('aside.sidebar')).toBeInViewport();
  await page.keyboard.press('Escape');
  await expect(page.locator('aside.sidebar')).not.toBeInViewport();
});

test('the Account menu opens on a phone', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 800 });
  await login(page);
  await page.locator('.usermenu summary').click();
  const out = page.locator('.usermenu-body').getByRole('button', { name: 'Sign out' });
  await expect(out).toBeVisible();
  const box = await out.boundingBox();
  expect(box!.y + box!.height).toBeLessThanOrEqual(800); // the whole menu fits on screen, not below the fold
  expect(box!.x).toBeGreaterThanOrEqual(0);
});
