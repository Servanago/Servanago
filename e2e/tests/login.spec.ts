import { test, expect } from '@playwright/test';

test('unauthenticated visit redirects to login', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveURL(/\/login$/);
});

test('wrong password shows an error and stays on login', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Password').fill('nope');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Wrong password' })).toBeVisible();
  await expect(page).toHaveURL(/\/login$/);
});

test('login reaches the dashboard and logout returns to login', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login$/);
});

test('root font size stays 14px on wide screens (Pico would scale it to 20px+)', async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 900 });
  await page.goto('/login');
  expect(await page.evaluate(() => getComputedStyle(document.documentElement).fontSize)).toBe('14px');
});
