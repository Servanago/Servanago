import { Locator, Page } from '@playwright/test';

// A dashboard site row. Its summary (host, target, type, status) is always visible; the details and actions are not.
export function siteRow(page: Page, host: RegExp | string): Locator {
  return page.locator('details.srow', { hasText: host });
}

// openRow expands the row, so its certificate, DNS and action buttons can be read and clicked. The 10s poll keeps it open.
export async function openRow(row: Locator): Promise<Locator> {
  if (!(await row.evaluate((d) => (d as HTMLDetailsElement).open))) await row.locator('summary').click();
  return row;
}

export async function login(page: Page) {
  await page.goto('/login');
  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.waitForURL(/\/$/);
}

// signout opens the account menu (Sign out lives inside it since the topbar redesign) and clicks it.
export async function signout(page: Page) {
  const menu = page.locator('.usermenu');
  if (!(await menu.evaluate((d) => d.open))) await menu.locator('summary').click();
  await menu.getByRole('button', { name: 'Sign out' }).click();
}

// navTo opens the topbar's account menu (it holds Help, Settings, Users and friends) and navigates.
export async function navTo(page: Page, label: string) {
  await page.locator('.usermenu summary').click();
  await page.locator('.usermenu-body').getByRole('link', { name: label }).click();
}
