import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('a second administrator signs in on their own, changes their password, and is removed', async ({ page, browser, baseURL }) => {
  await login(page);
  await page.getByRole('link', { name: 'Users' }).click();
  await expect(page.getByRole('row', { name: /^admin / })).toContainText('(you)');
  // You cannot manage yourself from this table.
  await expect(page.getByRole('row', { name: /^admin / }).getByText('Manage')).toHaveCount(0);

  // Adding an administrator asks for your own password again.
  const add = page.locator('form[hx-post="/users"]');
  await add.locator('input[name=username]').fill('second');
  await add.locator('input[name=new_password]').fill('second-admin-pw');
  await add.locator('input[name=password]').fill('wrong-pw');
  await add.getByRole('button', { name: 'Add administrator' }).click();
  await expect(page.locator('#add-msg')).toContainText('Wrong password');
  await add.locator('input[name=password]').fill('e2e-pass');
  await add.getByRole('button', { name: 'Add administrator' }).click();
  const row = page.getByRole('row', { name: /^second / });
  await expect(row).toBeVisible();

  // The new administrator signs in from a separate browser and keeps their session through a password change.
  const ctx = await browser.newContext({ baseURL });
  const other = await ctx.newPage();
  await other.goto('/login');
  await other.getByLabel('Username').fill('Second'); // names are case-insensitive
  await other.getByLabel('Password').fill('second-admin-pw');
  await other.getByRole('button', { name: 'Sign in', exact: true }).click();
  await other.waitForURL(/\/$/);
  await other.goto('/security');
  await other.getByLabel('Current password').fill('second-admin-pw');
  await other.getByLabel('New password').fill('second-new-pw-9');
  await other.getByRole('button', { name: 'Change password' }).click();
  await expect(other.getByLabel('Current password')).toHaveValue(''); // the page reloaded after a successful change
  await other.goto('/users');
  await expect(other.getByRole('heading', { name: 'Users' })).toBeVisible(); // still signed in

  // The first administrator removes them; their session is dead at once.
  await row.getByText('Manage').click();
  const remove = row.locator('form[hx-post$="/delete"]');
  await remove.locator('input[name=password]').fill('e2e-pass');
  page.once('dialog', (d) => d.accept());
  await remove.getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByRole('row', { name: /^second / })).toHaveCount(0);
  await other.goto('/');
  await expect(other).toHaveURL(/\/login$/);
  await ctx.close();

  // Everything above is on the Audit page, newest first.
  await page.getByRole('link', { name: 'Audit' }).click();
  await expect(page.getByRole('heading', { name: 'Audit' })).toBeVisible();
  for (const what of ['user.removed', 'user.password', 'user.added', 'reauth.failed']) {
    await expect(page.getByRole('row', { name: new RegExp(what.replace('.', '\\.')) }).first()).toBeVisible();
  }
  await expect(page.getByRole('row', { name: /user\.added.*second/ })).toBeVisible();
});

test('the sign-in form asks for a username and refuses an unknown one the same way', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('Username').fill('nobody');
  await page.getByLabel('Password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Wrong username or password' })).toBeVisible();
  await expect(page).toHaveURL(/\/login$/);
});
