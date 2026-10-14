import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('logs page renders Caddy lines and filters by level', async ({ page }) => {
  await login(page);
  await page.getByRole('link', { name: 'Logs' }).click();
  await expect(page.getByRole('heading', { name: 'Logs' })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'admin' }).first()).toBeVisible(); // "admin endpoint disabled" at startup

  await page.getByLabel('Minimum level').selectOption('error');
  await expect(page.locator('#log-rows tr.log-info')).toHaveCount(0);
});
