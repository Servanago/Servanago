import { test, expect } from '@playwright/test';
import { navTo, login } from './helpers';

// No real upgrade runs in e2e: the check has no trusted key in this build, so the page can only show its own state.
test('the Updates page opens from the nav and reports the running version', async ({ page }) => {
  await login(page);
  await navTo(page, 'Updates');
  await expect(page.getByRole('heading', { name: 'Updates', level: 1 })).toBeVisible();
  await expect(page.getByText('This host runs')).toBeVisible();
  await expect(page.getByRole('button', { name: /^Upgrade to/ })).toHaveCount(0);
});
