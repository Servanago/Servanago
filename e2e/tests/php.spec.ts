import { test, expect } from '@playwright/test';
import { login } from './helpers';

// The e2e server has no helper and no ServanaGo PHP build: the page must still render and explain, not break.
test('the PHP page renders without a helper or a build', async ({ page }) => {
  await login(page);
  await page.goto('/php');
  await expect(page.getByRole('heading', { name: /^PHP/ })).toBeVisible();
  await expect(page.getByText('No ServanaGo PHP build yet')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Build', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Check now' })).toBeVisible();
  await expect(page.getByText('could not report the build state')).toBeVisible();
});

test('a PHP site form offers the extension checklist and the health path', async ({ page }) => {
  await login(page);
  await page.goto('/sites/new');
  await page.getByLabel('Kind').selectOption('php');
  await expect(page.getByLabel('mbstring')).toBeChecked();
  await expect(page.getByLabel('curl')).not.toBeChecked();
  await expect(page.getByLabel('Health path (optional)')).toBeVisible();
});

test('the navigation links to the PHP page', async ({ page }) => {
  await login(page);
  await page.getByRole('link', { name: 'PHP', exact: true }).click();
  await expect(page).toHaveURL(/\/php$/);
});
