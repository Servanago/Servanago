import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

test('waf tab: preset saves, invalid directives refused, custom + engine-on saves', async ({ page }) => {
  await login(page);
  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('waf.example.test');
  await page.getByLabel('Upstream host or IP').fill('192.168.1.24');
  await page.getByLabel('Upstream port').fill('8791');
  await page.getByRole('button', { name: 'Add site' }).click();

  await openRow(siteRow(page, /waf\.example\.test/)).then(row =>
    row.getByRole('link', { name: 'Edit' }).click());
  await page.locator('nav[aria-label="Site sections"]').getByRole('link', { name: 'WAF' }).click();
  await expect(page.getByText("Off — the site's requests are not inspected.")).toBeVisible();

  await page.getByLabel('Ruleset').selectOption('crs');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText('Saved and applied.').first()).toBeVisible();

  await page.getByLabel('Ruleset').selectOption('custom');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText('Saved and applied.').first()).toBeVisible();

  await page.getByLabel('Custom directives').fill('SecAuditLog /var/log/x.log');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText('SecAuditLog').first()).toBeVisible();

  await page.getByLabel('Custom directives').fill('SecRuleEngine On');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText('Saved and applied.').first()).toBeVisible();

  await page.getByLabel('Ruleset').selectOption('');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText("Off — the site's requests are not inspected.")).toBeVisible();
});