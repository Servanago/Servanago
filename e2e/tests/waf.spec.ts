import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

test('waf tab: profiles, engine mode, invalid tail, rate limit, rules browser', async ({ page }) => {
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

  // a profile saves; the tab shows the profile chip and the detection engine after a reload
  await page.getByLabel('Ruleset').selectOption('shop');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText('Saved and applied.').first()).toBeVisible();
  await page.reload();
  await expect(page.getByText('Engine: DetectionOnly')).toBeVisible();

  // blocking is a setting now, not a directive
  await page.getByLabel('Engine mode').selectOption('block');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText('Saved and applied.').first()).toBeVisible();
  await page.reload();
  await expect(page.getByText('Engine: blocking')).toBeVisible();

  // the engine line cannot hide in a custom tail
  await page.getByLabel('Ruleset').selectOption('custom');
  await page.getByLabel('Custom directives').fill('SecRuleEngine On');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText('SecRuleEngine').first()).toBeVisible();

  await page.getByLabel('Custom directives').fill('');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText('Saved and applied.').first()).toBeVisible();

  // rate limiting saves and the chip appears after a reload
  await page.getByLabel('Requests per address').fill('150');
  await page.getByLabel('Window').selectOption('5m');
  await page.getByRole('button', { name: 'Save WAF' }).click();
  await expect(page.getByText('Saved and applied.').first()).toBeVisible();
  await page.reload();
  await expect(page.getByText('Rate limit: 150 / 5m')).toBeVisible();

  // the rules browser opens from the tab and lists the compiled files
  await page.getByRole('link', { name: 'Rules browser' }).click();
  await expect(page.getByRole('heading', { name: 'Rules files' })).toBeVisible();
  await page.getByRole('link', { name: 'Open', exact: true }).first().click();
  await expect(page.getByText('Back to all files')).toBeVisible();
});