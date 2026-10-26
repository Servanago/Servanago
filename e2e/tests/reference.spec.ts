import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { test, expect, Page } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

const A = 'refa.static.example.test';
const B = 'refb.static.example.test';

async function addStatic(page: Page, host: string, notes: string) {
  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill(host);
  await page.getByLabel('Kind').selectOption('static');
  await page.getByLabel('Folder', { exact: true }).fill(mkdtempSync(join(tmpdir(), 'servanago-ref-')));
  await page.getByLabel('Notes').fill(notes);
  await page.getByRole('button', { name: 'Add site' }).click();
  await expect(siteRow(page, new RegExp(host.replace(/\./g, '\\.')))).toBeVisible();
}

async function removeSite(page: Page, host: string) {
  await page.waitForLoadState('networkidle'); // a navigation still in flight aborts the next goto
  await page.goto('/');
  const row = siteRow(page, new RegExp(host.replace(/\./g, '\\.')));
  await (await openRow(row)).getByRole('link', { name: 'Edit' }).click();
  await page.getByRole('button', { name: 'Delete site' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(row).toHaveCount(0);
}

test('reference page: notes, search, filter, sort, list view, edit link', async ({ page }) => {
  await login(page);
  await addStatic(page, A, 'owner: Brian\nrenews by hand');
  await addStatic(page, B, '');

  await page.goto('/reference');
  const a = page.locator(`article[data-name="${A}"]`);
  const b = page.locator(`article[data-name="${B}"]`);
  await expect(a).toBeVisible();
  await expect(a.locator('pre.notes')).toContainText('renews by hand');

  // Search narrows to one card and the URL records it.
  await page.getByLabel('Search').fill('refa');
  await expect(a).toBeVisible();
  await expect(b).toBeHidden();
  await expect(page).toHaveURL(/[?&]q=refa/);

  // Filter by kind and issues: a healthy static site is not an issue.
  await page.getByLabel('Search').fill('');
  await page.locator('#ref-kind').selectOption('static'); // a select's label includes its options, so go by id
  await expect(a).toBeVisible();
  await page.getByLabel('Issues only').check();
  await expect(a).toBeHidden();
  await page.getByLabel('Issues only').uncheck();

  // Sort by name puts A before B; recently changed is a different order only if the dates differ, so just check it applies.
  const names = () => page.locator('#ref-list article:not([hidden])').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.name));
  await page.locator('#ref-sort').selectOption('name');
  const sorted = (await names()).filter((n) => n === A || n === B);
  expect(sorted).toEqual([A, B]);

  // List view survives a reload; a row opens its details.
  await page.getByLabel('List').check();
  await expect(page).toHaveURL(/view=list/);
  await page.reload();
  await expect(page.locator('#ref')).toHaveClass(/view-list/);
  await expect(a.locator('.ref-detail')).toBeHidden();
  await a.locator('.ref-row').click();
  await expect(a.locator('.ref-detail')).toBeVisible();

  // The name links to the edit view.
  await a.getByRole('link', { name: `Edit ${A}`, exact: true }).first().click();
  await expect(page).toHaveURL(/\/sites\/\d+$/);
  await expect(page.getByLabel('Notes')).toHaveValue('owner: Brian\nrenews by hand');

  await removeSite(page, A);
  await removeSite(page, B);
});
