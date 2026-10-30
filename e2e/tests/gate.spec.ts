import { createServer } from 'http';
import { test, expect } from '@playwright/test';
import { login, openRow, siteRow } from './helpers';

// The gate is enforced by Caddy on the site's own host: HTTPS via the internal issuer
// (playwright.config.ts sets ACME_ISSUER=internal) and Chromium's host-resolver-rules maps the
// domain to 127.0.0.1. ignoreHTTPSErrors trusts Caddy's self-signed cert.
const GATE = 'https://st.gate.example.test:28443';

test.use({ ignoreHTTPSErrors: true });

test('gated site: magic link in, revoke out', async ({ page }) => {
  const upstream = createServer((req, res) => res.end('GATE-UPSTREAM'));
  await new Promise<void>((ok) => upstream.listen(29111, '127.0.0.1', ok));

  await login(page);

  await page.goto('/domains');
  await page.getByLabel('Domain', { exact: true }).fill('gate.example.test');
  await page.getByLabel('Default IP').fill('192.168.1.19');
  await page.getByRole('button', { name: 'Add domain' }).click();
  await expect(page.getByRole('cell', { name: 'gate.example.test' })).toBeVisible();

  await page.goto('/sites/new');
  await page.getByLabel('Hostnames').fill('st.gate.example.test');
  await page.getByLabel('Upstream host or IP').fill('127.0.0.1');
  await page.getByLabel('Upstream port').fill('29111');
  await page.locator('summary', { hasText: 'Magic-link access' }).click(); // access features start closed on a new site
  await page.locator('select[name=gate_mode]').selectOption('open');
  // The site mails its own links: point its provider at the SMTP sink.
  await page.locator('select[name=gate_provider]').selectOption('smtp');
  await page.getByLabel('Sender (From address)').fill('e2e@example.com');
  await page.getByLabel('SMTP host').fill('127.0.0.1');
  await page.getByLabel('SMTP port').fill('28097');
  await page.getByRole('button', { name: 'Add site' }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect((await openRow(siteRow(page, /st\.gate\.example\.test/))).getByText('gated (any email)')).toBeVisible();

  // Unauthenticated: the portal answers on the site host, the app never sees the request.
  await page.goto(GATE);
  await expect(page.getByRole('heading', { name: 'Request access to st.gate.example.test' })).toBeVisible();

  // Request a link; the page is the same whatever the address (enumeration-neutral).
  await page.getByPlaceholder('you@example.com').fill('visitor@example.net');
  await page.getByRole('button', { name: 'Send me a link' }).click();
  await expect(page.getByRole('heading', { name: 'Check your email' })).toBeVisible();

  const mail = await (await fetch('http://127.0.0.1:28098/last')).text();
  const link = mail.match(/https:\/\/\S+\/_gate\/verify\/\S+/)?.[0];
  expect(link, 'the SMTP sink captured the magic link').toBeTruthy();
  expect(link).toContain('https://ml.st.gate.example.test:28443/_gate/verify/');

  // The link opens on the ml host, which hands the session to the site host and lands on the site.
  await page.goto(link);
  await expect(page).toHaveURL(`${GATE}/`);
  await expect(page.getByText('GATE-UPSTREAM')).toBeVisible();
  await expect(page.getByText('Send me a link')).toBeHidden();

  // The operator sees the identity and revokes it from Security; the site gates again.
  await page.goto('http://127.0.0.1:28081/security');
  const row = page.getByRole('row', { name: /visitor@example\.net/ });
  await expect(row).toBeVisible();
  page.once('dialog', (d) => d.accept());
  await row.getByRole('button', { name: 'Revoke' }).click();
  await expect(page.getByRole('cell', { name: 'visitor@example.net' })).toBeHidden();

  await page.goto(GATE);
  await expect(page.getByRole('heading', { name: 'Request access' })).toBeVisible();

  // Shared server: remove the site so later specs see the same checklist state they expect.
  await page.goto('http://127.0.0.1:28081/');
  const gated = await openRow(siteRow(page, /st\.gate\.example\.test/));
  await expect(gated.getByRole('link', { name: 'Edit' })).toBeVisible();
  await gated.getByRole('button', { name: 'Delete' }).click();
  await page.locator('#delete-dialog').getByLabel('Type the site name to confirm deletion').fill('st.gate.example.test');
  await page.locator('#delete-dialog').getByRole('button', { name: 'Delete' }).click();
  await expect(siteRow(page, /st\.gate\.example\.test/)).toHaveCount(0);

  await new Promise<void>((ok) => upstream.close(() => ok()));
});