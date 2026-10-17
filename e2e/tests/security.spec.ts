import { test, expect, Page } from '@playwright/test';
import { createHmac } from 'node:crypto';

// WebAuthn needs a secure context and a real hostname: localhost qualifies, 127.0.0.1 does not.
test.use({ baseURL: 'http://localhost:28081' });

function base32(s: string): Buffer {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '')) bits += A.indexOf(c).toString(2).padStart(5, '0');
  const out: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

function totp(secret: string): string {
  const ctr = Buffer.alloc(8);
  ctr.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac('sha1', base32(secret)).update(ctr).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1_000_000).padStart(6, '0');
}

async function signIn(page: Page) {
  await page.goto('/login');
  await page.getByLabel('Username').fill('admin');
  await page.getByLabel('Password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
}

test('authenticator app: enroll, sign in with a backup code, turn off', async ({ page }) => {
  page.on('dialog', (d) => d.accept());
  await signIn(page);
  await page.waitForURL(/\/$/);
  await page.goto('/security');
  await page.getByLabel('Password to start').fill('e2e-pass');
  await page.getByRole('button', { name: 'Set up authenticator' }).click();
  const secret = (await page.locator('#totp-setup code').first().innerText()).trim();
  await page.getByLabel('Code from the app').fill(totp(secret));
  await page.getByRole('button', { name: 'Confirm' }).click();
  const codes = await page.locator('#totp-msg li code').allInnerTexts();
  expect(codes).toHaveLength(10);

  await page.getByRole('button', { name: 'Sign out' }).click();
  await signIn(page);
  await expect(page).toHaveURL(/\/login\/totp$/);
  await page.getByLabel('Code', { exact: true }).fill('000000');
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Wrong code' })).toBeVisible();
  await page.getByLabel('Code', { exact: true }).fill(codes[0]);
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page).toHaveURL(/\/$/);

  await page.goto('/security');
  await page.getByLabel('Password to turn off').fill('e2e-pass');
  await page.getByLabel('Code to turn off').fill(codes[1]);
  await page.getByRole('button', { name: 'Turn off' }).click();
  await expect(page.getByText('Off. Adds a 6-digit code')).toBeVisible();
});

test('passkey: add, sign in without the password, delete', async ({ page }) => {
  page.on('dialog', (d) => d.accept());
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });

  await signIn(page);
  await page.waitForURL(/\/$/);
  await page.goto('/security');
  await page.getByLabel('Passkey name').fill('e2e key');
  await page.getByLabel('Password to add passkey').fill('e2e-pass');
  await page.getByRole('button', { name: 'Add passkey' }).click();
  await expect(page.getByRole('cell', { name: 'e2e key' })).toBeVisible();

  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.goto('/login');
  await page.getByRole('button', { name: 'Sign in with passkey' }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

  await page.goto('/security');
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('None yet.')).toBeVisible();
});
