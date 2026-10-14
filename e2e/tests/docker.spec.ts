import { test, expect } from '@playwright/test';
import { existsSync } from 'node:fs';
import { login } from './helpers';

const sock = '/var/run/docker.sock';

test.describe('docker discovery panel', () => {
  test.skip(!existsSync(sock), 'no Docker socket on this machine');

  test('is shown on the new-route page when the socket is mounted', async ({ page }) => {
    await login(page);
    await page.goto('/routes/new');
    await expect(page.getByText('Docker containers')).toBeVisible();
  });
});
