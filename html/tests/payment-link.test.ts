import { test, expect } from '@playwright/test';

// Configurable via env: FORTUNE_PATH defaults to /fortune
const FORTUNE = process.env.FORTUNE_PATH ?? '/fortune';
const SERVICE_WORKER_PATTERN = /__mpp_worker|__mppx_worker/;

test('payment link page renders correctly', async ({ page }) => {
  const response = await page.goto(FORTUNE, { waitUntil: 'networkidle' });
  expect(response?.status()).toBe(402);
  expect(response?.headers()['content-type']).toContain('text/html');
  await expect(page.locator('#root')).toBeVisible();
  await expect(page.getByRole('button', { name: /Continue with Solana/i })).toBeEnabled();
});

test('clicking pay triggers the payment flow', async ({ page, context }) => {
  await page.goto(FORTUNE, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /Continue with Solana/i }).click();

  await expect
    .poll(async () => {
      const workerUrls = context.serviceWorkers().map(worker => worker.url());
      const registrationUrl = await page
        .evaluate(async () => {
          const registration = await navigator.serviceWorker.getRegistration('/');
          return registration?.active?.scriptURL ?? registration?.installing?.scriptURL ?? registration?.waiting?.scriptURL ?? null;
        })
        .catch(() => null);

      return [...workerUrls, registrationUrl].filter(Boolean).some(url => SERVICE_WORKER_PATTERN.test(url!));
    }, { timeout: 30_000 })
    .toBe(true);
});

test('full e2e: payment completes and returns fortune', async ({ page }) => {
  await page.goto(FORTUNE, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /Continue with Solana/i }).click();

  // Wait for the service worker reload cycle
  await page.waitForLoadState('networkidle', { timeout: 30_000 });
  await page.waitForTimeout(3000);

  // The page must build a transaction the server admits (version 0: MPP
  // servers refuse legacy messages), so only the paid response passes. A
  // re-rendered payment page or an RFC 9457 problem document is a failure.
  const content = await page.content();
  expect(content).not.toContain('paymentauth.org/problems/');
  expect(content).toContain('"fortune"');
});

test('service worker endpoint returns javascript', async ({ page }) => {
  // Try mppx param first (TS demo), fall back to standalone param (Rust/Go/Lua)
  let response = await page.goto(`${FORTUNE}?__mppx_worker=1`);
  if (response?.status() !== 200) {
    response = await page.goto(`${FORTUNE}?__mpp_worker=1`);
  }
  expect(response?.status()).toBe(200);
  expect(response?.headers()['content-type']).toContain('application/javascript');
  const body = await response?.text();
  expect(body).toContain('addEventListener');
});

test('API client gets JSON 402 not HTML', async ({ request }) => {
  const response = await request.get(FORTUNE, {
    headers: { Accept: 'application/json' },
  });
  expect(response.status()).toBe(402);
  expect(response.headers()['www-authenticate']).toContain('Payment');
});
