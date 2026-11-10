import { expect, test } from '@playwright/test'

// The credit-funded session card runs only on the local sandbox with the
// payment-channels artifacts (see typescript/examples/playground-api/credits.ts):
//   PAYMENT_CHANNELS_V2_SO=<payment-channels>/target/deploy-v2/payment_channels.so
//   CREDIT_PROVIDER_SO=<payment-channels>/target/deploy/credit_provider.so
test('a credit provider funds a session through lifecycle hooks', async ({ page, request }) => {
  const status = (await (await request.get('/api/v1/credits/status')).json()) as { enabled: boolean; reason?: string }
  test.skip(!status.enabled, `credit demo disabled: ${status.reason ?? ''}`)

  await page.goto('/')
  await page.getByRole('button', { name: 'Fund a new account' }).click()
  await expect(page.getByRole('heading', { name: 'Account funded' })).toBeVisible({ timeout: 120_000 })
  await page.getByRole('button', { name: 'Enter playground' }).click()
  await page.locator('button.topnav-pill.credits').click()
  await expect(page.locator('.page-head .path')).toHaveText('/api/v1/credits/:customer/quote')

  await page.getByRole('button', { name: 'Run the credit-funded session' }).click()
  await expect(page.getByRole('button', { name: 'Run again' })).toBeVisible({ timeout: 120_000 })

  const row = (label: string) => page.locator('.credits-balances tr', { hasText: label }).locator('td')
  // 2 USDC of credits, 3 requests at 0.01: 0.03 spent, 0.97 restored.
  await expect(row('Customer credits')).toHaveText('1.97 USDC')
  await expect(row('Provider vault (backing)')).toHaveText('1.97 USDC')
  await expect(row('Channel escrow')).toHaveText('closed')
  await expect(row('Merchant earned')).toHaveText('+0.03 USDC')
  await expect(row('Ledger funded / refunded')).toHaveText('1 USDC / 0.97 USDC')
  await expect(row('Requests served')).toHaveText('3')
  await expect(page.locator('.event-msg.error')).toHaveCount(0)
})
