import { expect, test } from '@playwright/test'

test('renders the onboarding screen without startup errors', async ({ page }) => {
  const pageError = new Promise<never>((_, reject) => {
    page.once('pageerror', reject)
  })

  await page.goto('/')
  await Promise.race([
    expect(page.getByRole('button', { name: 'Fund a new account' })).toBeVisible(),
    pageError,
  ])
})
