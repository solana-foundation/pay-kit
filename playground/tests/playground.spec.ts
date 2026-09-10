import { expect, type Page, test } from '@playwright/test'

test.describe.configure({ mode: 'serial' })

let page: Page

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage()
  await page.goto('/')
  await page.getByRole('button', { name: 'Fund a new account' }).click()
  await expect(
    page.getByRole('heading', { name: 'Account funded' }),
  ).toBeVisible({ timeout: 120_000 })
  await page.getByRole('button', { name: 'Enter playground' }).click()
  await expect(
    page.getByRole('navigation', { name: 'Endpoints' }),
  ).toBeVisible()
})

test.afterAll(async () => {
  await page?.close()
})

type Scenario = {
  method: 'GET' | 'POST'
  path: string
  protocol: 'mpp' | 'x402'
  response: RegExp
}

async function runScenario({
  method,
  path,
  protocol,
  response,
}: Scenario): Promise<void> {
  await page.locator(`button[title^="${method} ${path}"]`).click()
  await expect(page.locator('.page-head .path')).toHaveText(path)

  const reset = page.getByRole('button', { name: 'Reset' })
  await reset.click()

  const toggle = page.getByRole('group', { name: 'Payment protocol' })
  if (await toggle.isVisible()) {
    await toggle.getByRole('button', { name: protocol, exact: true }).click()
    await expect(
      toggle.getByRole('button', { name: protocol, exact: true }),
    ).toHaveClass(/active/)
  }

  await page.getByRole('button', { name: 'Send request' }).click()
  const status = page.locator('.response-status .code')
  await expect(status).toBeVisible({ timeout: 120_000 })
  await expect(status).toHaveText('200')
  await expect(page.locator('.response-body')).toContainText(response)
  await expect(page.locator('.event-log')).toContainText('402 Payment Required')
  await expect(page.locator('.event-log')).toContainText('200 OK')
  await expect(page.getByRole('button', { name: 'Send request' })).toBeEnabled({
    timeout: 30_000,
  })
}

test('quote succeeds over MPP', async () => {
  await runScenario({
    method: 'GET',
    path: '/api/v1/quote/:symbol',
    protocol: 'mpp',
    response: /"via": "mpp"/,
  })
})

test('quote succeeds over x402', async () => {
  await runScenario({
    method: 'GET',
    path: '/api/v1/quote/:symbol',
    protocol: 'x402',
    response: /"via": "x402"/,
  })
})

test('fortune succeeds over MPP', async () => {
  await runScenario({
    method: 'GET',
    path: '/api/v1/fortune',
    protocol: 'mpp',
    response: /"fortune":/,
  })
})

test('fortune succeeds over x402', async () => {
  await runScenario({
    method: 'GET',
    path: '/api/v1/fortune',
    protocol: 'x402',
    response: /"fortune":/,
  })
})

test('split charge succeeds over MPP', async () => {
  await runScenario({
    method: 'GET',
    path: '/api/v1/joke',
    protocol: 'mpp',
    response: /"joke":/,
  })
})

test('usage settlement succeeds over x402', async () => {
  await runScenario({
    method: 'POST',
    path: '/api/v1/summarize',
    protocol: 'x402',
    response: /"billedBaseUnits":/,
  })
})

test('subscription activation succeeds over MPP', async () => {
  await runScenario({
    method: 'GET',
    path: '/api/v1/feed',
    protocol: 'mpp',
    response: /"headlines":/,
  })
})

test('metered session succeeds over MPP', async () => {
  await runScenario({
    method: 'GET',
    path: '/api/v1/stream',
    protocol: 'mpp',
    response: /payment channel/i,
  })
  await expect(page.locator('.event-log')).toContainText('Voucher signed')
})
