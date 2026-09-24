import { defineConfig, devices } from '@playwright/test'

const baseURL = process.env.PLAYGROUND_BASE_URL ?? 'http://localhost:5173'

export default defineConfig({
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? 'github' : 'list',
  testMatch: 'smoke.spec.ts',
  timeout: 30_000,
  use: {
    ...devices['Desktop Chrome'],
    baseURL,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'pnpm dev:app',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
    url: baseURL,
  },
})
