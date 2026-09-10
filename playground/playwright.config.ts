import { defineConfig, devices } from '@playwright/test'

// Match Vite's default listener name. On Ubuntu, `localhost` may bind only
// IPv6, so probing 127.0.0.1 can time out even while the server is healthy.
const baseURL = process.env.PLAYGROUND_BASE_URL ?? 'http://localhost:5173'

export default defineConfig({
  forbidOnly: !!process.env.CI,
  fullyParallel: false,
  outputDir: 'test-results',
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : 'list',
  retries: process.env.CI ? 1 : 0,
  testDir: 'tests',
  timeout: 120_000,
  use: {
    ...devices['Desktop Chrome'],
    baseURL,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'pnpm dev',
    reuseExistingServer: !process.env.CI,
    stderr: 'pipe',
    stdout: 'pipe',
    timeout: 180_000,
    // Vite can accept connections before the API has finished funding its
    // operator and bootstrapping the subscription plan. Wait through the
    // proxy for discovery so onboarding cannot race the faucet route.
    url: `${baseURL}/openapi.json`,
  },
  workers: 1,
})
