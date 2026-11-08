import { defineConfig } from '@playwright/test'

// RASP_E2E_PORT lets the suite run next to a console already using the default port.
const port = process.env.RASP_E2E_PORT || '18480'

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  use: { baseURL: `http://127.0.0.1:${port}`, viewport: { width: 1440, height: 1100 }, trace: 'retain-on-failure', screenshot: 'only-on-failure', launchOptions: { executablePath: process.env.RASP_CHROMIUM_EXECUTABLE || undefined } },
  webServer: {
    command: 'npm run build && node tests/start-server.mjs',
    url: `http://127.0.0.1:${port}`,
    timeout: 120000,
    reuseExistingServer: false,
  },
})
