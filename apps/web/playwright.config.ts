import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testMatch: '**/*.e2e.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 20_000 },
  outputDir: 'test-results/browser',
  reporter: [['list'], ['json', { outputFile: 'test-results/browser-summary.json' }]],
  use: {
    baseURL: 'http://127.0.0.1:8765',
    viewport: { width: 1440, height: 1000 },
    browserName: 'chromium',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    launchOptions: process.env.WIRECLAW_BROWSER_PATH
      ? { executablePath: process.env.WIRECLAW_BROWSER_PATH }
      : {},
  },
  webServer: {
    command: 'python -m wireclaw_api.cli --data-root ../../artifacts/gate5-e2e --port 8765',
    url: 'http://127.0.0.1:8765/api/health',
    reuseExistingServer: false,
    timeout: 20_000,
  },
});
