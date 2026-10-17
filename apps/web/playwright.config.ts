import { defineConfig } from '@playwright/test';

const e2ePort = process.env.WIRECLAW_E2E_PORT ?? '8765';
const externalAPI = process.env.WIRECLAW_E2E_EXTERNAL_API === '1';

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
    baseURL: `http://127.0.0.1:${e2ePort}`,
    viewport: { width: 1440, height: 1000 },
    browserName: 'chromium',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    launchOptions: process.env.WIRECLAW_BROWSER_PATH
      ? { executablePath: process.env.WIRECLAW_BROWSER_PATH }
      : {},
  },
  webServer: externalAPI
    ? undefined
    : {
        command: `python -m wireclaw_api.cli --data-root ../../artifacts/gate5-e2e --port ${e2ePort}`,
        url: `http://127.0.0.1:${e2ePort}/api/health`,
        reuseExistingServer: false,
        timeout: 20_000,
      },
});
