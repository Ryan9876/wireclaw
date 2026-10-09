import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const captures = resolve('../../artifacts/web-captures');
const visuals = resolve('../../docs/gate5-visual');
async function analyze(page: Page, capture: string, symptom = 'application is slow') {
  await page.goto('/');
  await page.getByLabel('Select capture').setInputFiles(resolve(captures, `${capture}.pcap`));
  await page.getByLabel('Symptom / problem description').fill(symptom);
  await page.getByRole('button', { name: 'Investigate capture' }).click();
  await expect(page).toHaveURL(/#case=[a-f0-9]{32}$/);
  return new URL(page.url()).hash.slice(6);
}
async function axe(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(results.violations).toEqual([]);
}
async function noOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
}
async function remove(page: Page) {
  await page.getByRole('button', { name: 'Delete case', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Delete this case?' });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Delete case and stored files' }).click();
  await expect(page.getByText(/deleted, including its stored original capture/)).toBeVisible();
}

test('intake has semantic labels, keyboard access, no overflow, and clean accessibility', async ({
  page,
}) => {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Investigate capture' })).toBeDisabled();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to investigation' })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('main')).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByLabel('Select capture')).toBeFocused();
  await axe(page);
  await noOverflow(page);
  await page.screenshot({ path: resolve(visuals, 'intake-desktop.png'), fullPage: true });
});

test('supported finding is the backend result; evidence drawer, reload, and deletion work', async ({
  page,
  request,
}) => {
  const errors: string[] = [];
  const remoteRequests: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => {
    if (!request.url().startsWith('http://127.0.0.1:8765/')) remoteRequests.push(request.url());
  });
  const id = await analyze(page, 'high_rtt');
  await expect(page.getByRole('heading', { name: 'Supported finding', exact: true })).toBeVisible();
  const report = await (await request.get(`/api/cases/${id}/report`)).json();
  await expect(page.getByText(report.conclusion.statement, { exact: true }).first()).toBeVisible();
  await expect(page.getByText('Stage subtotal:', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Open Full Capture in Wireshark' })).toBeDisabled();
  await expect(
    page.getByRole('button', { name: 'Open Evidence Capture in Wireshark' }),
  ).toBeDisabled();
  await axe(page);
  await noOverflow(page);
  await page.screenshot({ path: resolve(visuals, 'supported-desktop.png'), fullPage: true });
  const evidenceButton = page.getByRole('button', { name: 'Show packet evidence' });
  await evidenceButton.click();
  const drawer = page.getByRole('dialog', { name: 'Expert evidence' });
  await expect(drawer.getByRole('heading', { name: 'Normalized values' })).toBeVisible();
  await axe(page);
  await noOverflow(page);
  await page.screenshot({ path: resolve(visuals, 'evidence-desktop.png'), fullPage: true });
  await page.keyboard.press('Escape');
  await expect(drawer).not.toBeVisible();
  await expect(evidenceButton).toBeFocused();
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Supported finding', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Delete case', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Delete this case?' });
  await expect(dialog.getByRole('button', { name: 'Keep case' })).toBeFocused();
  await axe(page);
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press('Tab');
    expect(await dialog.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  }
  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  await expect(page.getByRole('button', { name: 'Delete case', exact: true })).toBeFocused();
  await remove(page);
  expect((await request.get(`/api/cases/${id}`)).status()).toBe(404);
  expect(errors).toEqual([]);
  expect(remoteRequests).toEqual([]);
});

test('healthy capture completes with insufficient evidence and discriminating next evidence', async ({
  page,
}) => {
  await analyze(page, 'clean_tcp');
  await expect(
    page.getByRole('heading', { name: 'Insufficient evidence', exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Remaining hypotheses' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Recommended next evidence' })).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Investigation failed', exact: true }),
  ).not.toBeVisible();
  await axe(page);
  await page.screenshot({ path: resolve(visuals, 'insufficient-desktop.png'), fullPage: true });
  await remove(page);
});

test('midstream capture keeps its quality limitations and uncertainty visible', async ({
  page,
}) => {
  await analyze(page, 'midstream');
  await expect(page.getByRole('heading', { name: /Capture quality: limited/i })).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Insufficient evidence', exact: true }),
  ).toBeVisible();
  await expect(page.getByText(/midstream/i).first()).toBeVisible();
  await axe(page);
  await page.screenshot({ path: resolve(visuals, 'limited-desktop.png'), fullPage: true });
  await remove(page);
});

test('malformed capture fails clearly, recovers across reload, and can be deleted', async ({
  page,
  request,
}) => {
  const id = await analyze(page, 'malformed');
  await expect(
    page.getByRole('heading', { name: 'Investigation failed', exact: true }),
  ).toBeVisible();
  await expect(page.getByText('Backend error:', { exact: false })).toBeVisible();
  expect((await (await request.get(`/api/cases/${id}`)).json()).state).toBe('FAILED');
  await page.reload();
  await expect(
    page.getByRole('heading', { name: 'Investigation failed', exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Resume capture intake' })).toBeVisible();
  await axe(page);
  await page.screenshot({ path: resolve(visuals, 'failed-desktop.png'), fullPage: true });
  await remove(page);
});

test('recovers uploaded idle case without automatically posting investigation', async ({
  page,
  request,
}) => {
  const created = await (
    await request.post('/api/cases', { data: { symptom: 'application is slow' } })
  ).json();
  const upload = await request.post(`/api/cases/${created.id}/capture`, {
    headers: { 'Content-Type': 'application/octet-stream' },
    data: readFileSync(resolve(captures, 'high_rtt.pcap')),
  });
  expect(upload.ok()).toBe(true);
  const mutations: string[] = [];
  page.on('request', (event) => {
    if (event.method() === 'POST') mutations.push(event.url());
  });
  await page.goto(`/#case=${created.id}`);
  await expect(page.getByRole('button', { name: 'Continue investigation' })).toBeVisible();
  expect(mutations).toEqual([]);
  await page.getByRole('button', { name: 'Continue investigation' }).click();
  await expect(page.getByRole('heading', { name: 'Supported finding', exact: true })).toBeVisible();
  expect(mutations).toHaveLength(1);
  await remove(page);
});

for (const width of [390, 768, 1024]) {
  test(`primary workflow and evidence are usable at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('/');
    await noOverflow(page);
    await axe(page);
    await analyze(page, 'high_rtt');
    await expect(
      page.getByRole('heading', { name: 'Supported finding', exact: true }),
    ).toBeVisible();
    await noOverflow(page);
    await axe(page);
    await page.screenshot({ path: resolve(visuals, `supported-${width}.png`), fullPage: true });
    await page.getByRole('button', { name: 'Show packet evidence' }).click();
    await expect(page.getByRole('heading', { name: 'Normalized values' })).toBeVisible();
    await noOverflow(page);
    await axe(page);
    await page.keyboard.press('Escape');
    await remove(page);
  });
}
