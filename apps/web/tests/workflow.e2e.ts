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
  await page.getByRole('button', { name: 'Send' }).click();
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
  if (!(await page.locator('.case-context').evaluate((element) => element.hasAttribute('open'))))
    await page.getByText('Case details', { exact: true }).click();
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
  await expect(page.getByRole('button', { name: 'Send' })).toBeDisabled();
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
  const bridgeHealthRequests: string[] = [];
  const apiOrigin = `http://127.0.0.1:${process.env.WIRECLAW_E2E_PORT ?? 8765}`;
  const bridgeOrigin = 'http://127.0.0.1:8766';
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.origin === apiOrigin) return;
    if (url.origin === bridgeOrigin && url.pathname === '/v1/health') {
      bridgeHealthRequests.push(request.url());
      return;
    }
    remoteRequests.push(request.url());
  });
  const id = await analyze(page, 'high_rtt');
  await expect(page.getByRole('heading', { name: 'Supported finding', exact: true })).toBeVisible();
  const report = await (await request.get(`/api/cases/${id}/report`)).json();
  await expect(page.getByText(report.conclusion.statement, { exact: true }).first()).toBeVisible();
  await page.getByText('Time attribution and measurement details', { exact: true }).click();
  await expect(page.getByText('Stage subtotal:', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Open Full Capture in Wireshark' })).toBeDisabled();
  await expect(
    page.getByRole('button', { name: 'Open Evidence Capture in Wireshark' }),
  ).toBeDisabled();
  await expect(page.getByText(/Native Wireshark bridge unavailable/)).toBeVisible();
  await expect(page.locator('.validation-actions .button-row button')).toHaveCount(2);
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.getByRole('button', { name: 'Copy Wireshark Display Filter' }).click();
  await expect(
    page.getByRole('status').filter({ hasText: 'Display filter copied.' }),
  ).toBeVisible();
  const reportFinding = report.findings.find(
    (item: { wireshark: { applicable: boolean } }) => item.wireshark.applicable,
  );
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    reportFinding.wireshark.display_filter,
  );
  await axe(page);
  await noOverflow(page);
  await page.screenshot({ path: resolve(visuals, 'supported-desktop.png'), fullPage: true });
  const evidenceButton = page.getByRole('button', { name: 'Show Packet Evidence' });
  await evidenceButton.click();
  const drawer = page.getByRole('dialog', { name: 'Expert evidence' });
  await expect(drawer.getByRole('heading', { name: 'Normalized values' })).toBeVisible();
  await axe(page);
  await noOverflow(page);
  await page.screenshot({ path: resolve(visuals, 'evidence-desktop.png'), fullPage: true });
  await page.keyboard.press('Escape');
  await expect(drawer).not.toBeVisible();
  await expect(evidenceButton).toBeFocused();
  await page
    .getByRole('button', { name: 'Create evidence capture without opening Wireshark' })
    .click();
  await expect(
    page.getByRole('status').filter({ hasText: 'Focused evidence capture created locally' }),
  ).toBeVisible();
  await axe(page);
  await noOverflow(page);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Supported finding', exact: true })).toBeVisible();
  await page.getByText('Case details', { exact: true }).click();
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
  expect(bridgeHealthRequests.length).toBeGreaterThan(0);
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
    await page.getByRole('button', { name: 'Show Packet Evidence' }).click();
    await expect(page.getByRole('heading', { name: 'Normalized values' })).toBeVisible();
    await noOverflow(page);
    await axe(page);
    await page.keyboard.press('Escape');
    await remove(page);
  });
}

for (const width of [1440, 390]) {
  test(`recent history opens, renames, and confirms deletion at ${width}px`, async ({
    page,
    request,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    const captureName = `history-${width}.pcap`;
    const displayName = `Office capture ${width}`;
    const createdResponse = await request.post('/api/cases', {
      data: { symptom: 'application is slow', capture_name: captureName },
    });
    expect(createdResponse.ok()).toBe(true);
    const created = await createdResponse.json();
    const uploaded = await request.post(`/api/cases/${created.id}/capture`, {
      headers: { 'Content-Type': 'application/octet-stream' },
      data: readFileSync(resolve(captures, 'high_rtt.pcap')),
    });
    expect(uploaded.ok()).toBe(true);
    expect((await request.post(`/api/cases/${created.id}/investigate`)).ok()).toBe(true);
    const browserMutations: { method: string; body: unknown }[] = [];
    page.on('request', (event) => {
      if (['POST', 'PATCH', 'DELETE'].includes(event.method())) {
        browserMutations.push({ method: event.method(), body: event.postDataJSON() });
      }
    });
    await page.goto('/');
    const historyButton = page.getByRole('button', { name: 'Recent captures', exact: true });
    await historyButton.click();
    let popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await expect(
      popover.getByRole('button', { name: `Open ${captureName}`, exact: true }),
    ).toBeVisible();
    await noOverflow(page);
    await popover.getByRole('button', { name: `Open ${captureName}`, exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Supported finding', exact: true }),
    ).toBeVisible();
    expect(browserMutations).toEqual([]);
    await expect(page).toHaveURL(new RegExp(`#case=${created.id}$`));
    const beforeRename = await (await request.get(`/api/cases/${created.id}`)).json();
    const beforeReport = await (await request.get(`/api/cases/${created.id}/report`)).json();
    await historyButton.click();
    popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await popover.getByLabel(`Actions for ${captureName}`, { exact: true }).click();
    await popover.getByRole('button', { name: 'Rename', exact: true }).click();
    await popover.getByLabel('Display name', { exact: true }).fill(displayName);
    await popover.getByRole('button', { name: 'Save name', exact: true }).click();
    await expect(
      popover.getByRole('button', { name: `Open ${displayName}`, exact: true }),
    ).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(popover).not.toBeVisible();
    await expect(historyButton).toBeFocused();
    await expect(page.locator('.selected-file')).toContainText(displayName);
    const afterRename = await (await request.get(`/api/cases/${created.id}`)).json();
    expect(afterRename.capture_sha).toBe(beforeRename.capture_sha);
    expect(afterRename.original_id).toBe(beforeRename.original_id);
    expect(afterRename.runs).toEqual(beforeRename.runs);
    expect(afterRename.history).toEqual(beforeRename.history);
    expect(await (await request.get(`/api/cases/${created.id}/report`)).json()).toEqual(
      beforeReport,
    );
    expect(browserMutations).toEqual([{ method: 'PATCH', body: { display_name: displayName } }]);
    await page.getByRole('button', { name: 'New case', exact: true }).click();
    await historyButton.click();
    popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await popover.getByRole('button', { name: `Open ${displayName}`, exact: true }).click();
    await expect(
      page.getByRole('heading', { name: 'Supported finding', exact: true }),
    ).toBeVisible();
    expect(browserMutations).toHaveLength(1);
    await historyButton.click();
    popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await popover.getByLabel(`Actions for ${displayName}`, { exact: true }).click();
    await popover.getByRole('button', { name: 'Delete', exact: true }).click();
    let confirmation = page.getByRole('dialog', { name: 'Delete this case?', exact: true });
    await expect(confirmation).toContainText('stored original capture');
    expect(browserMutations).toHaveLength(1);
    await confirmation.getByRole('button', { name: 'Keep case', exact: true }).click();
    await expect(confirmation).not.toBeVisible();
    await noOverflow(page);
    await page.screenshot({
      path: resolve('test-results', `recent-history-${width}.png`),
      fullPage: true,
    });
    await popover.getByRole('button', { name: 'Delete', exact: true }).click();
    confirmation = page.getByRole('dialog', { name: 'Delete this case?', exact: true });
    await confirmation
      .getByRole('button', { name: 'Delete case and stored files', exact: true })
      .click();
    await expect(page.getByText(/deleted, including its stored original capture/)).toBeVisible();
    expect((await request.get(`/api/cases/${created.id}`)).status()).toBe(404);
    expect(browserMutations.map((event) => event.method)).toEqual(['PATCH', 'DELETE']);
    await historyButton.click();
    popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await expect(
      popover.getByRole('button', { name: `Open ${displayName}`, exact: true }),
    ).toHaveCount(0);
    await page.keyboard.press('Escape');
    await expect(historyButton).toBeFocused();
    await noOverflow(page);
  });
}
