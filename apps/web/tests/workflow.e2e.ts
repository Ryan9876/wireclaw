import { expect, test, type Page, type Locator } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { humanLimitation } from '../src/ReportView';

const captures = resolve('../../artifacts/web-captures');
const visuals = resolve('test-results');
let historyCaseId: string | undefined;
async function analyze(page: Page, capture: string, symptom = 'application is slow') {
  await page.goto('/');
  await page.getByLabel('Select capture').setInputFiles(resolve(captures, `${capture}.pcap`));
  await page.getByLabel('Symptom / problem description').fill(symptom);
  await page.getByRole('button', { name: 'Send' }).click();
  await expect(page).toHaveURL(/#case=[a-f0-9]{32}$/);
  return new URL(page.url()).hash.slice(6);
}
async function axe(page: Page, soft = false) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  (soft ? expect.soft : expect)(results.violations).toEqual([]);
}
async function hoveredContrast(page: Page, button: Locator) {
  await button.hover();
  const contrast = await button.evaluate((element) => {
    const style = getComputedStyle(element);
    const luminance = (color: string) => {
      const channels = color
        .match(/[\d.]+/g)!
        .slice(0, 3)
        .map((value) => {
          const channel = Number(value) / 255;
          return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
        });
      return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
    };
    const values = [luminance(style.color), luminance(style.backgroundColor)].sort((a, b) => b - a);
    return (values[0] + 0.05) / (values[1] + 0.05);
  });
  // Axe omits the Send arrow as non-text; check its computed foreground/background too.
  expect
    .soft(
      contrast,
      `${(await button.getAttribute('aria-label')) ?? (await button.innerText())} hover contrast`,
    )
    .toBeGreaterThanOrEqual(4.5);
  await axe(page, true);
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

test.afterEach(async ({ page, request }, testInfo) => {
  const isHistoryTest =
    testInfo.title ===
    'history_popover_and_evidence_drawer_are_keyboard_dismissible_and_restore_focus';
  const failedHistoryCase =
    isHistoryTest && testInfo.status !== 'passed' ? historyCaseId : undefined;
  historyCaseId = undefined;
  if (
    (!isHistoryTest &&
      testInfo.title !== 'single_window_capture_to_report_flow_has_no_dashboard_chrome') ||
    testInfo.status === 'passed'
  )
    return;
  const caseId = failedHistoryCase ?? page.url().match(/#case=([a-f0-9]{32})$/)?.[1];
  if (caseId) await request.delete(`/api/cases/${caseId}`);
});

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
  await expect(
    page.getByRole('heading', { name: "Here's what I found", exact: true }),
  ).toBeVisible();
  const report = await (await request.get(`/api/cases/${id}/report`)).json();
  await expect(page.getByText(/TCP acknowledgements took about/).first()).toBeVisible();
  await page.getByText('Technical report details', { exact: true }).click();
  await expect(page.getByText('Stage subtotal:', { exact: false })).toBeVisible();
  await page.getByText('Technical evidence', { exact: true }).first().click();
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
  const drawer = page.getByRole('dialog', { name: 'Technical evidence' });
  await expect(drawer.getByRole('heading', { name: 'What this shows' })).toBeVisible();
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
  await expect(
    page.getByRole('heading', { name: "Here's what I found", exact: true }),
  ).toBeVisible();
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
    page.getByRole('heading', { name: "Here's what I found", exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('heading', { name: 'What to check next' })).toBeVisible();
  await page.getByText('Technical report details', { exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Remaining possibilities' })).toBeVisible();
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
  await expect(page.getByText(/Capture quality was limited/i)).toBeVisible();
  await expect(
    page.getByRole('heading', { name: "Here's what I found", exact: true }),
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
  await expect(
    page.getByRole('status').filter({ hasText: 'Investigation stopped.' }),
  ).toHaveAttribute('aria-live', 'polite');
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
  await expect(
    page.getByRole('heading', { name: "Here's what I found", exact: true }),
  ).toBeVisible();
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
      page.getByRole('heading', { name: "Here's what I found", exact: true }),
    ).toBeVisible();
    await noOverflow(page);
    await axe(page);
    await page.screenshot({ path: resolve(visuals, `supported-${width}.png`), fullPage: true });
    await page.getByText('Technical evidence', { exact: true }).first().click();
    await page.getByRole('button', { name: 'Show Packet Evidence' }).click();
    await expect(page.getByRole('heading', { name: 'What this shows' })).toBeVisible();
    await noOverflow(page);
    await axe(page);
    await page.keyboard.press('Escape');
    await remove(page);
  });
}

for (const width of [1440, 390]) {
  test(`filled buttons preserve accessible contrast while hovered at ${width}px`, async ({
    page,
    request,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('/');
    const choose = page.getByRole('button', { name: 'Choose file', exact: true });
    await hoveredContrast(page, choose);
    await page.getByLabel('Select capture').setInputFiles(resolve(captures, 'high_rtt.pcap'));
    await page.getByLabel('Symptom / problem description').fill('application is slow');
    const send = page.getByRole('button', { name: 'Send', exact: true });
    await expect(send).toBeEnabled();
    await hoveredContrast(page, send);
    await send.click();
    await expect(
      page.getByRole('heading', { name: "Here's what I found", exact: true }),
    ).toBeVisible();
    const id = new URL(page.url()).hash.slice(6);
    await page.getByText('Case details', { exact: true }).click();
    await page.getByRole('button', { name: 'Delete case', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Delete this case?', exact: true });
    await hoveredContrast(
      page,
      dialog.getByRole('button', { name: 'Delete case and stored files', exact: true }),
    );
    await dialog.getByRole('button', { name: 'Keep case', exact: true }).click();
    expect((await request.delete(`/api/cases/${id}`)).ok()).toBe(true);
  });
  test(`recent history opens, renames, and confirms deletion at ${width}px`, async ({
    page,
    request,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    const captureName = `history-${width}-${Date.now()}.pcap`;
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
    const previousResponse = await request.post('/api/cases', {
      data: { symptom: 'previous investigation' },
    });
    expect(previousResponse.ok()).toBe(true);
    const previous = await previousResponse.json();
    await page.goto(`/#case=${previous.id}`);
    await expect(page.locator('.symptom')).toHaveText('previous investigation');
    const historyButton = page.getByRole('button', { name: 'Recent captures', exact: true });
    await historyButton.press('Enter');
    let popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await expect(
      popover.getByRole('button', { name: `Open ${captureName}`, exact: true }),
    ).toBeVisible();
    await noOverflow(page);
    await popover.getByRole('button', { name: `Open ${captureName}`, exact: true }).press('Enter');
    await expect(
      page.getByRole('heading', { name: "Here's what I found", exact: true }),
    ).toBeVisible();
    await expect(historyButton).toBeFocused();
    expect(browserMutations).toEqual([]);
    await expect(page).toHaveURL(new RegExp(`#case=${created.id}$`));
    const beforeRename = await (await request.get(`/api/cases/${created.id}`)).json();
    const beforeReport = await (await request.get(`/api/cases/${created.id}/report`)).json();
    await historyButton.press('Enter');
    popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await popover.getByLabel(`Actions for ${captureName}`, { exact: true }).press('Enter');
    await popover.getByRole('button', { name: 'Rename', exact: true }).press('Enter');
    await expect(popover.getByLabel('Display name', { exact: true })).toBeFocused();
    await popover.getByLabel('Display name', { exact: true }).fill(displayName);
    await axe(page);
    await popover.getByRole('button', { name: 'Save name', exact: true }).press('Enter');
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
    await page.getByRole('button', { name: 'New case', exact: true }).press('Enter');
    await historyButton.press('Enter');
    popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await popover.getByRole('button', { name: `Open ${displayName}`, exact: true }).press('Enter');
    await expect(
      page.getByRole('heading', { name: "Here's what I found", exact: true }),
    ).toBeVisible();
    expect(browserMutations).toHaveLength(1);
    await expect(historyButton).toBeFocused();
    await historyButton.press('Enter');
    popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await popover.getByLabel(`Actions for ${displayName}`, { exact: true }).press('Enter');
    await popover.getByRole('button', { name: 'Delete', exact: true }).press('Enter');
    let confirmation = page.getByRole('dialog', { name: 'Delete this case?', exact: true });
    await expect(confirmation).toContainText('stored original capture');
    await expect(
      confirmation.getByRole('button', { name: 'Keep case', exact: true }),
    ).toBeFocused();
    await axe(page);
    expect(browserMutations).toHaveLength(1);
    await confirmation.getByRole('button', { name: 'Keep case', exact: true }).press('Enter');
    await expect(confirmation).not.toBeVisible();
    await noOverflow(page);
    await page.screenshot({
      path: resolve('test-results', `recent-history-${width}.png`),
      fullPage: true,
    });
    await popover.getByRole('button', { name: 'Delete', exact: true }).press('Enter');
    confirmation = page.getByRole('dialog', { name: 'Delete this case?', exact: true });
    await confirmation
      .getByRole('button', { name: 'Delete case and stored files', exact: true })
      .press('Enter');
    await expect(page.getByText(/deleted, including its stored original capture/)).toBeVisible();
    expect((await request.get(`/api/cases/${created.id}`)).status()).toBe(404);
    expect(browserMutations.map((event) => event.method)).toEqual(['PATCH', 'DELETE']);
    await historyButton.press('Enter');
    popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
    await expect(
      popover.getByRole('button', { name: `Open ${displayName}`, exact: true }),
    ).toHaveCount(0);
    await page.keyboard.press('Escape');
    await expect(historyButton).toBeFocused();
    await noOverflow(page);
    expect((await request.delete(`/api/cases/${previous.id}`)).ok()).toBe(true);
  });
}

// These regressions exercise the compiled UI and real case/report/evidence API.
test('production header logo loads from the fixed same-origin asset route', async ({
  page,
  request,
}) => {
  await page.goto('/');
  const logo = page.getByRole('img', { name: 'Wireclaw', exact: true });
  await expect(logo).toBeVisible();
  const logoResponse = await request.get('/brand/wireclaw-logo.jpeg');
  expect(logoResponse.ok()).toBe(true);
  expect(logoResponse.headers()['content-type']).toContain('image/jpeg');
  expect(logoResponse.headers()['x-content-type-options']).toBe('nosniff');
  expect(logoResponse.headers()['content-security-policy']).toContain("img-src 'self'");
  expect((await logoResponse.body()).byteLength).toBeGreaterThan(0);
  await expect
    .poll(() =>
      logo.evaluate((image) => {
        const element = image as HTMLImageElement;
        return element.complete ? element.naturalWidth : 0;
      }),
    )
    .toBeGreaterThan(0);
  expect((await request.get('/brand/other.jpeg')).status()).toBe(404);
});

test('single_window_capture_to_report_flow_has_no_dashboard_chrome', async ({ page, request }) => {
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto('/');
  await expect(page.getByText('Recover existing case', { exact: true })).toBeVisible();
  await expect(page.getByRole('tab')).toHaveCount(0);
  await expect(page.getByRole('navigation')).toHaveCount(0);
  await expect(page.locator('aside')).toHaveCount(0);
  await page.screenshot({ path: resolve(visuals, 'task6-desktop-empty.png'), fullPage: true });
  // Activate the native file picker through the keyboard, then submit through the composer.
  await page.getByRole('button', { name: 'Choose file', exact: true }).focus();
  const chooser = page.waitForEvent('filechooser');
  await page.keyboard.press('Enter');
  await (await chooser).setFiles(resolve(captures, 'high_rtt.pcap'));
  await expect(page.getByRole('status').filter({ hasText: 'high_rtt.pcap' })).toBeVisible();
  await page.getByLabel('Symptom / problem description').fill('application is slow');
  let releaseInvestigation!: () => void;
  const waiting = new Promise<void>((resolve) => {
    releaseInvestigation = resolve;
  });
  await page.route('**/api/cases/*/investigate', async (route) => {
    await waiting;
    await route.continue();
  });
  await page.getByRole('button', { name: 'Send', exact: true }).focus();
  await page.keyboard.press('Enter');
  const processing = page.getByTestId('processing-wave');
  await expect(processing).toBeVisible();
  await expect(processing).toContainText('Analyzing network traffic…');
  await expect(processing).toHaveAttribute('aria-live', 'polite');
  await expect(processing).toHaveAttribute('data-motion', 'moderate');
  const claw = processing.locator('svg.processing-claw');
  await expect(claw).toHaveAttribute('aria-hidden', 'true');
  const jaw = claw.locator('.claw-upper-jaw');
  await expect(jaw).toHaveCount(1);
  const motion = await jaw.evaluate((element) => {
    const style = getComputedStyle(element);
    return { name: style.animationName, duration: style.animationDuration };
  });
  expect(motion.name).toBe('claw-snap');
  expect(motion.duration).toBe('1.1s');
  await page.screenshot({ path: resolve(visuals, 'processing-desktop.png'), fullPage: true });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  expect(await jaw.evaluate((element) => getComputedStyle(element).animationName)).toBe('none');
  expect(await jaw.evaluate((element) => getComputedStyle(element).transform)).not.toBe('none');
  releaseInvestigation();
  await expect(
    page.getByRole('heading', { name: "Here's what I found", exact: true }),
  ).toBeVisible();
  const id = new URL(page.url()).hash.slice(6);
  const before = await (await request.get(`/api/cases/${id}`)).json();
  const sourceBytes = readFileSync(resolve(captures, 'high_rtt.pcap'));
  const storedOriginal = resolve(
    '../../artifacts/gate5-e2e/cases',
    id,
    'analyzer/cases',
    before.capture_sha,
    'original/capture',
  );
  // External-API qualification uses API provenance; source-run E2E also compares the actual stored bytes.
  if (process.env.WIRECLAW_E2E_EXTERNAL_API !== '1')
    expect(readFileSync(storedOriginal)).toEqual(sourceBytes);
  const report = await (await request.get(`/api/cases/${id}/report`)).json();
  await expect(page.locator('.selected-file')).toContainText('high_rtt.pcap');
  await page.getByText('Technical report details', { exact: true }).click();
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  const reportDetails = await page.locator('.report-technical').boundingBox();
  const fixedComposer = await page.locator('.composer-wrap').boundingBox();
  expect(reportDetails).not.toBeNull();
  expect(fixedComposer).not.toBeNull();
  expect(reportDetails!.y + reportDetails!.height).toBeLessThanOrEqual(fixedComposer!.y - 12);
  await expect(page.getByLabel('Question about this report')).toBeDisabled();
  await expect(page.getByText(/Follow-up is unavailable in rules-only mode/)).toBeVisible();
  await page.getByText('Technical evidence', { exact: true }).first().click();
  for (const name of ['Open Full Capture in Wireshark', 'Open Evidence Capture in Wireshark']) {
    await expect(page.getByRole('button', { name, exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name, exact: true })).toBeDisabled();
  }
  const finding = report.findings.find(
    (item: { wireshark: { applicable: boolean } }) => item.wireshark.applicable,
  );
  await expect(page.locator('.validation-actions')).toContainText(finding.wireshark.display_filter);
  await axe(page);
  await noOverflow(page);
  await page.screenshot({ path: resolve(visuals, 'task6-desktop-analysis.png'), fullPage: true });
  await page.getByRole('button', { name: 'Show Packet Evidence', exact: true }).click();
  const drawer = page.getByRole('dialog', { name: 'Technical evidence' });
  const evidenceId = await drawer.getByLabel('Evidence record', { exact: true }).inputValue();
  const evidence = await (await request.get(`/api/cases/${id}/evidence/${evidenceId}`)).json();
  await expect(drawer.getByRole('heading', { name: 'What this shows' })).toBeVisible();
  await expect(drawer.getByRole('heading', { name: 'Measurements' })).toBeVisible();
  await expect(drawer.getByText('Packets', { exact: true })).toBeVisible();
  const raw = drawer.locator('.evidence-raw pre');
  await expect(raw).toBeHidden();
  await drawer.getByText('Raw record').click();
  await expect(raw).toBeVisible();
  await expect(raw).toContainText(evidenceId);
  for (const text of [evidence.source.capability, evidence.source.tool, evidence.source.version]) {
    await expect(raw).toContainText(text);
  }
  expect(JSON.parse(await raw.innerText())).toEqual(evidence);
  if (evidence.display_filter) await expect(drawer).toContainText(evidence.display_filter);
  for (const limitation of evidence.limitations)
    await expect(drawer).toContainText(humanLimitation(limitation));
  await axe(page);
  await page.keyboard.press('Escape');
  await page
    .getByRole('button', { name: 'Create evidence capture without opening Wireshark' })
    .click();
  await expect(
    page.getByRole('status').filter({ hasText: 'Focused evidence capture created locally' }),
  ).toBeVisible();
  const after = await (await request.get(`/api/cases/${id}`)).json();
  expect(after.capture_sha).toBe(before.capture_sha);
  expect(after.original_id).toBe(before.original_id);
  expect(readFileSync(resolve(captures, 'high_rtt.pcap'))).toEqual(sourceBytes);
  if (process.env.WIRECLAW_E2E_EXTERNAL_API !== '1')
    expect(readFileSync(storedOriginal)).toEqual(sourceBytes);
  expect(after.artifacts.find((item: { id: string }) => item.id === after.original_id)).toEqual(
    before.artifacts.find((item: { id: string }) => item.id === before.original_id),
  );
  await remove(page);
});

test('history_popover_and_evidence_drawer_are_keyboard_dismissible_and_restore_focus', async ({
  page,
  request,
}) => {
  const created = await request.post('/api/cases', {
    data: { symptom: 'application is slow' },
  });
  expect(created.ok()).toBe(true);
  const { id: caseId } = await created.json();
  historyCaseId = caseId;
  const ingested = await request.post(`/api/cases/${caseId}/capture`, {
    headers: { 'content-type': 'application/octet-stream' },
    data: readFileSync(resolve(captures, 'high_rtt.pcap')),
  });
  expect(ingested.ok()).toBe(true);
  const investigated = await request.post(`/api/cases/${caseId}/investigate`);
  expect(investigated.ok()).toBe(true);
  await page.goto(`/#case=${caseId}`);
  const displayName = `Capture ${caseId.slice(0, 8)}`;
  await expect(
    page.getByRole('heading', { name: "Here's what I found", exact: true }),
  ).toBeVisible();
  const history = page.getByRole('button', { name: 'Recent captures', exact: true });
  await history.focus();
  await page.keyboard.press('Enter');
  const popover = page.getByRole('dialog', { name: 'Recent captures', exact: true });
  await expect(popover).toBeVisible();
  await expect(
    popover.getByRole('button', { name: `Open ${displayName}`, exact: true }),
  ).toBeVisible();
  await axe(page);
  await page.screenshot({ path: resolve(visuals, 'task6-history-popover.png'), fullPage: true });
  await page.keyboard.press('Escape');
  await expect(popover).not.toBeVisible();
  await expect(history).toBeFocused();
  await page.getByText('Technical evidence', { exact: true }).first().click();
  const evidence = page.getByRole('button', { name: 'Show Packet Evidence', exact: true });
  await evidence.focus();
  await page.keyboard.press('Enter');
  const drawer = page.getByRole('dialog', { name: 'Technical evidence' });
  await expect(drawer.getByRole('heading', { name: 'What this shows' })).toBeVisible();
  for (let i = 0; i < 5; i++) {
    await page.keyboard.press('Tab');
    expect(await drawer.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  }
  await page.keyboard.press('Escape');
  await expect(drawer).not.toBeVisible();
  await expect(evidence).toBeFocused();
  await remove(page);
});

test('conversation_report_and_actions_have_no_overflow_at_390px', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await analyze(page, 'high_rtt');
  await expect(
    page.getByRole('heading', { name: "Here's what I found", exact: true }),
  ).toBeVisible();
  await expect(page.locator('.selected-file')).toContainText('high_rtt.pcap');
  await noOverflow(page);
  await page.getByText('Technical evidence', { exact: true }).first().click();
  for (const name of ['Open Full Capture in Wireshark', 'Open Evidence Capture in Wireshark']) {
    const bounds = await page.getByRole('button', { name, exact: true }).boundingBox();
    expect(bounds).not.toBeNull();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(390);
  }
  await page.getByLabel('Question about this report').scrollIntoViewIfNeeded();
  const composer = await page.locator('.composer').boundingBox();
  expect(composer!.x).toBeGreaterThanOrEqual(0);
  expect(composer!.x + composer!.width).toBeLessThanOrEqual(390);
  expect(composer!.y + composer!.height).toBeLessThanOrEqual(844);
  await axe(page);
  await page.screenshot({ path: resolve(visuals, 'task6-mobile-390.png'), fullPage: true });
  await page.getByRole('button', { name: 'Show Packet Evidence', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'What this shows' })).toBeVisible();
  await noOverflow(page);
  await axe(page);
  await page.keyboard.press('Escape');
  await remove(page);
});

test('technical evidence presents supported facts and sparse records at desktop and mobile widths', async ({
  page,
}) => {
  const fixture = JSON.parse(readFileSync(resolve('tests/fixtures/supported.json'), 'utf8'));
  const categories = ['analyze_tcp_establishment', 'analyze_tcp_health', 'assess_capture_quality'];
  const records = categories.map((category) =>
    fixture.evidence.find((item: { category: string }) => item.category === category),
  );
  const sparse = {
    ...records[2],
    id: 'ev_sparse',
    category: 'future_signal',
    scope: {},
    frame_refs: [],
    display_filter: null,
    summary: 'Sparse observation',
    value: {},
  };
  records.push(sparse);
  fixture.report.findings[0].evidence_ids = records.map((item: { id: string }) => item.id);
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const prefix = `/api/cases/${fixture.case.id}`;
    let body: unknown;
    if (path === '/api/config/capabilities')
      body = {
        provider_mode: 'none',
        limits: { max_capture_bytes: 64 * 1024 * 1024 },
        ai: {
          effective_provider_mode: 'none',
          embedded_availability: 'not_applicable',
          model: null,
          failure_code: null,
        },
      };
    else if (path === prefix) body = fixture.case;
    else if (path === `${prefix}/report`) body = fixture.report;
    else if (path.startsWith(`${prefix}/evidence/`))
      body = records.find(
        (item: { id: string }) => item.id === decodeURIComponent(path.split('/').at(-1)!),
      );
    await route.fulfill({
      status: body ? 200 : 404,
      contentType: 'application/json',
      body: JSON.stringify(body ?? { error: { code: 'not_found' } }),
    });
  });
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto(`/#case=${fixture.case.id}`);
  await expect(page.getByRole('heading', { name: "Here's what I found" })).toBeVisible();
  await page.getByText('Technical evidence', { exact: true }).first().click();
  await page.getByRole('button', { name: 'Show Packet Evidence' }).click();
  const drawer = page.getByRole('dialog', { name: 'Technical evidence' });
  await expect(drawer.getByRole('heading', { name: 'TCP connection setup' })).toBeVisible();
  await expect(drawer.getByText('192.0.2.1:50000')).toBeVisible();
  await expect(drawer.getByText('192.0.2.2:443')).toBeVisible();
  await expect(drawer.getByText('1–5')).toBeVisible();
  await expect(drawer.getByText('tcp.stream == 0', { exact: true })).toBeVisible();
  await drawer.getByRole('button', { name: 'Copy Wireshark Display Filter' }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('tcp.stream == 0');
  const raw = drawer.locator('.evidence-raw pre');
  await expect(raw).toBeHidden();
  await drawer.getByText('Raw record').click();
  await expect(raw).toBeVisible();
  expect(JSON.parse(await raw.innerText())).toEqual(records[0]);
  await drawer.getByText('Raw record').click();
  await drawer.evaluate((element) => {
    element.scrollTop = 0;
  });
  await page.screenshot({ path: resolve(visuals, 'technical-evidence-desktop.png') });
  await drawer.getByLabel('Evidence record').selectOption(records[1].id);
  await expect(drawer.getByRole('heading', { name: 'TCP connection health' })).toBeVisible();
  await expect(drawer.getByText('Retransmission indicators')).toBeVisible();
  await expect(drawer.getByText('Duplicate ACK indicators')).toBeVisible();
  await expect(drawer.getByText('Client', { exact: true })).toHaveCount(0);
  await expect(drawer.getByText('Source', { exact: true })).toBeVisible();
  await page.screenshot({ path: resolve(visuals, 'technical-evidence-health.png') });
  await drawer.getByLabel('Evidence record').selectOption(records[2].id);
  await expect(drawer.getByRole('heading', { name: 'Capture quality' })).toBeVisible();
  await expect(drawer.getByText('Capture-wide')).toBeVisible();
  await expect(drawer.getByText('Client', { exact: true })).toHaveCount(0);
  await page.screenshot({ path: resolve(visuals, 'technical-evidence-quality.png') });
  await drawer.getByLabel('Evidence record').selectOption(sparse.id);
  await expect(drawer.getByRole('heading', { name: 'Future signal' })).toBeVisible();
  await expect(drawer.getByText('No packet references recorded')).toBeVisible();
  await expect(drawer.getByText('Client', { exact: true })).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow(page);
  const bounds = await drawer.boundingBox();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(390);
  expect(bounds!.width).toBeGreaterThanOrEqual(388);
  await axe(page);
  await page.screenshot({ path: resolve(visuals, 'technical-evidence-mobile.png') });
});

for (const width of [1440, 390]) {
  test(`followup browser fixture preserves report and opens real evidence at ${width}px`, async ({
    page,
    request,
  }) => {
    // Provider transport is a browser fixture; case/report/evidence stay on the real local API.
    await page.setViewportSize({ width, height: 900 });
    const id = await analyze(page, 'high_rtt');
    await expect(
      page.getByRole('heading', { name: "Here's what I found", exact: true }),
    ).toBeVisible();
    const report = await (await request.get(`/api/cases/${id}/report`)).json();
    if (width === 390) {
      await page.getByText('Technical report details', { exact: true }).click();
      await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
      const reportDetails = await page.locator('.report-technical').boundingBox();
      const fixedComposer = await page.locator('.composer-wrap').boundingBox();
      expect(reportDetails).not.toBeNull();
      expect(fixedComposer).not.toBeNull();
      expect(reportDetails!.y + reportDetails!.height).toBeLessThanOrEqual(fixedComposer!.y - 12);
      await page.getByText('Technical report details', { exact: true }).click();
    }
    const evidenceId = report.findings[0].evidence_ids[0];
    const status = {
      effective_provider_mode: 'openai_compatible_local',
      embedded_availability: 'not_applicable',
      model: null,
      failure_code: null,
    };
    await page.route(`**/api/cases/${id}`, async (route) => {
      if (route.request().method() !== 'GET') {
        await route.continue();
        return;
      }
      const response = await route.fetch();
      const record = await response.json();
      await route.fulfill({
        response,
        json: { ...record, provider_mode: 'openai_compatible_local', ai_status: status },
      });
    });
    const questions: unknown[] = [];
    let releaseFirstFollowup!: () => void;
    const firstFollowupWaiting = new Promise<void>((resolve) => {
      releaseFirstFollowup = resolve;
    });
    await page.route(`**/api/cases/${id}/followups`, async (route) => {
      questions.push(route.request().postDataJSON());
      if (questions.length === 1) await firstFollowupWaiting;
      await route.fulfill({
        json: {
          answer:
            'The capture does not identify the exact device. Validate with a capture at the other endpoint.',
          evidence_ids: [evidenceId],
        },
      });
    });
    await page.reload();
    await expect(page.getByLabel('Question about this report')).toBeEnabled();
    for (const question of ['Which device?', 'What would validate this?']) {
      await page.getByLabel('Question about this report').fill(question);
      await page.getByRole('button', { name: 'Send', exact: true }).focus();
      await page.keyboard.press('Enter');
      await expect(page.getByText(question, { exact: true })).toBeVisible();
      if (questions.length === 1) {
        const thinking = page.getByTestId('followup-wave');
        await expect(thinking).toContainText('Thinking about your question…');
        await expect(thinking).toHaveAttribute('data-motion', 'reasoning');
        if (width === 1440)
          await page.screenshot({
            path: resolve(visuals, 'followup-thinking-desktop.png'),
            fullPage: true,
          });
        releaseFirstFollowup();
        await expect(thinking).not.toBeVisible();
      }
      await expect(page.getByRole('status').filter({ hasText: 'Explanation ready.' })).toHaveText(
        'Explanation ready.',
      );
      const analysis = page.getByRole('region', { name: 'Analysis results' });
      const questionMessage = page.locator('.followups .user-question').last();
      const answerMessage = page
        .getByRole('article', { name: 'Explanation about this report' })
        .last();
      expect(
        await analysis.evaluate(
          (element) =>
            !!(
              element.compareDocumentPosition(document.querySelector('.followups')!) &
              Node.DOCUMENT_POSITION_FOLLOWING
            ),
        ),
      ).toBe(true);
      expect(
        await questionMessage.evaluate(
          (element) =>
            !!(
              element.compareDocumentPosition(
                document.querySelector('.followups .turn:last-child article.reply')!,
              ) & Node.DOCUMENT_POSITION_FOLLOWING
            ),
        ),
      ).toBe(true);
      await expect(answerMessage).toBeVisible();
    }
    expect(questions).toEqual([
      { question: 'Which device?' },
      { question: 'What would validate this?' },
    ]);
    await expect(page.getByRole('article', { name: 'Explanation about this report' })).toHaveCount(
      2,
    );
    await axe(page);
    await noOverflow(page);
    await page.screenshot({
      path: resolve(
        visuals,
        width === 1440 ? 'task6-followup-browser-fixture.png' : 'task6-followup-mobile-fixture.png',
      ),
      fullPage: true,
    });
    await page
      .getByRole('article', { name: 'Explanation about this report' })
      .last()
      .getByRole('button', { name: 'View supporting evidence (1)', exact: true })
      .click();
    await expect(
      page
        .getByRole('dialog', { name: 'Technical evidence' })
        .getByRole('heading', { name: 'What this shows' }),
    ).toBeVisible();
    await page.keyboard.press('Escape');
    expect(await (await request.get(`/api/cases/${id}/report`)).json()).toEqual(report);
    await remove(page);
  });
}
