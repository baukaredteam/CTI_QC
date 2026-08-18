import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('hypotheses page lists persisted scan hypotheses', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto('/hypotheses');
  await expect(page.getByRole('heading', { name: 'Hypothesis Scanner' })).toBeVisible();
  await expect(page.getByText('Persisted hunt hypotheses')).toBeVisible();
  await expect(page.getByText('T1486', { exact: true })).toBeVisible();
  await expect(page.getByText('proposed', { exact: true })).toBeVisible();
  await expect(page.getByText(/TL-2026-1693/)).toBeVisible();
});

test('hypotheses Validate advances status via PATCH', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto('/hypotheses');
  const validate = page.getByRole('button', { name: 'Validate' });
  await expect(validate).toBeVisible();
  await validate.click();
  await expect(page.getByText('validated', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Validate' })).toHaveCount(0);
});

test('hypotheses filter by status', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto('/hypotheses');
  await page.getByLabel('Status').selectOption({ label: 'Validated' });
  await expect(page.getByText('No hypotheses match the filters.')).toBeVisible();
});

test('hypotheses render enrichment sections with safe display-only values', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto('/hypotheses');

  const enrichedRow = page.locator('div.p-4').filter({ hasText: 'TL-2026-1693' });
  await expect(enrichedRow.getByText('High-confidence bonus: +0.250', { exact: true })).toBeVisible();
  await expect(enrichedRow.getByText('Kasablanka · Sandworm', { exact: true })).toBeVisible();
  await expect(enrichedRow.getByText('Port Scan · C2 Beacon', { exact: true })).toBeVisible();
  await expect(enrichedRow.getByText('infra_ip: 203.0.113.7 · port: 443')).toBeVisible();
  await expect(enrichedRow.getByText('T1132 — Data Encoding · 0.700 [attack_flow]')).toBeVisible();
  await expect(enrichedRow.getByText('T1560 — Archive Collected Data [attack_flow]')).toBeVisible();

  const bonusNullRow = page.locator('div.p-4').filter({ hasText: 'TL-2026-1695' });
  await expect(bonusNullRow.getByText('High-confidence bonus:', { exact: false })).toHaveCount(0);
  await expect(bonusNullRow.getByText('Kasablanka', { exact: true })).toBeVisible();
  await expect(bonusNullRow.getByText('C2 Beacon', { exact: true })).toBeVisible();

  const legacyRow = page.locator('div.p-4').filter({ hasText: 'TL-2026-1697' });
  await expect(legacyRow.getByText('Related threats', { exact: true })).toHaveCount(0);
  await expect(legacyRow.getByText('Adversary playbooks', { exact: true })).toHaveCount(0);
  await expect(legacyRow.getByText('Infrastructure pivots', { exact: true })).toHaveCount(0);
  await expect(legacyRow.getByText('Predicted next techniques', { exact: true })).toHaveCount(0);

  await expect(page.getByText('High-confidence bonus:', { exact: false })).toHaveCount(1);
  await expect(page.getByText('Related threats', { exact: true })).toHaveCount(2);
  await expect(page.getByText('Adversary playbooks', { exact: true })).toHaveCount(2);
  await expect(page.getByText('Infrastructure pivots', { exact: true })).toHaveCount(1);
  await expect(page.getByText('Predicted next techniques', { exact: true })).toHaveCount(1);
  await expect(page.getByText('[object Object]', { exact: true })).toHaveCount(0);
  await expect(page.getByText('T1071', { exact: true })).toHaveCount(0);
  await expect(page.getByText('[attack_flow]', { exact: true })).toHaveCount(2);
});
