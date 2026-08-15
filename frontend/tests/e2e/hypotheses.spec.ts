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