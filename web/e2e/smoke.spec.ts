// Copyright (c) 2026 Vassel Goleyu. MIT License.
// Runs against the real API, worker and database (tools/e2e_stack.py) with SYNTHETIC OSV records.
import { expect, type Page, test } from '@playwright/test'

const PASSWORD = 'e2e-dummy-passphrase-1'

async function login(page: Page, username: string, password = PASSWORD): Promise<void> {
  await page.goto('/login')
  await page.getByLabel('Nama pengguna').fill(username)
  await page.getByLabel('Kata sandi').fill(password)
  await page.getByRole('button', { name: 'Masuk' }).click()
}
async function loginOk(page: Page, username: string): Promise<void> {
  await login(page, username)
  await expect(page).toHaveURL(/\/products/)
}

test('login rejects a wrong password with a catalog message, then accepts the right one', async ({
  page,
}) => {
  await login(page, 'analyst', 'wrong-password-123')
  await expect(page.getByRole('alert')).toContainText('Nama pengguna atau kata sandi salah')
  await login(page, 'analyst')
  await expect(page.getByRole('heading', { name: 'Produk' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Demo App' })).toBeVisible()
})

test('anonymous visitors are sent to login and viewers cannot reach admin', async ({ page }) => {
  await page.goto('/products')
  await expect(page).toHaveURL(/\/login/)
  await loginOk(page, 'viewer')
  await page.goto('/admin')
  await expect(page).toHaveURL(/\/products/)
  await expect(page.getByRole('link', { name: 'Admin' })).toHaveCount(0)
})

test('findings list, triage with a failing then a passing submit, incomplete export', async ({
  page,
}) => {
  await loginOk(page, 'analyst')
  await page.getByRole('link', { name: 'Demo App' }).click()
  await page.getByRole('link', { name: '1.0.0' }).click()

  // findings table with state badges (text, not colour only) and the unmatchable components
  const table = page.getByRole('table', { name: 'Temuan' })
  await expect(table).toBeVisible()
  await expect(table.getByRole('link', { name: 'CVE-2099-0001' })).toBeVisible()
  await expect(table.getByText('Belum ditriase').first()).toBeVisible()
  await expect(
    page.getByText('Ekosistem tidak didukung (hanya PyPI, npm, Maven, Go)'),
  ).toBeVisible()
  await expect(page.getByText('Tanpa purl valid')).toBeVisible()

  // detail: the API drops the javascript: reference; the UI would show it as text, never a link
  await table.getByRole('link', { name: 'CVE-2099-0001' }).click()
  await expect(page.getByRole('heading', { name: 'CVE-2099-0001', level: 1 })).toBeVisible()
  await expect(page.getByText('javascript:alert(1)')).toHaveCount(0)
  await expect(page.locator('a[href^="javascript"]')).toHaveCount(0)
  await expect(
    page.locator('a[href^="https://example.invalid/advisory/"]').first(),
  ).toHaveAttribute('rel', 'noopener noreferrer')

  // triage: validation fails first (nothing sent), then succeeds
  await page.getByLabel('Tidak terdampak').check()
  await page.getByRole('button', { name: 'Simpan pernyataan' }).click()
  await expect(page.getByText('Status "tidak terdampak" wajib punya justifikasi.')).toBeVisible()
  await expect(page.getByText('Pernyataan dampak wajib diisi minimal 20 karakter.')).toBeVisible()
  await page.getByLabel('Kode rentan tidak dijalankan').check()
  await page
    .getByLabel('Pernyataan dampak (impact statement)')
    .fill('Fitur parser yang rentan tidak dipakai oleh aplikasi ini.')
  await expect(page.getByText('Tanpa bukti.')).toBeVisible()
  await page.getByRole('button', { name: 'Simpan pernyataan' }).click()
  await expect(page.getByText('Pernyataan disimpan.')).toBeVisible()
  await expect(page.getByText('Sudah ditriase').first()).toBeVisible()
  await expect(page.getByText('Tanpa bukti').first()).toBeVisible()

  // export: the gate is incomplete, so an explicit confirmation is required
  await page.goto('/products/demo-app/releases/1.0.0/export')
  await expect(page.getByText('Dokumen tidak ditandatangani')).toBeVisible()
  await expect(page.getByText('Tidak lengkap.')).toBeVisible()
  await page.getByRole('button', { name: 'Unduh walau tidak lengkap' }).click()
  const go = page.getByRole('button', { name: 'Ekspor tetap' })
  await expect(go).toBeDisabled()
  await page.getByLabel('Saya paham dokumen ini tidak lengkap').check()
  const download = page.waitForEvent('download')
  await go.click()
  expect((await download).suggestedFilename()).toMatch(/^vex-demo-app-1\.0\.0-v\d+\.json$/)
  await expect(page.getByText('Dokumen versi 1 dibuat dan diunduh.')).toBeVisible()
  await expect(page.getByRole('table', { name: 'Riwayat versi ekspor' })).toBeVisible()
})

test('bulk triage dialog opens for selected rows and validates before sending', async ({
  page,
}) => {
  await loginOk(page, 'analyst')
  await page.goto('/products/demo-app/releases/1.0.0')
  const table = page.getByRole('table', { name: 'Temuan' })
  await table.getByRole('checkbox').nth(1).check()
  await expect(page.getByText('1 temuan dipilih')).toBeVisible()
  await page.getByRole('button', { name: 'Triase massal' }).first().click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByText('Bila satu gagal, semuanya dibatalkan.')).toBeVisible()
  await dialog.getByLabel('Terdampak', { exact: true }).check()
  await dialog.getByRole('button', { name: 'Triase massal' }).click()
  await expect(
    dialog.getByText('Pernyataan tindakan wajib diisi untuk status "terdampak".'),
  ).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
})

test('admin sees users and gets a one-time token', async ({ page }) => {
  await loginOk(page, 'admin')
  await page.getByRole('link', { name: 'Admin' }).click()
  await expect(page.getByRole('cell', { name: 'analyst' }).first()).toBeVisible()
  await page.getByRole('tab', { name: 'Token API' }).click()
  await page.getByLabel('Nama token').fill('ci')
  await page.getByRole('button', { name: 'Buat token' }).click()
  await expect(page.getByText('Token tidak akan ditampilkan lagi.')).toBeVisible()
  await expect(page.getByText(/^vxl_/)).toBeVisible()
  await page.getByRole('tab', { name: 'Audit log' }).click()
  await expect(page.getByRole('cell', { name: /statement\.create/ }).first()).toBeVisible()
})
