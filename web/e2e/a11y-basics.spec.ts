// Copyright (c) 2026 Vassel Goleyu. MIT License.
// basic accessibility invariants on every main page. This is NOT a full
// audit (no axe run, no screen reader pass); it only catches the common regressions.
import { expect, test } from '@playwright/test'

const PASSWORD = 'e2e-dummy-passphrase-1'

test('every main page has a language, one main landmark, an h1 and named controls', async ({
  page,
}) => {
  await page.goto('/login')
  await expect(page.locator('html')).toHaveAttribute('lang', 'id')
  await page.request.post('/api/v1/auth/login', { data: { username: 'admin', password: PASSWORD } })
  const list = await (
    await page.request.get('/api/v1/products/demo-app/releases/1.0.0/findings?page_size=1')
  ).json()
  const pages = [
    '/products',
    '/products/demo-app',
    '/products/demo-app/releases/1.0.0',
    '/products/demo-app/releases/1.0.0/export',
    '/products/demo-app/diff?from=1.0.0&to=1.1.0',
    '/products/demo-app/settings',
    `/findings/${list.items[0].id}`,
    '/admin',
  ]
  for (const url of pages) {
    await page.goto(url)
    await expect(page.getByRole('heading', { level: 1 })).toHaveCount(1)
    await expect(page.locator('main')).toHaveCount(1)
    await expect(page.locator('html')).toHaveAttribute('lang', 'id')
    const unnamed = await page.evaluate(() => {
      const bad: string[] = []
      const name = (el: Element): string =>
        (el.getAttribute('aria-label') ?? '') +
        (el.getAttribute('aria-labelledby') ? 'x' : '') +
        ((el as HTMLInputElement).labels?.length ? 'x' : '') +
        (el.getAttribute('title') ?? '')
      for (const el of document.querySelectorAll('input:not([type=hidden]), select, textarea')) {
        if (!name(el)) bad.push(el.outerHTML.slice(0, 80))
      }
      for (const el of document.querySelectorAll('button, a[href]')) {
        if (!(el.textContent ?? '').trim() && !name(el)) bad.push(el.outerHTML.slice(0, 80))
      }
      for (const el of document.querySelectorAll('table')) {
        if (!el.querySelector('caption') && !name(el)) bad.push('table without name')
      }
      for (const el of document.querySelectorAll('img')) {
        if (!el.hasAttribute('alt')) bad.push('img without alt')
      }
      return bad
    })
    expect(unnamed, `${url}: ${unnamed.join(' | ')}`).toEqual([])
  }
})
