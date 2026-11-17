// Copyright (c) 2026 Vassel Goleyu. MIT License.
// hostile text from analysts and SBOMs must render as inert text.
import { expect, test } from '@playwright/test'

const PASSWORD = 'e2e-dummy-passphrase-1'
const IMG = '<img src=x onerror=window.__xss=1>'

test('analyst text, evidence and SBOM component names never execute or become markup', async ({
  page,
}) => {
  const login = await page.request.post('/api/v1/auth/login', {
    data: { username: 'analyst', password: PASSWORD },
  })
  expect(login.ok()).toBeTruthy()
  const csrf = (await login.json()).csrf_token as string
  const headers = { 'X-CSRF-Token': csrf }

  // a release whose components carry hostile names and a hostile (invalid) purl
  const version = `9.${Date.now() % 100000}.0`
  await page.request.post('/api/v1/products/demo-app/releases', { data: { version }, headers })
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: { component: { type: 'application', name: 'app', 'bom-ref': 'app' } },
    components: [
      { type: 'library', name: IMG, version: '1', 'bom-ref': 'a', purl: `pkg:pypi/${IMG}@1` },
      { type: 'library', name: '"><script>window.__xss=9</script>', version: '1', 'bom-ref': 'b' },
    ],
    dependencies: [{ ref: 'app', dependsOn: ['a', 'b'] }],
  }
  const up = await page.request.post(`/api/v1/products/demo-app/releases/${version}/sbom`, {
    headers,
    multipart: {
      file: {
        name: 's.json',
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify(sbom)),
      },
    },
  })
  expect(up.status(), await up.text()).toBe(202)

  // hostile analyst text and evidence on a real finding of release 1.0.0
  const list = await (
    await page.request.get('/api/v1/products/demo-app/releases/1.0.0/findings?page_size=1')
  ).json()
  const f = list.items[0]
  const tri = await page.request.post(`/api/v1/findings/${f.id}/triage`, {
    headers,
    data: {
      status: 'not_affected',
      justification: 'vulnerable_code_not_present',
      impact_statement: `${IMG} this text is long enough to be accepted`,
      expected_head_id: f.head_id ?? null,
      evidence: [
        { kind: 'NOTE', value: '<script>window.__xss=2</script>' },
        {
          kind: 'LINK',
          value:
            'https://example.invalid/?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dwindow.__xss%3D3%3E',
        },
      ],
    },
  })
  expect(tri.status(), await tri.text()).toBe(201)

  await page.goto(`/findings/${f.id}`)
  await expect(page.getByText(IMG).first()).toBeVisible()
  await expect(page.getByText('<script>window.__xss=2</script>')).toBeVisible()

  for (const url of [`/findings/${f.id}`, `/products/demo-app/releases/${version}`]) {
    await page.goto(url)
    expect(
      await page.evaluate(() => (window as unknown as { __xss?: unknown }).__xss),
    ).toBeUndefined()
    await expect(page.locator('img[src="x"]')).toHaveCount(0)
    await expect(page.locator('main script')).toHaveCount(0)
  }
})
