// Copyright (c) 2026 Vassel Goleyu. MIT License.
// the release diff page shows added, removed and version-changed components.
import { expect, test } from '@playwright/test'

const PASSWORD = 'e2e-dummy-passphrase-1'

function sbom(components: Array<[string, string]>): Buffer {
  const comps = components.map(([name, version]) => ({
    type: 'library',
    name,
    version,
    'bom-ref': `${name}@${version}`,
    purl: `pkg:pypi/${name}@${version}`,
  }))
  return Buffer.from(
    JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      version: 1,
      metadata: { component: { type: 'application', name: 'app', 'bom-ref': 'app' } },
      components: comps,
      dependencies: [{ ref: 'app', dependsOn: comps.map((c) => c['bom-ref']) }],
    }),
  )
}

test('diff page lists added, removed and version-changed components of two releases', async ({
  page,
}) => {
  const login = await page.request.post('/api/v1/auth/login', {
    data: { username: 'admin', password: PASSWORD },
  })
  const headers = { 'X-CSRF-Token': (await login.json()).csrf_token as string }
  const tag = Date.now() % 100000
  await page.request.post('/api/v1/products', {
    headers,
    data: {
      slug: `diff-${tag}`,
      name: 'Diff probe',
      purl: 'pkg:generic/diffprobe',
      vex_author: 'Ex',
    },
  })
  for (const [version, comps] of [
    [
      '1.0.0',
      [
        ['keepme', '1.0'],
        ['bumped', '1.0'],
        ['goneaway', '1.0'],
      ],
    ],
    [
      '2.0.0',
      [
        ['keepme', '1.0'],
        ['bumped', '2.0'],
        ['brandnew', '1.0'],
      ],
    ],
  ] as const) {
    await page.request.post(`/api/v1/products/diff-${tag}/releases`, { headers, data: { version } })
    const up = await page.request.post(`/api/v1/products/diff-${tag}/releases/${version}/sbom`, {
      headers,
      multipart: {
        file: {
          name: 's.json',
          mimeType: 'application/json',
          buffer: sbom(comps.map((c) => [c[0], c[1]] as [string, string])),
        },
      },
    })
    expect(up.status(), await up.text()).toBe(202)
  }
  await page.goto(`/products/diff-${tag}/diff?from=1.0.0&to=2.0.0`)
  await expect(page.getByRole('heading', { name: 'Diff rilis', level: 1 })).toBeVisible()
  await expect(page.getByText('brandnew').first()).toBeVisible() // added
  await expect(page.getByText('goneaway').first()).toBeVisible() // removed
  await expect(page.getByText('bumped').first()).toBeVisible() // version changed
  await expect(page.getByText('keepme')).toHaveCount(0) // unchanged components stay out
})
