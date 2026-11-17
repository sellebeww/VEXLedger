// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { ESLint } from 'eslint'
import { expect, test } from 'vitest'
import { atLeast, requiredRole } from '../../app/lib/roles'
import { safeDownloadPath, safeHttpUrl } from '../../app/lib/safe-url'

test('only absolute http(s) URLs with a host become links', () => {
  expect(safeHttpUrl('https://example.com/x?y=1')).toBe('https://example.com/x?y=1')
  expect(safeHttpUrl('http://example.com')).toBe('http://example.com')
  for (const bad of [
    'javascript:alert(1)',
    'data:text/html,x',
    'file:///etc/passwd',
    'ftp://x.test',
    '//evil.test',
    'https://',
    'https://a b',
    ' https://x.test',
    'HTTPS://x.test',
    '',
    null,
    undefined,
  ]) {
    expect(safeHttpUrl(bad as string | null)).toBeNull()
  }
})

test('evidence downloads are only same-origin API paths', () => {
  const ok = '/api/v1/evidence-files/123e4567-e89b-12d3-a456-426614174000/download'
  expect(safeDownloadPath(ok)).toBe(ok)
  expect(safeDownloadPath('https://evil.test/api/v1/evidence-files/x/download')).toBeNull()
  expect(safeDownloadPath('/api/v1/evidence-files/../x')).toBeNull()
})

test('route guard: admin pages need admin, login is public, the rest needs a session', () => {
  expect(requiredRole('/login')).toBe('public')
  expect(requiredRole('/admin')).toBe('admin')
  expect(requiredRole('/products/x/releases/1')).toBe('viewer')
  expect(atLeast('viewer', 'analyst')).toBe(false)
  expect(atLeast('analyst', 'analyst')).toBe(true)
  expect(atLeast('admin', 'analyst')).toBe(true)
  expect(atLeast(null, 'viewer')).toBe(false)
})

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n)
    return statSync(p).isDirectory() ? files(p) : [p]
  })
}

test('no em dash anywhere in the UI sources', () => {
  for (const f of files('app'))
    expect(readFileSync(f, 'utf8'), f).not.toContain(String.fromCharCode(0x2014))
})

test('the lint config rejects v-html, innerHTML and hardcoded template text', async () => {
  const eslint = new ESLint({ cwd: process.cwd() })
  const lint = async (code: string): Promise<string[]> => {
    const [r] = await eslint.lintText(code, {
      filePath: join(process.cwd(), 'app/components/Probe.vue'),
    })
    return r!.messages.map((m) => m.ruleId ?? 'parse')
  }
  expect(
    await lint(
      '<script setup lang="ts">const h = ref("")</script>\n<template><div><p v-html="h"></p></div></template>\n',
    ),
  ).toContain('vue/no-v-html')
  expect(
    await lint(
      '<script setup lang="ts">const el = document.body\nel.innerHTML = "x"</script>\n<template><div></div></template>\n',
    ),
  ).toContain('no-restricted-properties')
  expect(
    await lint(
      '<script setup lang="ts"></script>\n<template><div><p>Teks mentah</p></div></template>\n',
    ),
  ).toContain('vue/no-bare-strings-in-template')
}, 60_000)
