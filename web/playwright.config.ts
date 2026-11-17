// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { defineConfig } from '@playwright/test'

// Full stack: Postgres/Redis from `make dev-up`, then tools/e2e_stack.py (API, worker, fake OSV
// with SYNTHETIC records, seeded demo data) and the Nuxt dev server proxying /api to it.
export default defineConfig({
  testDir: 'e2e',
  workers: 1,
  use: { baseURL: 'http://localhost:3000' },
  webServer: [
    {
      command: 'cd .. && uv run python tools/e2e_stack.py',
      url: 'http://127.0.0.1:8000/healthz',
      reuseExistingServer: true,
      timeout: 120_000,
    },
    { command: 'npm run dev', url: 'http://localhost:3000', reuseExistingServer: true },
  ],
})
