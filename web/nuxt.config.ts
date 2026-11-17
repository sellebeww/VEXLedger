// Copyright (c) 2026 Vassel Goleyu. MIT License.
// The UI is a client-rendered SPA: auth lives in an httpOnly cookie that only the browser holds,
// so server rendering would add nothing. /api is proxied to the backend so cookies stay same-origin.
const apiTarget = process.env.VEXLEDGER_API_URL ?? 'http://localhost:8000'

export default defineNuxtConfig({
  compatibilityDate: '2026-11-01',
  ssr: false,
  modules: ['@pinia/nuxt', '@nuxt/eslint'],
  devtools: { enabled: false },
  typescript: { strict: true },
  css: ['~/assets/app.css'],
  app: {
    head: {
      htmlAttrs: { lang: 'id' },
      title: 'VEXLedger',
      meta: [{ name: 'viewport', content: 'width=device-width, initial-scale=1' }],
    },
  },
  routeRules: { '/api/**': { proxy: `${apiTarget}/api/**` } },
})
