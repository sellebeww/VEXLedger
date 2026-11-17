// Copyright (c) 2026 Vassel Goleyu. MIT License.
import withNuxt from './.nuxt/eslint.config.mjs'
import prettier from 'eslint-config-prettier'

export default withNuxt(
  prettier,
  {
    files: ['app/**/*.{vue,ts}'],
    rules: {
      // User text is plain text, never HTML: both the directive and the DOM sinks.
      'vue/no-v-html': 'error',
      'no-restricted-properties': [
        'error',
        { property: 'innerHTML', message: 'Never render data as HTML.' },
        { property: 'outerHTML', message: 'Never render data as HTML.' },
        { property: 'insertAdjacentHTML', message: 'Never render data as HTML.' },
      ],
      'no-restricted-syntax': [
        'error',
        { selector: "Identifier[name='v-html']", message: 'Never render data as HTML.' },
        { selector: "JSXAttribute[name.name='innerHTML']", message: 'Never render data as HTML.' },
        { selector: "Property[key.name='innerHTML']", message: 'Never render data as HTML.' },
        { selector: "Property[key.name='domProps']", message: 'Never render data as HTML.' },
      ],
    },
  },
  {
    files: ['app/**/*.vue'],
    ignores: ['app/i18n/**'],
    rules: {
      // No hardcoded UI strings in templates: text comes from the catalog (app/i18n/id.ts).
      'vue/no-bare-strings-in-template': [
        'error',
        { allowlist: ['(', ')', ',', '.', ':', '-', '/', '|', '%', '→', '•'] },
      ],
    },
  },
)
