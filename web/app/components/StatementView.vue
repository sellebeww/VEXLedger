<script setup lang="ts">
// Copyright (c) 2026 Vassel Goleyu. MIT License.
// One statement with its evidence. Everything analysts typed is rendered as plain text.
import { id } from '~/i18n/id'
import { formatDateTime } from '~/lib/format'
import { safeDownloadPath } from '~/lib/safe-url'
import type { Statement } from '~/lib/types'

defineProps<{ statement: Statement }>()
</script>

<template>
  <div class="stack">
    <div class="row">
      <strong>{{ id.status[statement.status] }}</strong>
      <span v-if="statement.justification" class="badge neutral">{{
        id.justification[statement.justification].label
      }}</span>
      <span v-if="statement.inherited_from_id" class="badge info">{{ id.finding.inherited }}</span>
      <span v-if="statement.without_evidence" class="badge warn">{{
        id.finding.withoutEvidence
      }}</span>
    </div>
    <p v-if="statement.impact_statement" class="plain-text">{{ statement.impact_statement }}</p>
    <p v-if="statement.action_statement" class="plain-text">{{ statement.action_statement }}</p>
    <p v-if="statement.status_notes" class="plain-text">{{ statement.status_notes }}</p>
    <p class="muted">
      {{ id.finding.by }} {{ statement.created_by }}, {{ formatDateTime(statement.created_at) }}.
      {{ id.finding.validUntil }}{{ id.common.separator }}
      {{ statement.valid_until ? formatDateTime(statement.valid_until) : id.common.noExpiry }}
    </p>
    <div v-if="statement.evidence.length">
      <strong>{{ id.finding.evidence }}</strong>
      <ul>
        <li v-for="ev in statement.evidence" :key="ev.id">
          <SafeLink v-if="ev.kind === 'LINK'" :href="ev.value" />
          <span v-else-if="ev.kind === 'NOTE'" class="plain-text">{{ ev.value }}</span>
          <template v-else>
            <span class="plain-text">{{ ev.file_name }}</span>
            <span class="muted">
              ({{ ev.size_bytes }} {{ id.common.bytes }}, {{ ev.detected_type }})</span
            >
            <a
              v-if="safeDownloadPath(ev.download_url)"
              :href="safeDownloadPath(ev.download_url) ?? undefined"
              download
              >{{ id.triage.downloadEvidence }}</a
            >
          </template>
        </li>
      </ul>
    </div>
    <p v-else class="muted">{{ id.finding.noEvidence }}</p>
  </div>
</template>
