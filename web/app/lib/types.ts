// Copyright (c) 2026 Vassel Goleyu. MIT License.
// Hand-written types of the /api/v1 contract (src/vexledger/api/schemas.py). Kept in step by
// tests/unit/api-client.test.ts, which exercises every shape the UI relies on.
export type Role = 'admin' | 'analyst' | 'viewer'
export type Status = 'not_affected' | 'affected' | 'fixed' | 'under_investigation'
export type Justification =
  | 'component_not_present'
  | 'vulnerable_code_not_present'
  | 'vulnerable_code_not_in_execute_path'
  | 'vulnerable_code_cannot_be_controlled_by_adversary'
  | 'inline_mitigations_already_exist'
export type FindingState =
  'UNTRIAGED' | 'NEEDS_REVIEW' | 'EXPIRED' | 'INHERITED' | 'TRIAGED' | 'WITHDRAWN'
export type MatchStatus = 'MATCH_PENDING' | 'MATCHED' | 'MATCH_FAILED'

export const STATUSES: readonly Status[] = [
  'not_affected',
  'affected',
  'fixed',
  'under_investigation',
]
export const JUSTIFICATIONS: readonly Justification[] = [
  'component_not_present',
  'vulnerable_code_not_present',
  'vulnerable_code_not_in_execute_path',
  'vulnerable_code_cannot_be_controlled_by_adversary',
  'inline_mitigations_already_exist',
]
export const FINDING_STATES: readonly FindingState[] = [
  'UNTRIAGED',
  'NEEDS_REVIEW',
  'EXPIRED',
  'INHERITED',
  'TRIAGED',
  'WITHDRAWN',
]

export interface User {
  id: string
  username: string
  role: Role
  is_active: boolean
  created_at: string
}
export interface Session {
  user: User
  csrf_token: string | null
  demo_data: boolean
}
export interface ApiToken {
  id: string
  user_id: string
  name: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
}
export interface ApiTokenCreated extends ApiToken {
  token: string
}

export interface Product {
  id: string
  slug: string
  name: string
  purl: string
  vex_author: string
  inherit_enabled: boolean
  validity_not_affected_days: number | null
  validity_under_investigation_days: number | null
  validity_affected_days: number | null
  validity_fixed_days: number | null
  created_at: string
}
export type ProductCreate = Pick<Product, 'slug' | 'name' | 'purl' | 'vex_author'> &
  Partial<
    Pick<
      Product,
      | 'inherit_enabled'
      | 'validity_not_affected_days'
      | 'validity_under_investigation_days'
      | 'validity_affected_days'
      | 'validity_fixed_days'
    >
  >
export type ProductPatch = Partial<Omit<Product, 'id' | 'slug' | 'created_at'>>

export interface Release {
  id: string
  version: string
  ordering: number
  status: MatchStatus
  match_error: string | null
  has_sbom: boolean
  created_at: string
}
export interface ImportWarning {
  code: string
  message: string
  ref?: string | null
  [key: string]: unknown
}
export interface Sbom {
  sha256: string
  spec_version: string | null
  size_bytes: number
  component_count: number
  edge_count: number
  root_present: boolean
  no_purl_count: number
  unsupported_ecosystem_count: number
  warning_summary: Record<string, number>
  warnings: ImportWarning[]
}
export interface ReleaseDetail extends Release {
  match_notes: string[]
  sbom: Sbom | null
  finding_total: number
  open_count: number
  investigating_count: number
  findings_by_state: Record<string, number>
}
export interface Upload {
  release: Release
  sbom: Sbom
  created: boolean
  match_status: MatchStatus
  queued: boolean
}
export interface MatchStatusInfo {
  status: MatchStatus
  error: string | null
  notes: string[]
  finding_total: number
}
export interface Gate {
  release_version: string
  match_status: MatchStatus
  complete: boolean
  total: number
  open_count: number
  investigating_count: number
  open: { vulnerability_id: string; component_ref: string }[]
}
export interface ExportItem {
  version: number
  content_sha256: string
  created_by: string | null
  created_at: string
}
export interface ExportResult {
  text: string
  version: number
  sha256: string
  isNew: boolean
}

export interface FindingItem {
  id: string
  vulnerability_id: string
  aliases: string[]
  component_ref: string
  component_purl: string
  ecosystem: string | null
  severity_label: string | null
  state: FindingState
  investigating: boolean
  assignee_id: string | null
  statement_status: Status | null
  statement_valid_until: string | null
  head_id: string | null
}
export interface FindingPage {
  match_status: MatchStatus
  items: FindingItem[]
  total: number
  page: number
  page_size: number
}
export interface Evidence {
  id: string
  kind: 'LINK' | 'NOTE' | 'FILE'
  value: string | null
  file_id: string | null
  file_name: string | null
  size_bytes: number | null
  sha256: string | null
  detected_type: string | null
  download_url: string | null
}
export interface Statement {
  id: string
  status: Status
  justification: Justification | null
  impact_statement: string | null
  action_statement: string | null
  status_notes: string | null
  created_by: string
  created_at: string
  valid_until: string | null
  supersedes_id: string | null
  inherited_from_id: string | null
  evidence: Evidence[]
  without_evidence: boolean
}
export interface OsvRecord {
  id: string
  aliases: string[]
  summary: string | null
  details: string | null
  severity: { type?: string; score?: string }[]
  references: { type?: string; url?: string }[]
  published: string | null
  modified: string
  withdrawn: string | null
}
export interface Component {
  id: string
  name: string
  version: string | null
  purl: string | null
  component_ref: string | null
  ecosystem: string | null
  component_hash: string | null
}
export interface DependencyPath {
  reachable: boolean
  direct: boolean | null
  path: { component_id: string; name: string; version: string | null }[]
}
export interface FindingDetail extends FindingItem {
  product_slug: string
  release_version: string
  release_id: string
  match_discrepancy: Record<string, unknown> | null
  component: Component
  dependency_path: DependencyPath
  osv: OsvRecord[]
  statements: Statement[]
  review_context: { release_version: string; statement: Statement } | null
}

export interface EvidenceDraft {
  kind: 'LINK' | 'NOTE'
  value: string
}
export interface Draft {
  status: Status
  justification?: Justification | null
  impact_statement?: string | null
  action_statement?: string | null
  status_notes?: string | null
  evidence?: EvidenceDraft[]
  valid_until?: string | null
  reason?: string | null
}

export interface FindingRef {
  canonical_vuln_id: string
  component_key: string
  state: FindingState
}
export interface ReleaseDiff {
  components_added: string[]
  components_removed: string[]
  version_changed: { component_key: string; from_versions: string[]; to_versions: string[] }[]
  hash_changed: {
    component_key: string
    versions: string[]
    from_hashes: (string | null)[]
    to_hashes: (string | null)[]
  }[]
  findings_new: FindingRef[]
  findings_resolved: FindingRef[]
  findings_persisting: {
    canonical_vuln_id: string
    component_key: string
    state_a: FindingState
    state_b: FindingState
  }[]
  statements: { inherited: number; needs_review: number }
}
export interface Diff {
  from_version: string
  to_version: string
  diff: ReleaseDiff
}

export interface AuditEntry {
  id: number
  at: string
  actor_id: string | null
  action: string
  entity_type: string
  entity_id: string
  before: Record<string, unknown> | null
  after: Record<string, unknown> | null
  reason: string | null
}
export interface AuditPage {
  items: AuditEntry[]
  next_before_id: number | null
}
