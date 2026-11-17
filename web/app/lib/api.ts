// Copyright (c) 2026 Vassel Goleyu. MIT License.
import { type Client, uploadWithProgress } from './client'
import { ApiError } from './errors'
import { buildQuery, type FindingQuery, findingsParams } from './query'
import type {
  ApiToken,
  ApiTokenCreated,
  AuditPage,
  Diff,
  Draft,
  ExportItem,
  ExportResult,
  FindingDetail,
  FindingPage,
  Gate,
  MatchStatusInfo,
  Product,
  ProductCreate,
  ProductPatch,
  Release,
  ReleaseDetail,
  Role,
  Session,
  Statement,
  Upload,
  User,
} from './types'

export const API = '/api/v1'
const enc = encodeURIComponent
const rel = (slug: string, version: string): string =>
  `${API}/products/${enc(slug)}/releases/${enc(version)}`

export interface ApiContext {
  client: Client
  getCsrf: () => string | null
  onUnauthorized: () => void
}

export function createApi({ client, getCsrf, onUnauthorized }: ApiContext) {
  const j = client.json
  return {
    // auth
    login: (username: string, password: string) =>
      j<Session>('POST', `${API}/auth/login`, {
        json: { username, password },
        allowUnauthorized: true,
      }),
    logout: () => j<undefined>('POST', `${API}/auth/logout`),
    me: () => j<Session>('GET', `${API}/auth/me`, { allowUnauthorized: true }),
    myTokens: () => j<ApiToken[]>('GET', `${API}/auth/tokens`),
    createToken: (name: string) =>
      j<ApiTokenCreated>('POST', `${API}/auth/tokens`, { json: { name } }),

    // products
    products: () => j<Product[]>('GET', `${API}/products`),
    product: (slug: string) => j<Product>('GET', `${API}/products/${enc(slug)}`),
    createProduct: (body: ProductCreate) => j<Product>('POST', `${API}/products`, { json: body }),
    patchProduct: (slug: string, body: ProductPatch) =>
      j<Product>('PATCH', `${API}/products/${enc(slug)}`, { json: body }),

    // releases
    releases: (slug: string) => j<Release[]>('GET', `${API}/products/${enc(slug)}/releases`),
    createRelease: (slug: string, version: string) =>
      j<Release>('POST', `${API}/products/${enc(slug)}/releases`, { json: { version } }),
    release: (slug: string, version: string) => j<ReleaseDetail>('GET', rel(slug, version)),
    matchStatus: (slug: string, version: string) =>
      j<MatchStatusInfo>('GET', `${rel(slug, version)}/match-status`),
    uploadSbom: (
      slug: string,
      version: string,
      file: File,
      onProgress: (fraction: number) => void,
    ) => {
      const form = new FormData()
      form.append('file', file)
      return uploadWithProgress<Upload>(
        `${rel(slug, version)}/sbom`,
        form,
        getCsrf(),
        onProgress,
        onUnauthorized,
      )
    },
    findings: (slug: string, version: string, q: FindingQuery) =>
      j<FindingPage>('GET', `${rel(slug, version)}/findings`, {
        query: buildQuery(findingsParams(q)),
      }),
    gate: (slug: string, version: string) => j<Gate>('GET', `${rel(slug, version)}/gate`),
    exports: (slug: string, version: string) =>
      j<ExportItem[]>('GET', `${rel(slug, version)}/exports`),
    exportRelease: async (
      slug: string,
      version: string,
      allowIncomplete: boolean,
    ): Promise<ExportResult> => {
      const res = await client.request('POST', `${rel(slug, version)}/export`, {
        query: buildQuery({ allow_incomplete: allowIncomplete ? 'true' : '' }),
      })
      const v = Number(res.headers.get('X-VEX-Version'))
      const sha = res.headers.get('X-VEX-Content-SHA256')
      if (!Number.isInteger(v) || !sha)
        throw new ApiError({ status: res.status, code: 'bad_response' })
      return {
        text: await res.text(),
        version: v,
        sha256: sha,
        isNew: res.headers.get('X-VEX-New-Version') === 'true',
      }
    },
    diff: (slug: string, from: string, to: string) =>
      j<Diff>('GET', `${API}/products/${enc(slug)}/diff`, { query: buildQuery({ from, to }) }),

    // findings
    finding: (findingId: string) => j<FindingDetail>('GET', `${API}/findings/${enc(findingId)}`),
    triage: (findingId: string, draft: Draft, expectedHeadId: string | null) =>
      j<Statement>('POST', `${API}/findings/${enc(findingId)}/triage`, {
        json: { ...draft, expected_head_id: expectedHeadId },
      }),
    bulkTriage: (findingIds: string[], draft: Draft) =>
      j<{ created: number; statements: Statement[] }>('POST', `${API}/findings/bulk-triage`, {
        json: { ...draft, finding_ids: findingIds },
      }),
    confirm: (findingId: string, expectedHeadId: string | null) =>
      j<Statement>('POST', `${API}/findings/${enc(findingId)}/confirm`, {
        json: { expected_head_id: expectedHeadId },
      }),
    assign: (findingId: string, assigneeId: string | null) =>
      j<{ finding_id: string; assignee_id: string | null }>(
        'PUT',
        `${API}/findings/${enc(findingId)}/assignee`,
        { json: { assignee_id: assigneeId } },
      ),
    addEvidenceFile: (findingId: string, file: File, expectedHeadId: string | null) => {
      const form = new FormData()
      form.append('file', file)
      if (expectedHeadId) form.append('expected_head_id', expectedHeadId)
      return j<Statement>('POST', `${API}/findings/${enc(findingId)}/evidence/file`, { form })
    },

    // admin
    users: () => j<User[]>('GET', `${API}/admin/users`),
    createUser: (username: string, password: string, role: Role) =>
      j<User>('POST', `${API}/admin/users`, { json: { username, password, role } }),
    patchUser: (userId: string, body: { role?: Role; is_active?: boolean; password?: string }) =>
      j<User>('PATCH', `${API}/admin/users/${enc(userId)}`, { json: body }),
    allTokens: () => j<ApiToken[]>('GET', `${API}/admin/tokens`),
    revokeToken: (tokenId: string) => j<undefined>('DELETE', `${API}/admin/tokens/${enc(tokenId)}`),
    audit: (params: { entity_type?: string; action?: string; before_id?: number | null }) =>
      j<AuditPage>('GET', `${API}/admin/audit`, { query: buildQuery({ ...params, limit: 50 }) }),
  }
}

export type Api = ReturnType<typeof createApi>
