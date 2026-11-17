# API VEXLedger (`/api/v1`)

Dokumen OpenAPI otomatis: `/docs` (Swagger UI), `/redoc`, `/openapi.json`. Dokumen ini ringkasannya untuk pemilik dan CI.

VEXLedger adalah alat bantu pencatatan keputusan triase oleh manusia. Ia tidak menentukan eksploitabilitas, tidak menjamin kepatuhan regulasi apa pun, dan dokumen OpenVEX hasilnya TIDAK ditandatangani. "Tidak ada temuan" bukan bukti "tidak ada kerentanan" (data OSV.dev bisa tidak lengkap atau terlambat).

## Autentikasi

| Cara | Untuk | Detail |
|---|---|---|
| Sesi cookie | Browser | `POST /auth/login` mengisi cookie `vexledger_session` (HttpOnly, SameSite=Lax, Secure di prod) dan mengembalikan `csrf_token`. Setiap mutasi wajib mengirim `X-CSRF-Token`. `GET /auth/me` mengembalikan token CSRF sesi aktif. |
| Token API pribadi | CI dan skrip | `Authorization: Bearer vxl_...`. Tanpa CSRF. Peran = peran pemilik saat ini; pemilik dinonaktifkan atau token dicabut: 401. Dibuat lewat sesi (`POST /auth/tokens`), ditampilkan SEKALI, hanya hash SHA-256 yang disimpan. Token tidak dapat membuat token. |

Admin pertama dibuat lewat CLI (tidak ada pendaftaran publik):
`VEXLEDGER_ADMIN_PASSWORD='...' uv run vexledger create-admin NAMA` (tanpa variabel itu, kata sandi diminta interaktif). Kata sandi minimal 12 karakter, disimpan sebagai argon2id.

Batas login: 5 percobaan gagal per akun dan 20 per IP dalam 15 menit, lalu `429` dengan `Retry-After`. Catatan: batas per akun dapat dipakai penyerang untuk mengunci akun korban sementara (kompromi yang disengaja). Di belakang proxy, jalankan uvicorn dengan `--proxy-headers --forwarded-allow-ips=<ip proxy>` agar IP klien benar; tanpa itu semua klien tampak satu IP.

## Peran x endpoint

`V` viewer, `A` analyst, `D` admin. Tanda `x` berarti diizinkan; peran lebih rendah mendapat `403 forbidden`, tanpa kredensial `401 unauthorized`. Tabel ini dijaga test (`test_authz_matrix.py`): setiap route harus tercantum dan menyatakan peran yang sama.

| Endpoint | V | A | D |
|---|---|---|---|
| `POST /auth/login` (publik, ber-rate-limit) | | | |
| `GET /auth/me`, `POST /auth/logout` | x | x | x |
| `GET/POST /auth/tokens`, `DELETE /auth/tokens/{id}` (milik sendiri; buat: hanya sesi) | x | x | x |
| `GET /products`, `GET /products/{slug}` | x | x | x |
| `POST /products`, `PATCH /products/{slug}` (inherit, masa berlaku, author) | | | x |
| `GET /products/{slug}/releases`, `.../releases/{v}`, `.../match-status`, `.../findings`, `.../gate`, `.../exports`, `GET /products/{slug}/diff` | x | x | x |
| `POST /products/{slug}/releases` (buat rilis) | | x | x |
| `POST .../releases/{v}/sbom` (unggah SBOM) | | x | x |
| `POST .../releases/{v}/export` | | x | x |
| `GET /findings/{id}`, `GET /evidence-files/{id}/download` | x | x | x |
| `POST /findings/{id}/triage`, `/findings/bulk-triage`, `/findings/{id}/confirm`, `PUT /findings/{id}/assignee`, `POST /findings/{id}/evidence`, `/findings/{id}/evidence/file` | | x | x |
| `GET /admin/audit`, `GET/POST /admin/users`, `PATCH /admin/users/{id}`, `GET /admin/tokens`, `DELETE /admin/tokens/{id}` | | | x |

## Bentuk galat

Selalu `{"error": {"code", "message", "field"?, "details"?, "request_id"}}`. Tidak pernah ada stack trace atau gema input. Kode stabil:

| Status | `code` |
|---|---|
| 401 / 403 / 429 | `unauthorized`, `invalid_credentials`, `forbidden`, `csrf_failed`, `session_required`, `rate_limited` |
| 404 | `not_found` |
| 409 | `conflict` (pernyataan berubah sejak dibaca; `details.current_head_id`), `release_incomplete` (`details`: `open_count`, `investigating_count`, `total`), `release_not_matched`, `release_exists`, `product_exists`, `user_exists`, `last_admin`, `not_inherited`, `no_statement` |
| 413 | `payload_too_large`, `sbom_too_large`, `file_too_large` |
| 422 | `validation_error`; pernyataan: `justification_required`, `justification_not_allowed`, `impact_statement_required`, `action_statement_required`, `status_notes_required`, `evidence_invalid`, `valid_until_not_in_future`, `no_op`; ekspor: `no_exportable_statements`; SBOM: `sbom_not_json`, `sbom_unsupported_format`, `sbom_schema_invalid`, `sbom_limit_exceeded`; bukti: `empty_file`, `type_not_allowed`, `content_does_not_match_type`; lain: `invalid_purl`, `invalid_assignee`, `password_too_short` |
| 500 / 503 | `internal_error`; `service_unavailable` (Redis atau Postgres mati, dengan `Retry-After`) |

## Aturan penting

- **Triase** (`POST /findings/{id}/triage`) menambah pernyataan baru (append-only). `expected_head_id` opsional: bila dikirim dan rantai sudah bergerak, `409`. Dua analis serentak: satu menang, satu `409`.
- **Triase massal** (maks 200 id unik, satu isi untuk semua): satu pernyataan per temuan, semua atau tidak sama sekali dalam satu transaksi; satu gagal membatalkan semua dan galat menyebut `details.finding_id`. Tiap pernyataan tercatat di `audit_log`.
- **Konfirmasi** (`/confirm`) hanya untuk pernyataan yang diwarisi dan masih berlaku (`409 not_inherited` bila bukan).
- **Bukti**: LINK (http/https, tidak pernah di-fetch server), NOTE (teks polos), FILE (maks 10 MB; txt, md, log, json, patch, diff, png, jpg, pdf; isi diperiksa, bukan hanya ekstensi). Menambah bukti = pernyataan baru dengan isi sama plus satu bukti. Unduhan SELALU `Content-Disposition: attachment`, `application/octet-stream`, `X-Content-Type-Options: nosniff`.
- **Unggah SBOM** idempoten: byte yang sama lagi mengembalikan hasil tersimpan (`created: false`) tanpa antrean ganda; SBOM berbeda untuk rilis yang sama `409` (SBOM baru = rilis baru). Balasan `202`: pencocokan berjalan di worker, pantau `match-status`. Rilis yang belum `MATCHED` tidak pernah dianggap "bersih": `gate.complete` false dan ekspor `409 release_not_matched`.
- **Ekspor**: `POST .../export` mengembalikan dokumen OpenVEX v0.2.0 apa adanya (byte identik untuk isi yang sama, versi tetap; isi berubah: versi naik dan baris `vex_exports` baru). Header `X-VEX-Version`, `X-VEX-Content-SHA256`, `X-VEX-New-Version`. Ada temuan terbuka (UNTRIAGED, NEEDS_REVIEW, EXPIRED) tanpa `?allow_incomplete=true`: `409`. Pernyataan `under_investigation` yang masih berlaku dilaporkan terpisah, tidak memblokir.
- **Batas ukuran**: JSON 256 KB, SBOM 25 MB (`VEXLEDGER_MAX_UPLOAD_MB`), berkas bukti 10 MB; ditolak sebelum dibaca (`413`).
- **CORS**: tidak ada asal yang diizinkan secara bawaan; isi `VEXLEDGER_CORS_ORIGINS` (daftar JSON asal eksplisit, `*` ditolak).

## Contoh alur CI (curl)

```bash
VEX=https://vex.example.com            # alamat server
TOKEN=vxl_xxxxx                        # token API analyst, simpan sebagai secret CI
P=web-app; V=1.4.0                     # slug produk dan versi rilis
H="Authorization: Bearer $TOKEN"
R="$VEX/api/v1/products/$P/releases"

# 1. buat rilis (409 release_exists berarti sudah ada: lanjut)
curl -sS -X POST "$R" -H "$H" -H 'Content-Type: application/json' -d "{\"version\": \"$V\"}"

# 2. unggah SBOM CycloneDX JSON (202; aman diulang)
curl -sS --fail-with-body -X POST "$R/$V/sbom" -H "$H" -F "file=@bom.cdx.json;type=application/json"

# 3. tunggu pencocokan selesai (MATCH_PENDING -> MATCHED atau MATCH_FAILED)
until s=$(curl -sS "$R/$V/match-status" -H "$H" | jq -r .status); [ "$s" != MATCH_PENDING ]; do sleep 10; done
[ "$s" = MATCHED ] || { echo "pencocokan gagal"; exit 1; }

# 4. gerbang: gagalkan build bila masih ada temuan terbuka
curl -sS "$R/$V/gate" -H "$H" | tee gate.json | jq -e '.complete' >/dev/null || { jq . gate.json; exit 1; }

# 5. ekspor OpenVEX (409 release_incomplete bila belum lengkap; tambahkan ?allow_incomplete=true untuk memaksa)
curl -sS --fail-with-body -X POST "$R/$V/export" -H "$H" -o "vex-$P-$V.json" -D headers.txt
grep -i '^x-vex-version' headers.txt
```
