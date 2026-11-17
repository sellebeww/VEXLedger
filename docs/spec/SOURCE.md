# Sumber spesifikasi OpenVEX

Diambil 2026-11-16 dari https://github.com/openvex/spec.

- `OPENVEX-SPEC-v0.2.0.md`: `OPENVEX-SPEC.md` pada tag `v0.2.0` (tag beranotasi, commit 7667061835da09300f913e26be10ee03c05e784d, 2023-08-22).
- `openvex_json_schema_0.2.0.json`: `openvex_json_schema.json` dari cabang `main`, commit 93139bd2c65390b504e47f82f11c50451289f93a. Berkas ini tidak ada pada tag v0.2.0 (diperiksa: 404), tetapi `$id` di dalamnya adalah `https://github.com/openvex/spec/openvex_json_schema_0.2.0.json`, jadi ini skema resmi untuk v0.2.0.

Catatan: skema mensyaratkan `statements` minimal 1 item (`minItems: 1`) dan melarang properti tambahan di tingkat dokumen dan statement.
Catatan: OPENVEX-SPEC v0.2.0 menyebut `@context` tetap `https://openvex.dev/ns` sebelum 1.0; skema hanya mensyaratkan URI. VEXLedger memakai `https://openvex.dev/ns/v0.2.0` sesuai spesifikasi proyek 5.8.

Lisensi berkas upstream: repositori openvex/spec berlisensi Apache-2.0 (tidak diverifikasi ulang di sesi ini; periksa LICENSE di repo sumber bila akan didistribusikan ulang).
