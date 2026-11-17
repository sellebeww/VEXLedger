# Uji manual di lingkungan nyata

Hal-hal ini TIDAK dapat dibuktikan di lingkungan pengembangan (butuh internet ke OSV, VPS publik, atau browser nyata). Jalankan sendiri dan catat hasilnya di bawah "Catatan hasil".

## 1. `pytest -m live_osv`
```sh
uv run pytest -m live_osv tests/integration/test_live_osv.py -q
```
Memeriksa bentuk respons `api.osv.dev` (querybatch dan detail). Tidak menyatakan kerentanan apa pun. Lulus = klien cocok dengan API nyata hari ini.

## 2. Pencocokan SBOM nyata terhadap OSV (bandingkan manual dengan osv.dev)
1. `make dev-up && make migrate`, jalankan API dan worker TANPA mode demo (`VEXLEDGER_DEMO_OSV_FIXTURES` tidak diset): `uv run uvicorn vexledger.api.app:create_app --factory` dan `uv run python -m vexledger.worker`.
2. Buat SBOM nyata, mis. `uv run cyclonedx-py environment --pyproject pyproject.toml --mc-type application --sv 1.6 --of JSON -o /tmp/real.cdx.json` (atau SBOM npm: `cd web && npx @cyclonedx/cyclonedx-npm --output-file /tmp/web.cdx.json package.json`).
3. Buat admin (`VEXLEDGER_ADMIN_PASSWORD=... uv run vexledger create-admin admin`), buat produk, rilis, unggah SBOM, tunggu `MATCHED`.
4. Pilih 3 sampai 5 temuan di UI. Untuk tiap temuan buka `https://osv.dev/vulnerability/<ID>` dan periksa: paket dan versi komponen berada dalam rentang terdampak di osv.dev; alias sama; severity sama. Pilih juga 2 komponen TANPA temuan dan periksa `https://osv.dev` untuk paket+versi itu. Catat selisih (termasuk `match_discrepancy`).
5. Ingat: "tidak ada temuan" bukan bukti "tidak ada kerentanan".

## 3. Stack produksi di VPS
Ikuti `docs/DEPLOY.md` dari nol di VPS dan domain nyata, lalu periksa: sertifikat TLS valid (`curl -vI https://DOMAIN`), `/readyz` 200, `create-admin`, login di browser, unggah SBOM nyata, pencocokan selesai (server dapat menjangkau OSV), `deploy/backup.sh` lalu `deploy/restore.sh` di mesin lain berhasil, `docker compose ... up -d --build` setelah `git pull` mempertahankan data.
Tanpa VPS: `deploy/smoke.sh` menguji stack yang sama di mesin lokal (TLS lokal, data sintetis).

## 4. Browser nyata
Buka UI di Chrome, Firefox, Safari: login, daftar temuan, triase (semua status), triase massal, unggah bukti berkas, ekspor tidak lengkap dengan konfirmasi, unduhan JSON, diff, halaman admin. Periksa ukuran layar sempit, navigasi keyboard, dan banner demo (hanya mode demo). Audit aksesibilitas otomatis (axe, Lighthouse) belum dijalankan.

## 5. Validasi dokumen OpenVEX dengan `vexctl`
Pengembang memvalidasi dokumen terhadap skema JSON resmi OpenVEX v0.2.0; `vexctl` tidak bisa dipasang di lingkungan pengembangan. Jalankan sendiri:
```sh
go install github.com/openvex/vexctl@latest    # atau unduh rilis dari github.com/openvex/vexctl
vexctl merge --product "pkg:pypi/vexledger@1.1.0" demo-out/vex-vexledger-demo-1.1.0-v1.json
```
Perintah ini belum dijalankan: `merge` dipilih karena memuat (mengurai) dokumen OpenVEX; sesuaikan dengan `vexctl --help` versi Anda bila sub-perintahnya berbeda. Dugaan tanpa verifikasi: vexctl tidak punya perintah `validate` khusus, jadi hasil yang berarti hanya "dokumen dapat dibaca".

## 6. Uji diferensial Maven terhadap Java asli
Pembanding Maven diport dari `ComparableVersion.java` dan lulus semua vektor upstream, tetapi belum pernah dibandingkan dengan Java yang sebenarnya (sandbox menolak menjalankan Java hasil unduhan, 2026-11-17). Skrip siap pakai, BELUM dijalankan oleh pemilik:
```sh
uv run python tools/maven_differential.py            # butuh JDK dan internet; keluar 1 bila ada selisih
```
Ia mengunduh `maven-artifact` dari Maven Central, memeriksa SHA-1 dari Central, mengompilasi harness kecil, dan membandingkan 30000 pasang versi acak. Selisih hanya memengaruhi penanda `match_discrepancy` (OSV tetap menang), bukan daftar temuan.

## 7. CSP dan UI di browser terhadap stack Docker
Header CSP di `deploy/Caddyfile` diuji pengembang terhadap build produksi UI di Chromium (7 halaman, 0 pelanggaran), tetapi dengan header disuntik, bukan lewat Caddy: Chromium di sandbox tidak dapat menjangkau port yang dipublikasikan Docker. Jalankan `deploy/smoke.sh`, atau buka stack Anda di browser, lalu periksa konsol (tidak boleh ada "Content Security Policy" atau "Refused to").

## Catatan hasil (isi oleh pemilik)
| Uji | Tanggal | Hasil |
|---|---|---|
| live_osv | | |
| Pencocokan nyata vs osv.dev | | |
| VPS | | |
| Browser | | |
| vexctl | | |
| Diferensial Maven (Java) | | |
| CSP lewat Caddy di browser | | |
