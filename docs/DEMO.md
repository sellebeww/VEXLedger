# Demo untuk pemilik (data SINTETIS)

Satu perintah dari nol: `make demo` (butuh Docker untuk Postgres/Redis dev, `uv`, Node). Perintah ini membuat basis data `vexledger_demo` baru, menyalakan API dan worker dengan `VEXLEDGER_DEMO_OSV_FIXTURES=1`, lalu memutar seluruh alur lewat `tools/seed_demo.py` dan memeriksa hasilnya. Lalu `cd web && VEXLEDGER_API_URL=http://localhost:8000 npm run dev`, buka http://localhost:3000, login `admin` / `e2e-dummy-passphrase-1`.

Kejujuran data:
- SBOM `tools/demo/sbom-1.0.0.cdx.json` adalah keluaran NYATA `cyclonedx-py` dari lingkungan proyek ini. `sbom-1.1.0.cdx.json` adalah salinannya dengan SATU dependensi (`idna` 3.20 menjadi 3.21) diubah sengaja (kenaikan versi SIMULASI; versi itu tidak diklaim ada di PyPI). Pembuat: `tools/demo/make_demo_sboms.py`.
- Rekaman OSV buatan tangan (`src/vexledger/demo/osv_fixtures.py`): id `CVE-2099-*`/`GHSA-demo-*`, ringkasan berlabel "DATA DEMO SINTETIS", mengklaim semua versi paket terdampak. Nama paket nyata hanya karena SBOM-nya nyata; tidak ada klaim bahwa paket itu rentan.
- UI menampilkan banner "DATA DEMO SINTETIS" setelah login selama mode demo aktif.

Alur yang diputar skrip (dan yang bisa Anda ulangi di UI):
1. Produk `vexledger-demo`, rilis 1.0.0 dari SBOM nyata; pencocokan menghasilkan 11 temuan (satu WITHDRAWN).
2. Triase: lima justifikasi `not_affected`, satu `affected`, satu `fixed`, satu `under_investigation`; dua temuan sengaja dibiarkan UNTRIAGED.
3. Ekspor rilis 1.0.0 ditolak 409 (gerbang kelengkapan).
4. Rilis 1.1.0 (idna naik versi): tujuh pernyataan INHERITED, `idna` NEEDS_REVIEW.
5. Diff 1.0.0 ke 1.1.0 (`idna` 3.20 ke 3.21).
6. Konfirmasi satu pernyataan warisan, triase ulang `idna`, triase massal dua sisanya.
7. Ekspor OpenVEX 1.1.0, ekspor ulang identik byte-per-byte, validasi terhadap skema resmi OpenVEX v0.2.0 (hasil disimpan di `demo-out/`, dokumen berisi data sintetis dan tidak ditandatangani).
