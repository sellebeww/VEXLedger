# Tangkapan layar (diambil pemilik)

Agen tidak membuat tangkapan layar apa pun, dan tidak ada gambar palsu di folder ini. Pemilik
mengambilnya dari stack demo:

```sh
make dev-up
uv run python tools/e2e_stack.py        # API :8000, worker, OSV tiruan SINTETIS, data demo
(cd web && npm run dev)                  # UI di http://localhost:3000 (proksi /api ke :8000)
```

Masuk sebagai `admin`, `analyst`, atau `viewer` dengan kata sandi dummy yang dicetak skrip
(`READY: ...`). Data berasal dari rekaman OSV **sintetis** (id `CVE-2099-*`); beri keterangan
"data sintetis" bila gambar dipublikasikan. Simpan sebagai PNG berawalan nomor di folder ini.

| # | Layar | Cara mencapai | Yang harus terlihat |
|---|---|---|---|
| 01 | Login | `/login` | Formulir, pernyataan jujur |
| 02 | Daftar produk | `/products` | Produk Demo App, tombol "Buat produk" (admin) |
| 03 | Pengaturan produk | `/products/demo-app/settings` | Author, pewarisan beserta peringatan, masa berlaku bawaan |
| 04 | Detail produk | `/products/demo-app` | Daftar rilis, ringkasan temuan per state |
| 05 | Unggah SBOM | tombol "Unggah SBOM untuk rilis ..." | Dropzone, progres, status pencocokan, peringatan impor |
| 06 | Tabel temuan | `/products/demo-app/releases/1.0.0` | Badge state (ikon + teks), filter, seleksi baris |
| 07 | Komponen tak dapat dicocokkan | bagian bawah layar 06 | Daftar NO_PURL dan ekosistem tidak didukung |
| 08 | Triase massal | pilih beberapa baris, "Triase massal" | Dialog dengan status, justifikasi, masa berlaku |
| 09 | Detail temuan | klik id kerentanan | Ringkasan OSV, jalur dependensi, riwayat, form triase |
| 10 | Form triase dengan galat | kirim "Tidak terdampak" tanpa justifikasi | Pesan galat per kolom, peringatan "tanpa bukti" |
| 11 | Temuan diwarisi / perlu tinjau | rilis kedua dari SBOM yang sedikit berbeda | Tombol "Konfirmasi", konteks pernyataan lama |
| 12 | Diff rilis | `/products/demo-app/diff` | Komponen dan temuan berubah, ringkasan pewarisan |
| 13 | Ekspor tidak lengkap | `/products/demo-app/releases/1.0.0/export` | Gerbang, dialog konfirmasi eksplisit, "tidak ditandatangani" |
| 14 | Riwayat versi ekspor | layar 13 setelah mengunduh | Tabel versi dan hash |
| 15 | Admin: pengguna | `/admin` | Daftar pengguna, peran |
| 16 | Admin: token dibuat | tab "Token API" | Token tampil sekali dengan peringatan |
| 17 | Admin: audit log | tab "Audit log" | Entri audit dengan filter |
| 18 | Layar sempit | layar 06 di lebar 390 px | Tabel dapat digulir, tidak ada scroll halaman horizontal |
| 19 | Navigasi keyboard | layar 06 atau 08 | Cincin fokus terlihat pada tabel dan dialog |
