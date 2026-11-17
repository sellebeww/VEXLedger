# Deploy VEXLedger di VPS (dari nol)

Stack: Caddy (TLS otomatis) -> `web` (UI statis) dan `app` (API), plus `worker`, Postgres, Redis. Hanya Caddy yang membuka port. Semua didefinisikan di `deploy/docker-compose.prod.yml`.

Pernyataan jujur: VEXLedger mencatat keputusan triase manusia, tidak menjamin kepatuhan regulasi apa pun, dan dokumen OpenVEX hasilnya tidak ditandatangani. Status uji stack ini di VPS nyata: lihat `docs/ENV_TEST.md` (belum dibuktikan di lingkungan pengembangan).

## 1. Prasyarat
- VPS Linux (1 vCPU / 2 GB RAM cukup untuk tim kecil), Docker Engine + plugin Compose v2, `git`.
- Port 80 dan 443 (TCP, dan 443/UDP) terbuka di firewall VPS dan penyedia.
- Sebuah domain, mis. `vex.contoh.id`.

## 2. DNS
Buat rekaman `A` (dan `AAAA` bila ada IPv6) `vex.contoh.id` yang menunjuk ke IP publik VPS. Tunggu sampai `dig +short vex.contoh.id` mengembalikan IP itu. Caddy baru bisa mendapat sertifikat setelah DNS benar.

## 3. Ambil kode dan isi konfigurasi
```sh
git clone <url-repo-ini> vexledger && cd vexledger/deploy
cp .env.example .env
chmod 600 .env
```
Edit `.env`: `SITE_ADDRESS` dan `VEXLEDGER_VEX_BASE_URL` ke domain Anda; ganti kedua `CHANGE_ME` dengan `openssl rand -hex 24` (hex saja, karena sandi masuk ke URL). Biarkan `DEMO_OSV_FIXTURES=0` untuk penggunaan nyata. `.env` tidak pernah di-commit.

## 4. Jalankan dan TLS
```sh
docker compose -f docker-compose.prod.yml up -d --build --wait
docker compose -f docker-compose.prod.yml ps
curl -sS https://vex.contoh.id/readyz      # {"status":"ok",...}
```
Caddy meminta sertifikat Let's Encrypt otomatis saat start pertama dan memperbaruinya sendiri; sertifikatnya ada di volume `caddy_data` (jangan dihapus, ada batas penerbitan Let's Encrypt). Bila gagal: `docker compose -f docker-compose.prod.yml logs caddy` (biasanya DNS belum menunjuk benar atau port 80/443 tertutup). Migrasi basis data berjalan otomatis lewat layanan `migrate` sebelum API dan worker naik.

## 5. Admin pertama (bootstrap)
Tidak ada pendaftaran publik. Buat admin dari terminal (kata sandi minimal 12 karakter, diminta interaktif, tidak masuk riwayat shell):
```sh
docker compose -f docker-compose.prod.yml exec app vexledger create-admin admin
```
Lalu buka `https://vex.contoh.id`, login, dan buat pengguna lain di halaman Admin. Peran: `admin`, `analyst`, `viewer`.

## 6. Pemakaian dasar
Buat produk (isi `vex_author`), buat rilis, unggah SBOM CycloneDX JSON, tunggu pencocokan (worker memanggil `https://api.osv.dev`, server harus bisa keluar ke sana), triase, ekspor OpenVEX. Skrip CI: `docs/API.md`.

## 7. Backup dan restore
```sh
deploy/backup.sh            # -> deploy/backups/db-<stamp>.dump dan evidence-<stamp>.tgz
deploy/restore.sh deploy/backups/db-<stamp>.dump deploy/backups/evidence-<stamp>.tgz
```
`backup.sh` memakai `pg_dump -Fc` dan mengarsipkan berkas bukti. `restore.sh` MENGGANTI isi basis data (API dan worker dihentikan sebentar). Jadwalkan dengan cron (mis. harian `0 3 * * * /opt/vexledger/deploy/backup.sh`) dan SALIN berkasnya ke luar server; backup di disk yang sama tidak melindungi dari kehilangan server. Latih restore di mesin lain sebelum Anda membutuhkannya. Sesi login ada di Redis dan tidak ikut dibackup (pengguna cukup login ulang).

## 8. Pembaruan
```sh
cd vexledger && git pull
deploy/backup.sh
cd deploy && docker compose -f docker-compose.prod.yml up -d --build --wait
```
Migrasi dijalankan otomatis. Rollback: `git checkout <tag lama>`, build ulang, dan bila skema berubah, `restore.sh` dari backup sebelum pembaruan (migrasi turun tidak dijamin untuk data nyata).

## 9. Mode demo (tanpa internet, DATA SINTETIS)
Untuk memperlihatkan alur tanpa data nyata: `DEMO_OSV_FIXTURES=1` di `.env`. Worker memakai rekaman OSV buatan (id `CVE-2099-*`) dan UI menampilkan banner "DATA DEMO SINTETIS". Jangan dipakai bersama data produksi. Satu perintah untuk demo di laptop: `make demo` (lihat `docs/DEMO.md`). Uji cepat stack produksi lokal (build, TLS lokal, shell UI tidak kosong, readyz, unggah, temuan, ekspor): `deploy/smoke.sh`. Skrip membersihkan stack dan volume yang dibuatnya (exit 0 hanya bila seluruh alur lulus).

## 10. Catatan keamanan
- Port Postgres, Redis, dan API tidak dipublikasikan; hanya Caddy. Jangan menambahkan `ports:` pada layanan lain.
- Kontainer berjalan sebagai pengguna non-root, filesystem root read-only, tanpa capability.
- Header UI disetel Caddy: CSP, HSTS, nosniff, frame DENY, referrer, permissions-policy. CSP masih memakai `'unsafe-inline'` untuk skrip karena Nuxt menyisipkan skrip inline; sumber lain, objek, framing, dan base tag dikunci. Menggantinya dengan hash saat build ada di BACKLOG.
- Batas login per IP bergantung pada alamat klien yang diteruskan Caddy; API hanya terjangkau lewat Caddy sehingga `--forwarded-allow-ips=*` aman di sini.
