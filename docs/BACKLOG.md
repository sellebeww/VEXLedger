# BACKLOG

Ide di luar daftar Wajib (satu baris per ide).
- Opsi "tanpa kedaluwarsa" eksplisit pada draft pernyataan untuk status yang punya masa berlaku default (mis. not_affected permanen).
- Temuan yang tidak lagi dikembalikan OSV pada resync (mis. rekaman diperbarui) tetap ada; perlu penanda "tidak lagi cocok".
- Endpoint `/metrics` bersama untuk proses API dan worker.
- Ganti kata sandi sendiri oleh pengguna (`POST /auth/password`); saat ini hanya admin yang dapat mereset.
- Berkas bukti yatim (disimpan tetapi pernyataan gagal ditulis) belum dibersihkan; cukup job pembersih berkala.
- Daftar sesi aktif dan pencabutan sesi oleh pemiliknya.
- Halaman akun sendiri (token pribadi untuk analis dan pembaca; saat ini token dibuat dari tab admin).
- Endpoint ringan daftar pengguna untuk non-admin agar nama penerima tugas tampil (saat ini label umum "Ditugaskan").
- Perketat CSP UI: ganti `'unsafe-inline'` pada `script-src` dengan hash dihitung saat build.
- Daftar temuan memuat semua temuan rilis lalu mengurutkan di Python; pindahkan sorting dan paginasi ke SQL bila rilis mencapai puluhan ribu temuan.
- Banner demo juga di halaman login (saat ini hanya setelah login, karena flag datang dari `/auth/me`).
- Uji diferensial `vexctl` otomatis di CI bila pemasangannya stabil.
