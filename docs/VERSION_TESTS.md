# Sumber vektor uji pembanding versi

Dibuat 2026-11-16. Semua vektor ada di `tests/unit/domain/test_versions_*.py`.

## Maven (`ComparableVersion`)
- Implementasi diport dari `apache/maven`, cabang `maven-3.9.x`, commit `4f347192deadb151c6647a8038ad2741dcc1a754`, berkas `maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java` (diambil dari raw.githubusercontent.com pada tanggal di atas).
- Vektor: `ComparableVersionTest.java` pada commit yang sama, disalin ke Python tanpa perubahan nilai: `VERSIONS_QUALIFIER`, `VERSIONS_NUMBER` (urutan, semua pasangan i<j), `testVersionsEqual`, `testVersionComparing`, `testMng5568`, `testMng6572` (bilangan 10, 15, 20 digit), `testVersionEqualWithLeadingZeroes`, `testVersionZeroEqualWithLeadingZeroes`, `testMng6964`, `testLocaleIndependent`, `testMng7644`. Tambahan kami (bukan dari upstream): beberapa pasangan kualifier umum (`1.0-RC1 < 1.0 < 1.0-sp1`).
- Hasil: seluruhnya lulus. Properti hypothesis (antisimetri, transitivitas, 1500 contoh) lulus.
- **Belum dilakukan (butuh pemilik, `tools/maven_differential.py`, lihat ENV_TEST bagian 6):** uji diferensial menjalankan `ComparableVersion.java` asli terhadap input acak. JDK tersedia di mesin ini, tetapi menjalankan kode Java hasil unduhan ditolak oleh pengaman lingkungan sesi ini. Pemilik dapat menjalankannya sendiri bila ingin keyakinan tambahan.

## PyPI (PEP 440)
- Memakai pustaka referensi `packaging` (versi di `uv.lock`); urutan diuji dengan daftar contoh dari aturan pengurutan PEP 440 (dev < a < b < rc < rilis < local < post), epoch, ekuivalensi ejaan. Daftar ini ditulis dari pemahaman teks PEP 440; halaman PEP tidak diambil ulang dalam sesi ini, tetapi seluruh daftar divalidasi oleh pustaka `packaging`.

## npm dan Go (SemVer 2.0.0)
- Rantai urutan dari SemVer 2.0.0 butir 11 (`1.0.0-alpha < ... < 1.0.0-rc.1 < 1.0.0`) ditulis dari ingatan teks spesifikasi, tidak diambil ulang. Aturan identifier numerik vs alfanumerik, build metadata diabaikan, angka dibanding secara numerik.
- Pseudo-version Go: bentuk `vX.0.0-yyyymmddhhmmss-hash`, `vX.Y.(Z+1)-0.yyyymmddhhmmss-hash`, `vX.Y.Z-pre.0.yyyymmddhhmmss-hash`, dan `+incompatible` ditulis dari dokumentasi modul Go (go.dev/ref/mod#pseudo-versions) berdasarkan pengetahuan, tidak diambil ulang. Urutannya adalah urutan SemVer biasa, yang juga cara Go membandingkannya.

## Skema OSV
- `ossf/osv-schema`, `docs/schema.md`, commit `ef84846d74dc87816baf791da76d5f123bb0081e` (main, 2026-11-16). Bagian "Evaluation", "affected[].ranges[].events", "affected[].ranges[].type".

## Tambahan
- Maven: hypothesis menemukan dua kasus yang melanggar transitivitas: `0 < b <= 0A0 < 0` dan `1 <= 1.sp.1 <= 1.alpha < 1`. Semua vektor upstream tetap lulus, jadi diduga perilaku `ComparableVersion` asli; belum dikonfirmasi terhadap Java (diblokir). Tes transitivitas dibatasi pada bentuk umum, dan kedua kasus di atas dicatat sebagai tes yang mendokumentasikan (bukan menyembunyikan) perilaku.

## Verifikasi tambahan
- 66 kasus yang dihitung tangan dari spesifikasi (bukan dari test yang ada), dijalankan lewat jalur produksi `parse_purl` -> `parse_record` -> `local_match`: PyPI 20, npm 18, Go 12, Maven 16, semuanya cocok, termasuk batas fixed eksklusif, last_affected inklusif, epoch, pre-release, build metadata, `+incompatible`, pseudo-version Go, kualifier Maven, dan versi tak valid (selalu UNKNOWN, tidak pernah AFFECTED). Kasus Log4Shell-shaped bersifat SINTETIS (bentuk rentang, bukan rekaman OSV).
- SemVer (npm, Go): 20000 pasang acak (identifier numerik dan alfanumerik, build metadata) dibandingkan dengan paket `semver` 7.8.6 (npm): 0 selisih. Skrip pembangkit dan pembanding tidak disimpan di repo. Ke-66 kasus tangan disimpan sebagai `tests/unit/domain/test_hand_derived_matching.py`.
- PyPI memakai pustaka referensi `packaging`; tidak ada pembanding independen kedua.
- Maven: lihat bagian "Belum dilakukan" di atas. Pencocok lokal tetap aktif untuk Maven karena vektor upstream kuat; dampak kesalahan terbatas pada penanda `match_discrepancy` (OSV menang).
