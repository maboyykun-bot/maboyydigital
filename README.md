# MaboyyDigital v17.37

Bot Telegram produk digital, saldo, OTP, Sosmed dan API mitra.
Command: `/start`, `/otp`, `/sosmed`, `/tools`, `/owner`, `/ping`.

## Menjalankan

Python 3.12. Isi `BOT_TOKEN` dan `ADMIN_ID` di Secrets hosting.
Contoh variabel tersedia di `.env.example`.

```sh
pip install -r requirements.txt
python main.py
```

## Northflank

Service `maboyydigital`, Heroku Buildpack, satu instance, 0.2 vCPU / 512 MB.

| Pengaturan | Nilai |
| --- | --- |
| Startup | `python main.py` |
| Port / health check | `8080` / `/health` |
| Mount volume | `/data` |
| `DB_PATH` | `/data/shop.db` |
| `BACKUP_DIR` | `/data/backups` |

Pertahankan database, token, kunci enkripsi dan konfigurasi fitur lain saat update.

## Update v17.37 dari iPhone

1. Ekstrak ZIP di Files. Upload **main.py, bot.py, klikqris_gateway.py** bersama
   dan README.md ke root GitHub, lalu deploy Northflank. Instalasi baru memakai
   seluruh **16 file** root ZIP. Jangan upload `.env` aktif, database atau backup.
2. Buka ulang `/owner` → QRIS Otomatis. Versi bot/Gateway harus **17.37** dan
   Database `/data/shop.db`. Pastikan volume tetap persisten setelah restart.
3. Untuk menutup riwayat lama yang memang Anda pilih: **Reset Riwayat QRIS** →
   baca pratinjau → **Tutup & kosongkan riwayat**. Tombol tersedia juga pada daftar
   dan detail invoice. Ini tindakan owner, tidak dijalankan saat deploy.
4. Berhasil hanya jika **Reset tersimpan** memuat waktu/jumlah dan daftar kosong.
   Bila gagal, panel menampilkan **Reset gagal terakhir** beserta penyebab,
   tahap, waktu dan ID. Konfirmasi reset lama diberi pesan sudah diproses;
   gunakan pratinjau baru untuk riwayat baru. Rekonsiliasi Status hanya membaca status.
5. Reset menjeda QRIS. Setelah persistensi/stok terverifikasi, pilih **Aktifkan
   KlikQRIS**, lalu buka pembelian baru. Aktifkan dan Cek Koneksi tidak membuat
   invoice percobaan. Jangan membayar QR lama.

Reset menutup pesanan QRIS belum dibayar dan melepas reservasi stoknya.
Saldo, pesanan lunas, signature serta penanda anti pembayaran ganda tetap disimpan.
**Reset tidak membatalkan invoice di KlikQRIS.** Pembayaran terlambat memerlukan
pemeriksaan owner. Proses pembayaran/pengiriman aktif tetap melarang reset.
Tidak menghapus atau mengganti database.

## Konfigurasi KlikQRIS

**Tidak ada variabel baru.** Isi di runtime variables/secrets Northflank:

| Variabel | Isi |
| --- | --- |
| `KLIKQRIS_API_KEY` | API key baru yang aktif |
| `KLIKQRIS_MERCHANT_ID` | Merchant ID akun KlikQRIS yang sesuai |
| `KLIKQRIS_MODE` | `gateway` |
| `KLIKQRIS_SANDBOX` | `false` |
| `KLIKQRIS_ENABLED` | `false` sebagai default instalasi; aktivasi melalui owner |
| `PUBLIC_BASE_URL` | URL HTTPS bot existing, tanpa path webhook |

Webhook: `https://DOMAIN_BOT/webhooks/klikqris`; override opsional existing
`KLIKQRIS_WEBHOOK_URL`. Semua request API memakai key aktif. Key lama tidak
wajib untuk reset atau pembelian baru; `KLIKQRIS_PREVIOUS_API_KEY` boleh dihapus
jika sudah hilang. Dukungan dekripsi lokal data lama tetap ada.
Mode environment eksplisit mengalahkan mode DB; aktif/nonaktif DB mengalahkan
default environment. Ubah aktif/nonaktif melalui panel owner.

Dokumentasi: <https://klikqris.com/dokumentasi-api>. Base `https://klikqris.com/api`,
header `x-api-key` dan `id_merchant`, create `POST /qris/create`, status
`GET /qris/status/{order_id}`. History 404 bukan bukti autentikasi atau riwayat kosong.
Timeout/5xx create tidak diulang otomatis; hasilnya harus direkonsiliasi.
QR resmi dibaca dari `qris_image` atau `qris_url` invoice yang sama. Retry gambar
atau Telegram tidak membuat invoice baru.

Invoice foto QRIS Otomatis yang berhasil dibayar dibersihkan **1 jam setelah
invoice sukses terkirim**. Ledger, riwayat, saldo, stok dan pesan akun tetap ada.
Pembersihan dilanjutkan setelah restart. Ukuran file SQLite tidak selalu langsung
mengecil; ruang yang dibersihkan dapat digunakan ulang.

## Tes dan rollback

**128 tes offline** dengan mock HTTP/Telegram dan SQLite sementara lulus, termasuk
lima invoice CANCELLED_LOCAL → reset owner → key baru → foto QR sintetis.
Schema tetap **207**, tanpa dependensi baru. QRIS manual/rekening, saldo, stok,
pembatalan, signature, webhook/polling dan pengiriman tetap diuji.

Patch, tes, checksum, bukti dan panduan lengkap/rollback ada di
`MaboyyDigital_v17.37_QA.zip` → `docs/KLIKQRIS_V17_37.md`.
Rollback: deploy tiga file source v17.36 bersama; jangan restore DB.
GitHub terakhir diperiksa sudah v17.36. Paket v17.37 belum di-push/deploy oleh
sesi ini. Pembayaran live, hasil reset hosting dan gangguan HTTP 503 belum dapat
diverifikasi; console hosting tidak tersedia. Tes mock tidak membuktikan QR produksi.
