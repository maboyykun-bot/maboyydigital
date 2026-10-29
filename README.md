# MaboyyDigital v17.36

Bot Telegram untuk produk digital, saldo, OTP, Sosmed dan API mitra.
Command: `/start`, `/otp`, `/sosmed`, `/tools`, `/owner`, `/ping`.

## Menjalankan

Gunakan Python 3.12. Isi `BOT_TOKEN` dan `ADMIN_ID` melalui secrets hosting;
contoh variabel lainnya tersedia di `.env.example`.

```sh
pip install -r requirements.txt
python main.py
```

## Northflank

Service: `maboyydigital`, Heroku Buildpack, satu instance, 0.2 vCPU / 512 MB.

| Pengaturan | Nilai |
| --- | --- |
| Startup | `python main.py` |
| Port | `8080` |
| Health check | `/health` |
| Mount volume | `/data` |
| `DB_PATH` | `/data/shop.db` |
| `BACKUP_DIR` | `/data/backups` |

Pertahankan database, token dan kunci enkripsi existing saat update.

## KlikQRIS Gateway

Isi `KLIKQRIS_API_KEY` dan `KLIKQRIS_MERCHANT_ID` melalui secrets hosting.
Gunakan konfigurasi berikut:

```env
KLIKQRIS_MODE=gateway
KLIKQRIS_ENABLED=false
KLIKQRIS_SANDBOX=false
```

Mode environment eksplisit mengalahkan mode DB. Pengaturan aktif/nonaktif di DB
mengalahkan nilai default environment; gunakan panel owner untuk menonaktifkan.
Webhook: `https://DOMAIN_BOT/webhooks/klikqris`, melalui `PUBLIC_BASE_URL` atau
`KLIKQRIS_WEBHOOK_URL`. Cek Koneksi hanya membaca API, tanpa membuat invoice.
History HTTP 404 bukan bukti autentikasi berhasil atau riwayat kosong.
Jika create timeout/5xx, cek status atau rekonsiliasi sebelum mencoba lagi.
Aktifkan hanya setelah persistensi `/data/shop.db` dan stok terverifikasi.

## Update v17.36

Untuk proyek existing, timpa `main.py`, `bot.py`, `klikqris_gateway.py` dan
`README.md` dari paket ini. Launcher dan bot harus memakai versi yang sama.
Untuk instalasi baru, upload seluruh **16 file** dari root ZIP ke root repository.
Jangan upload `.env` asli, database atau backup ke GitHub.

Invoice **QRIS Otomatis yang pembayarannya berhasil** dihapus otomatis **1 jam
setelah invoice sukses terkirim**.
Gambar QR dan salinan ringkasan sementara dibersihkan; riwayat, signature, saldo,
stok serta pesan akun tetap tersimpan. Hanya chat pembeli; channel dan metode
pembayaran lain mengikuti alur existing. Pembersihan berlanjut setelah restart,
dengan retry jika Telegram gagal. Ruang SQLite yang dibersihkan dipakai ulang;
ukuran file database tidak selalu langsung mengecil.

Request mengikuti <https://klikqris.com/dokumentasi-api>: base
`https://klikqris.com/api`, header `x-api-key` dan `id_merchant`, create
`POST /qris/create`, status `GET /qris/status/{order_id}`. Body create memakai
`order_id`, `id_merchant`, `amount` integer, `keterangan` dan `callback_url` opsional.
Nominal akhir tetap `total_amount` provider. Semua request memakai key aktif.
Tidak ada variabel baru; key lama tidak diperlukan untuk pembelian baru.

Jika `qris_image` tidak valid, bot mencoba `qris_url` HTTPS resmi untuk invoice yang
sama. Download tidak memakai API key atau mengikuti redirect. Kegagalan gambar
tetap tercatat saat refresh; Cek Status mengambil ulang gambar tanpa create baru.

Di `/owner` → QRIS Otomatis, pastikan:

1. Versi bot dan Gateway sama-sama **17.36**, Database **/data/shop.db**.
2. **Reset tersimpan** memuat waktu/jumlah jika reset sudah berhasil. Membuka
   pratinjau tidak dihitung sebagai reset. Bukti v17.35 tetap dapat dibaca.
3. Setelah reset, pilih **Aktifkan KlikQRIS** sampai izin membuat invoice AKTIF,
   lalu buka checkout baru. Reset sendiri tidak membuat invoice.

Reset mengosongkan daftar QRIS, membersihkan QR sementara, serta menutup pesanan
QRIS yang belum dibayar dan melepas reservasi stoknya. Saldo, pesanan lunas,
signature dan penanda anti pembayaran ganda tetap disimpan. Tidak menghapus DB.
**Reset tidak membatalkan invoice di KlikQRIS.** QR lama mungkin masih dapat
dibayar; pembayaran terlambat memerlukan pemeriksaan owner. Jangan bayar QR lama.
Reset tidak membuat invoice; default retry timeout/5xx tetap tidak diulang.

`KLIKQRIS_PREVIOUS_API_KEY` boleh dihapus dari Secrets setelah reset jika key
lama memang hilang. Kompatibilitas dekripsi lokal untuk data lama tetap ada,
tanpa memakai key lama untuk HTTP. Cek Koneksi hanya GET; setelah daftar kosong,
history 404 tetap belum terverifikasi sampai ada bukti API yang sah.
Schema tetap **207**; dependensi dan fitur pembayaran manual tetap dipertahankan.

## Pengujian dan panduan

**115 tes mock/database sementara lulus.** Termasuk alur HTTP response → SQLite →
foto Telegram dengan gambar QR sintetis, tanpa transaksi nyata. Belum push GitHub, deploy atau tes
pembayaran live; HTTP 503 live belum terverifikasi. Persistensi volume dikonfirmasi pengguna;
akses console hosting tidak tersedia di sesi perbaikan.

Paket `MaboyyDigital_v17.36_QA.zip` memuat tes, patch, checksum dan panduan
pemasangan/rollback (`docs/KLIKQRIS_V17_36.md`). Riwayat fitur lengkap tersedia
di `docs/RIWAYAT_RILIS.md` pada paket QA. Paket QA tidak diperlukan untuk startup.
