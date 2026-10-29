# MaboyyDigital v17.35

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

## Update v17.35

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

Semua request memakai `KLIKQRIS_API_KEY` aktif. Tidak ada variabel baru.
Reset dan pembelian baru tidak memerlukan key lama. Untuk memulai ulang:

1. Buka `/owner` → QRIS Otomatis → **Reset Riwayat QRIS**.
2. Baca jumlah transaksi dan akibatnya, lalu pilih **Tutup & kosongkan riwayat**.
3. Reset menjeda QRIS. Pilih **Aktifkan KlikQRIS** saat siap, lalu buka checkout baru.

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

**101 tes mock/database sementara lulus.** Belum push GitHub, deploy atau tes
pembayaran live; HTTP 503 live belum terverifikasi. Persistensi volume dikonfirmasi pengguna;
akses console hosting tidak tersedia di sesi perbaikan.

Paket `MaboyyDigital_v17.35_QA.zip` memuat tes, patch, checksum dan panduan
pemasangan/rollback (`docs/KLIKQRIS_V17_35.md`). Riwayat fitur lengkap tersedia
di `docs/RIWAYAT_RILIS.md` pada paket QA. Paket QA tidak diperlukan untuk startup.
