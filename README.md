# MaboyyDigital v17.32

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

## Update v17.32

Untuk proyek existing, timpa `main.py`, `bot.py`, `klikqris_gateway.py` dan
`README.md` dari paket ini. Launcher dan bot harus memakai versi yang sama.
Untuk instalasi baru, upload seluruh **16 file** dari root ZIP ke root repository.
Jangan upload `.env` asli, database atau backup ke GitHub.

Invoice **QRIS Otomatis yang berhasil dikirim** dihapus otomatis setelah **1 jam**.
Gambar QR dan salinan ringkasan sementara dibersihkan; riwayat, signature, saldo,
stok serta pesan akun tetap tersimpan. Hanya chat pembeli; channel dan metode
pembayaran lain mengikuti alur existing. Pembersihan berlanjut setelah restart,
dengan retry jika Telegram gagal. Ruang SQLite yang dibersihkan dipakai ulang;
ukuran file database tidak selalu langsung mengecil.

Rilis ini juga memulihkan draft yang belum dikirim setelah API key berubah, serta
merekonsiliasi invoice lama tanpa membuat tagihan baru. Untuk invoice yang sudah
dikirim, isi `KLIKQRIS_PREVIOUS_API_KEY` dengan key lama melalui secrets hosting;
key ini hanya untuk membuka signature/QR tersimpan. Semua request memakai key baru.
Lalu gunakan **QRIS Otomatis → Rekonsiliasi → Cek Koneksi**. Jangan kirim key di chat.
Jika key lama hilang, invoice yang sudah terkirim perlu rekonsiliasi penyedia;
validasi signature tetap diwajibkan. Draft NEW tidak memerlukan key lama.
Schema tetap **207**; dependensi dan fitur pembayaran manual tetap dipertahankan.

## Pengujian dan panduan

**64 tes mock/database sementara lulus.** Belum push GitHub, deploy atau tes
pembayaran live; HTTP 503 live belum terverifikasi. Persistensi volume dikonfirmasi pengguna;
akses console hosting tidak tersedia di sesi perbaikan.

Paket `MaboyyDigital_v17.32_QA.zip` memuat tes, patch, checksum dan panduan
pemasangan/rollback (`docs/KLIKQRIS_V17_32.md`). Riwayat fitur lengkap tersedia
di `docs/RIWAYAT_RILIS.md` pada paket QA. Paket QA tidak diperlukan untuk startup.
