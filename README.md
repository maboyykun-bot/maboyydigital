# MaboyyDigital v17.38

Bot Telegram untuk penjualan produk digital dan pengelolaan transaksi.

## Fitur

- Katalog produk, stok, keranjang dan riwayat pesanan.
- Saldo, QRIS Otomatis, QRIS manual dan transfer rekening.
- Pengiriman produk, OTP, layanan Sosmed dan API mitra.

## Menjalankan

Gunakan Python 3.12. Contoh konfigurasi tersedia di `.env.example`.
Simpan nilai konfigurasi privat melalui environment atau secret hosting.

```sh
pip install -r requirements.txt
python main.py
```

## Pembaruan

Gunakan `main.py`, `bot.py` dan `klikqris_gateway.py` dari versi yang sama.
Pertahankan data dan konfigurasi saat memperbarui aplikasi.
Jangan unggah `.env` aktif, database atau backup ke repository publik.

## Pengujian

Tes dan patch tersedia dalam paket QA terpisah.
Setelah menyalin folder `tests` ke source proyek, jalankan:

```sh
python -m unittest discover -s tests -v
```
