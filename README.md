# MaboyyDigital v17.46

Bot Telegram untuk penjualan produk digital dan pengelolaan transaksi.

## Fitur

- Katalog produk, stok, keranjang dan riwayat pesanan.
- Saldo, QRIS Otomatis (KlikQRIS/Payinaja), QRIS manual dan transfer rekening.
- Pengiriman produk, OTP, layanan Sosmed dan API mitra.

## Menjalankan

Gunakan Python 3.12. Contoh konfigurasi tersedia di `.env.example`.
Simpan nilai konfigurasi privat melalui environment atau secret hosting.

```sh
pip install -r requirements.txt
python main.py
```

## Pembaruan

Gunakan seluruh file source dari paket versi yang sama saat memperbarui aplikasi.
Pertahankan data dan konfigurasi saat memperbarui aplikasi.
Jangan unggah `.env` aktif, database atau backup ke repository publik.

## Pengujian

Tes dan patch tersedia dalam paket QA terpisah.
Setelah menyalin folder `tests` ke source proyek, jalankan:

```sh
python -m unittest discover -s tests -v
```
