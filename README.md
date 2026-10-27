# MaboyyDigital v17.29

Paket ringkas: **16 file**, langsung di root ZIP. Upload seluruh isinya ke root repository GitHub.

## Pembaruan v17.29: API Bot untuk mitra

**/owner → 🔑 API Bot** mengelola key integrasi untuk produk /start, OTP dan
SOSMED. Owner membuat key dengan Nama Mitra | User ID Telegram terdaftar,
mengonfirmasi, menyimpan key sekali, memilih akses/limit, mengganti atau mencabut
key. Key memakai saldo akun tersebut dan harga jual existing; bukan BOT_TOKEN.
Key disimpan sebagai hash, quote sensitif terenkripsi, dan riwayat memakai WIB.

API berada pada **PUBLIC_BASE_URL/api/v1** di webserver aiohttp existing.
Gunakan Authorization: Bearer API_KEY_MITRA dan JSON. Pembelian API awalnya OFF;
isi PUBLIC_BASE_URL HTTPS existing lalu Buka Pembelian di panel owner. Tidak ada
Variables baru pada bot Maboyy. Bot mitra menyimpan base URL/key sebagai secrets
miliknya sendiri. OTP/SOSMED dan saldo/stok existing tetap harus tersedia.

Alur: GET /products, /otp/services atau /sosmed/services → POST /quotes →
POST /orders dengan quote_id dan header Idempotency-Key → GET /orders/ORDER_ID.
Simpan quote_id dan idempotency key sebelum membeli; setelah timeout gunakan
keduanya yang sama. GET /balance membaca saldo yang sama dengan /start /otp
/sosmed. API tidak membuka approval pembayaran, topup/kredit saldo atau refund
paksa. Batal OTP memakai izin/refund existing; gagal/partial SOSMED mengikuti
refund native. Daftar order hanya memuat ringkasan; hasil akun/SMS ada di detail
order yang berhak. Harga SOSMED per 1.000; total final dihitung server.

Contoh POST /quotes produk: {"kind":"products","variant_id":12,"quantity":1}.
Contoh POST /orders: {"quote_id":"Q-..."}, header Idempotency-Key: order-mitra-000001.
Produk tetap quantity 1 per checkout. Famhead memerlukan family_gmail; preorder
menunggu owner. OTP memakai offer_id dari katalog, SOSMED memakai service_id dan
parameters sesuai form native. Layanan yang belum didukung tetap ditolak.

Paket runtime kini **16 file**, termasuk modul baru **bot_api.py**. Semua nama
file lama dipertahankan. Backup project dari panel owner ikut menyertakan modul
API. Panduan lengkap dan contoh client async tersedia di **API_BOT_GUIDE.md** pada
paket SourceLengkap serta file panduan API tersendiri yang menyertai rilis.

Schema **207** additive hanya menambah metadata API: hash key, quote, mapping
order/idempotensi dan audit. Wallet/deposit, provider, pembayaran, invoice foto,
keyboard, channel transaksi dan command existing tetap memakai alur sebelumnya.
Tidak ada command baru, server kedua, reset database atau pembelian live saat QA.

## Fitur v17.28: perpindahan command tanpa teks keyboard

Keyboard tetap berisi List Produk, Voucher, Laporan Stok dan nomor produk hanya
aktif di menu /start beserta katalog dan tombol kembali ke menu tersebut.
Saat /otp, /sosmed, /tools, /owner, /demo, /ping atau command lain dibuka,
**balasan asli dikirim lebih dulu dengan tombol inline tetap utuh**. Pesan
“Keyboard mengetik aktif” tidak lagi dikirim. Pelepasan keyboard terpisah tidak
memuat teks yang terlihat, tanpa notifikasi, dan langsung dibersihkan bersama
prompt keyboard /start lama yang tercatat. Balasan teks tanpa tombol inline
dapat melepas keyboard dalam pesan balasan itu sendiri, tanpa pesan tambahan.

Pembersihan Telegram dibatasi dua detik setelah respons, tidak menahan menu,
dan tidak mengulangi handler/transaksi jika gagal. Keyboard yang sudah dilepas
tidak direset lagi setiap berpindah command. Kontrol yang gagal dibersihkan
dicoba kembali pada navigasi berikutnya. Pesan keyboard lama v17.27 yang
tercatat ikut dibersihkan; identitas invoice/pesan lain tidak dijadikan target.

Command @nama_bot, fallback tanpa metadata Command, status yang hanya mengedit
foto, deep link /start am_mail_…, rating dan tombol fitur dari pesan lama ikut
ditangani. Tidak ada foto invoice atau pesan sukses kedua untuk pergantian
keyboard. Kembali ke /start memulihkan keyboard produk; tombol Perbarui Keyboard
lama tidak mengaktifkannya di command lain. Scope user/chat tetap terpisah.

Perubahan runtime hanya pada UI keyboard/navigasi di bot.py dan penanda versi
main.py. Registrasi handler/command, katalog A–Z, pemetaan nomor, FSM fitur,
invoice, channel transaksi, wallet, pembayaran, provider, refund dan migration
tetap memakai implementasi sebelumnya. Schema tetap **206**; tidak ada migration,
Variables Railway, dependency, callback pembayaran atau file runtime baru.
Paket utama tetap 16 file langsung di root ZIP, tanpa mengganti nama runtime.

## Fitur v17.26 yang dipertahankan: invoice pembelian dan channel transaksi

Pembelian **/otp dan /sosmed** sekarang mempunyai satu pesan foto invoice,
caption detail pesanan, dan tombol. Notifikasi purchase, worker, pembayaran
manual dan tombol Cek memakai invoice yang sama. Status/SMS memperbarui caption,
bukan membuat invoice sukses lain. SMS lengkap tetap tersedia sebagai isi SMS,
bukan invoice pembayaran kedua. Salin Nomor dan Salin OTP memakai satu tombol
native masing-masing, tanpa ikon clipboard tambahan pada label.

Tombol **Batalkan Pesanan** OTP tampil selama menunggu SMS. Jika provider belum
mengizinkan pembatalan, bot menjelaskan jedanya dalam WIB. Pembatalan/refund
hanya mengikuti respons nyata dan ledger existing. Pembatalan SOSMED tetap
mengikuti kemampuan resmi provider; tombol owner untuk saldo tertahan tetap ada.

Foto pembelian OTP/SOSMED dihapus ketika status provider terkonfirmasi batal,
gagal atau kedaluwarsa. OTP juga memakai expires_at provider untuk masa berlaku
foto pesanan yang belum selesai. Timer foto tidak menyatakan pembayaran gagal,
tidak memotong saldo, dan tidak membuktikan refund provider. SOSMED tidak diberi
deadline buatan karena kontrak API tidak menyediakannya. Partial tetap menampilkan
status/refund sebenarnya; transaksi selesai tetap menyimpan invoice sukses.
Jika Telegram menolak penghapusan foto lama, pesan yang sama diganti gambar
**INVOICE HANGUS** tanpa tombol. Cleanup yang gagal dicoba ulang setelah restart.
Invoice yang sudah ditutup tidak dikirim ulang sebagai sukses. Riwayat dan
snapshot pembayaran tetap disimpan. Invoice sukses command lain mengikuti v17.25.

**/owner → 📢 Notifikasi Transaksi** mengatur satu channel tersendiri. Owner
memasukkan ID -100… atau @username, melihat konfirmasi lama/baru, menyimpan,
memeriksa izin, lalu mengaktifkan. Bot wajib admin channel dengan izin kirim.
Fitur nonaktif secara default dan tidak memerlukan Variables Railway baru.
Setiap transaksi sukses dikirim sebagai **satu foto invoice + caption**:
produk/VIP terkirim, deposit terverifikasi, OTP diterima, dan SOSMED selesai.
Pending, gagal, batal, serta topup perantara pembayaran OTP/SOSMED tidak
menghasilkan pengumuman sukses ganda. Transaksi lama dilewati saat aktivasi;
ganti channel/nonaktif tidak mengirim ulang riwayat.

Invoice channel hanya memuat branding toko, referensi invoice, produk, jumlah,
nominal/metode, dan waktu WIB. Identitas pembeli, nomor, OTP/SMS, target sosial,
data login, modal provider, dan API key tidak dipublikasikan. Setelan dan antrean
tersimpan di SQLite. Unique source/entity, lease, dan penanda pengiriman mencegah
pengulangan dari worker/restart. Jika Telegram mungkin menerima foto tetapi
responsnya hilang, status UNKNOWN ditampilkan pada panel owner dan tidak diulang
buta. Tidak ada klaim exactly-once transport pada respons yang tidak pasti.

Migration **206** additive menambah payment_receipts.caption_hash dan outbox
transaction_channel_events; sistem wallet, deposit dan pembayaran tetap memakai
tabel existing. Hash caption menggunakan HMAC agar tidak menjadi kamus tebakan
OTP. Tidak ada command, runtime file, dependency, callback pembayaran, atau ENV baru.
Nama file runtime tetap sama; paket utama tetap 16 file langsung di root ZIP.

## Aturan QRIS manual existing (v17.25)


QRIS Manual pada /otp dan /sosmed ditampilkan dalam **satu foto beserta caption
invoice dan tombol**. Cek Pembayaran, Pesanan Saya, dan Kembali dari pengiriman
bukti membuka foto invoice yang sama. Pengiriman yang hasilnya belum pasti
tidak diulang otomatis. Nama file runtime dan paket ringkas tetap sama.

Semua QRIS manual — checkout /start, deposit, /otp, dan /sosmed — berlaku
**15 menit sejak invoice dibuat**. Tanggal ditampilkan dalam WIB. Tanpa bukti,
invoice kedaluwarsa, tombol pembayaran ditolak, stok checkout dilepas, dan QRIS
tercatat dihapus/dinonaktifkan. Worker membersihkan QRIS setiap siklus; tombol
lama juga memeriksa deadline di server. Restart dan klik ulang tidak memperpanjang
waktu atau mengganti kode unik invoice yang masih aktif.

**Bukti yang dikirim sebelum batas 15 menit menunggu konfirmasi owner tanpa
kedaluwarsa**, termasuk tombol di PM owner dan setelah restart. Reservasi stok
checkout tetap ditahan sampai keputusan/pembatalan. Kirim bukti bukan bukti
pembayaran sah secara otomatis: owner wajib memeriksa transfer sebelum menyetujui;
sebelumnya saldo tidak bertambah dan produk tidak diproses. Bukti terlambat ditolak.
Rekening transfer dan deadline gateway otomatis tetap mengikuti alur existing.

Pembelian langsung /otp dan /sosmed tetap menawarkan Saldo Bot dan QRIS Manual;
wallet existing dipakai bersama. Konfirmasi manual memakai topups dan ledger
existing secara atomik, dengan satu reservasi dan purchase attempt. Dana terlambat
yang diverifikasi owner untuk invoice OTP/SOSMED kedaluwarsa masuk ke saldo,
tanpa memesan produk dari invoice tersebut. Checkout produk yang kedaluwarsa
tanpa bukti tidak boleh dihidupkan kembali dari tombol lama. Jika uang sudah
terlanjur ditransfer, owner perlu memeriksa dan menyelesaikannya lewat saldo/refund
existing; uang tidak dihapus oleh timer.

Salin Nomor/OTP nyata, refund kegagalan definitif ke saldo, rekonsiliasi hasil
provider yang belum pasti, riwayat, invoice gambar sukses tunggal dan perlindungan
approval ganda dari v17.24 dipertahankan. Kode unik tidak termasuk saldo/refund harga
produk. Tidak ada transaksi provider live dalam pengujian rilis ini.

Migration **205** yang dipertahankan hanya menambahkan pelacakan pesan QRIS checkout pada orders dan
mengisi deadline invoice QRIS manual pending lama yang belum mengirim bukti,
berdasarkan tanggal pembuatan asal. Deadline/riwayat/bukti/saldo/ledger existing
dipertahankan; invoice yang sudah final tidak dihidupkan kembali otomatis. Tidak
ada wallet, deposit, command, dependency atau Railway Variables baru.

## Lokasi Cek MLBB

User: **/start → Belanja / List Produk → 🎮 Cek MLBB**.
Owner: **/owner → 🎮 Pengaturan MLBB** untuk status API, statistik, limit dan
aktif/nonaktif. Owner yang membuka lewat /start mendapat tampilan pemeriksaan
akun biasa; pengaturan tetap berada di /owner.

Tombol Cek MLBB dihapus dari menu /tools yang baru. Tombol pada pesan lama tetap
ditangani, dengan tujuan kembali ke daftar produk atau panel owner. Tombol
checker merupakan pintasan, tanpa menambah produk database, mengubah nomor
produk, urutan A–Z, stok, harga, wallet atau invoice. **Semua user dapat mengecek
tanpa VIP**, termasuk user yang VIP-nya habis dan owner. Batas harian, jeda cek,
pemeriksaan akun terblokir dan rate limit API tetap berlaku. Menu /tools kembali
seperti sebelum Cek MLBB ditambahkan; VIP Rp20.000/bulan untuk tools lama,
pembelian dan perpanjangannya tetap memakai alur existing. Tidak ada Variables, migration,
dependency atau command baru pada pembaruan MLBB. Schema checker 203 dipertahankan dalam migration 206 rilis ini.

## Cek MLBB: satu pesan untuk kedua ID

Buka **/start → Belanja → Cek MLBB → Mulai Cek**, lalu kirim **User ID dan Server ID sekaligus**:
`12345678 1234`, `12345678 (1234)`, atau `12345678(1234)`.
Bot langsung mengecek setelah kedua ID valid; tidak meminta Server ID lagi.
Input yang belum lengkap ditolak dengan contoh format, tanpa memakai kuota API.
Sesi versi lama yang sudah menunggu Server ID tetap dapat diselesaikan setelah
update. Limit, whitelist API, wallet dan pembayaran tetap memakai alur existing.
Tidak ada Variables, migration, dependency, command, atau file runtime baru.

## Status Weekly Elite / Monthly Epic

Status bundle tidak lagi ditetapkan selalu ⚠️ di tampilan. Jika respons resmi
`/mlbb-bonus-check` memuat baris `bonus_limit` berjudul **Weekly Elite Bundle** atau
**Monthly Epic Bundle** (nama tanpa akhiran Bundle juga dikenali), bot membaca
`reached_limit` boolean: `false` → ✅ tersedia, `true` → ❌ sudah digunakan.
Nilai hilang, bukan boolean, atau judul duplikat → ⚠️; status tiap paket berdiri
sendiri. First Top Up atau Weekly Diamond Pass tidak membuktikan status bundle.

[Dokumentasi ALU](https://aluu.in/docs), diperiksa 18 Oktober 2026, hanya menjelaskan
empat paket First Top Up; dukungan bundle belum dapat dibuktikan dari dokumentasi
atau akun live workspace. Pembacaan baris bundle tambahan diuji dengan **mock
kondisional**, bukan hasil API nyata. Bila API akun hanya mengirim empat paket,
kedua bundle tetap ⚠️ dengan keterangan data belum dapat diverifikasi. Centang
pada bot lain tidak membuktikan API ALU menyediakan data yang sama. Tidak ada
endpoint baru, request tambahan, atau pembelian game untuk mencoba eligibility.

## Perbaikan IP_NOT_ALLOWED pada ALU

API Key saja belum cukup untuk Name Check: IP keluar server wajib masuk whitelist
[profil akun ALU](https://aluu.in/docs). Buka **/owner → Pengaturan MLBB → Status API**.
Panel owner sekarang menampilkan IP yang benar-benar dilihat ALU, tombol **Salin IP
Server**, **Periksa Ulang**, dan **Periksa & Aktifkan**. Tambahkan IP itu ke whitelist,
simpan, lalu periksa ulang. Tidak ada Variables, schema, atau command baru.

Jika memakai [Static Outbound IP Railway](https://docs.railway.com/networking/static-outbound-ips),
daftarkan seluruh IP yang ditampilkan pada **service → Settings → Networking**;
Railway dapat memakai beberapa IP. Static Outbound IP tersedia pada plan Pro;
perubahan konfigurasi tersebut memerlukan redeploy. Pada koneksi dengan IP dinamis,
whitelist perlu diperbarui saat IP keluar berubah. Domain bot/IP perangkat pengguna
tidak menentukan IP keluar request API server.

Pemeriksaan biasa tetap dicache 60 detik; tombol Periksa Ulang dan aktivasi memeriksa
koneksi kembali dengan jeda minimal tiga detik. Cache lama diperbarui setelah update.
Bot tidak membuka whitelist ALU secara otomatis dan tidak menebak IP jika provider
tidak mengirimkannya. Alamat IP/diagnostik hanya terlihat di panel owner privat.

## Cek MLBB di /start

User membuka **/start → Belanja → 🎮 Cek MLBB → Mulai Cek**, lalu mengirim User ID dan Server ID
(Zone ID) dalam satu pesan. Pengecekan tersedia untuk semua user tanpa VIP,
termasuk non-VIP dan VIP kedaluwarsa; tidak ada pembelian paket atau potongan
saldo per cek. Pengaturan hanya dapat dibuka owner melalui /owner.

Adapter memakai [ALU API — Name Check](https://aluu.in/docs): nickname/negara dan bonus
top-up pertama dibaca melalui dua endpoint GET dengan header `x-api-key`.
`reached_limit=true` berarti bonus sudah digunakan; field yang hilang, ambigu, atau
gagal dibaca ditampilkan **⚠️**. Status Weekly Elite/Monthly Epic dibaca jika baris
bundle dikirim API; dokumentasi saat ini belum menjaminnya. Nama provider dan
konfigurasi hanya tampil kepada owner. Validasi nickname yang berhasil tidak
dianggap membuktikan bonus/bundle ketika pengecekan bonus gagal.

Railway: tambahkan **MLBB_API_KEY** dari akun ALU, whitelist IP keluar server pada
dashboard API, lalu **/owner → Pengaturan MLBB → Status API → Kembali → Aktifkan**.
Jangan kirim key melalui Telegram atau masukkan ke GitHub. Default fitur nonaktif.
Semua Variables baru ada di `.env.example`: `MLBB_ENABLED=false`,
`MLBB_HTTP_TIMEOUT_SECONDS=12`, `MLBB_CACHE_SECONDS=60`, `MLBB_DAILY_LIMIT=20`,
`MLBB_COOLDOWN_SECONDS=10`; selain key, nilainya opsional. Toggle/limit owner disimpan
di SQLite dan mengutamakan pengaturan owner yang sudah tersimpan.

Kuota API mengikuti akun provider, berbeda dari limit user bot. Satu cek memakai
hingga dua request; menu Status API juga memakai kuota dan dicache 60 detik.
Batas harian user reset pukul 00.00 WIB. Owner dapat mengatur limit, melihat statistik,
dan menonaktifkan akses user. Cache hasil singkat, timeout dan batas request mencegah
spam. User ID/Zone ID hanya diteruskan ke endpoint tetap, tanpa mengambil URL input.
Schema **203** menambahkan pencatatan pemakaian checker; tabel VIP/wallet tidak diubah.

Pengujian memakai mock API. Koneksi akun/kuota dan hasil akun MLBB nyata tetap harus
divalidasi setelah key dan whitelist dipasang; rilis tidak mengklaim uji live.

## Voucher khusus produk

Buka **/owner → Pelanggan → Promo & Voucher → Voucher → Buat Voucher**.
Pilih produk A–Z, isi kode dan ketentuan, lalu periksa dan **Simpan Voucher**.
Voucher baru hanya berlaku pada produk terpilih, termasuk varian aktifnya.
Produk lain ditolak sebelum invoice dibuat atau saldo dipotong.

Voucher lama tetap tersimpan. Untuk menentukan produknya, buka **Daftar & Atur
Produk → pilih kode → Atur Produk Voucher → pilih produk → konfirmasi**.
Voucher lama yang global tetap global sampai owner memilih produknya; bot tidak
menebak produk tujuan. Invoice yang sudah dibuat mempertahankan harga dan voucher
yang telah tercatat. Pengaturan baru berlaku untuk checkout baru.

Jika voucher ditolak, klik **Ganti Voucher** atau **Lanjut Tanpa Voucher**.
Klik pembayaran berulang tidak otomatis mengubahnya menjadi harga penuh.
Kuota ditahan oleh invoice pending dan dilepas saat dibatalkan/kedaluwarsa sesuai
metode pembayaran; pemakaian dicatat sekali saat pembayaran sah. Masa aktif tampil
dalam WIB. Tidak ada Variables, migration, atau file runtime baru; schema tetap 202.

## Daftar produk A–Z

Daftar /start, Produk Populer, Flash Sale, laporan stok, Atur Produk, Atur Harga,
Atur Stok, Hapus Stok/Produk, pencarian dan pilihan produk terkait memakai urutan
nama A–Z yang sama. Varian diurutkan berdasarkan namanya. Huruf besar/kecil dan
spasi di awal/akhir tidak mengubah urutan; nama asli tetap ditampilkan.
Nomor pilihan mengikuti daftar yang dilihat user dan tetap terikat ke ID produk,
termasuk saat berpindah halaman atau nama produk diubah. Harga, stok, filter,
pembayaran dan riwayat memakai data existing. Schema tetap **202**; tidak ada
Variables atau file runtime baru.

## VIP /tools Rp20.000 per bulan

User membuka **/tools → VIP → Bayar Saldo atau QRIS Otomatis**, lalu konfirmasi.
Saldo memakai wallet bot existing; QRIS memakai gateway existing dan biaya akhirnya
terlihat sebelum dibayar. VIP aktif setelah pembayaran terverifikasi, mendapat
invoice gambar sekali, lalu mengikuti rating pembelian existing.

Masa aktif **satu bulan kalender dalam WIB**. Setelah habis, akses otomatis kembali
normal, termasuk ketika user sedang menjalankan form /tools. Tidak ada perpanjangan
atau potongan saldo otomatis. Membeli perpanjangan sebelum habis menambah satu bulan
dari tanggal berakhir; membeli setelah habis dihitung dari waktu aktivasi baru.
Akses permanen yang diberikan owner sebelumnya tetap mengikuti pengaturan owner.

Schema **202** menambah riwayat pembelian VIP dan masa aktif secara additive.
Harga tetap Rp20.000; tidak ada Variables atau file runtime baru. Pertahankan
database, Volume, konfigurasi /tools, serta gateway existing saat redeploy.

## Setelah QRIS berhasil dibayar

QRIS otomatis diganti menjadi **satu invoice gambar pembayaran berhasil** pada
pesan yang sama. Salinan QRIS lain dibersihkan. Notifikasi teks pembayaran sukses
yang berulang dihapus khusus QRIS Otomatis; pengiriman produk tetap berjalan.
ID pesan dan antrean invoice tersimpan agar webhook berulang/restart tidak
menggandakan invoice. Jika hasil kirim gambar baru tidak pasti, bot tidak mengirim
ulang otomatis; owner dapat memeriksanya di rincian Riwayat Transaksi.

Schema **201** pada rilis sebelumnya menambah tabel pencatatan pesan QRIS; data wallet/invoice lama
dipertahankan. Tidak ada Variables baru. Untuk QRIS checkout dari versi lama yang
belum menyimpan ID pesan, tekan **Cek Status** pada pesan tersebut satu kali setelah
update agar bot mengenali dan membersihkannya. Pesan sukses lama yang sebelumnya
tidak dicatat tidak dapat dihapus otomatis dari riwayat Telegram.

## QRIS langsung bersama invoice

Saat user memilih **⚡ QRIS Otomatis** untuk isi saldo atau checkout, gambar QRIS
langsung dikirim bersama nomor invoice, nominal, biaya, total dan waktu WIB.
Tombol **Tampilkan QRIS** dihapus. **Cek Status** juga menampilkan kembali QRIS
invoice yang sama selama masih menunggu pembayaran, termasuk setelah pemulihan
invoice tertunda atau kegagalan pengiriman gambar. Tidak membuat tagihan baru.
Invoice yang sudah dibayar menampilkan invoice sukses yang sama tanpa kirim
ulang; invoice kedaluwarsa atau dibatalkan menampilkan status.

## Pemeriksaan gateway untuk akun baru

Gunakan **/owner → Pengaturan Pembayaran → QRIS Otomatis → Aktifkan KlikQRIS**.
Aktivasi gateway biasa mengizinkan pembuatan invoice pertama dengan konfigurasi
yang sudah diisi. Tidak perlu riwayat, ID uji atau transaksi percobaan. Status API
awal **Menunggu invoice pertama**; API dinyatakan terverifikasi setelah respons
pembuatan QRIS nyata lolos pemeriksaan referensi, nominal dan signature.

User memilih /start → Isi Saldo → ⚡ QRIS Otomatis. Saldo masuk setelah pembayaran
invoice asli dan nominalnya diverifikasi melalui API; membuat QRIS tidak menambah
saldo. Cek Koneksi memakai invoice nyata yang tersimpan atau riwayat bila tersedia.
Riwayat HTTP 404 tidak menghalangi aktivasi. Tidak ada Variables baru.

## Perbaikan aktivasi KlikQRIS

Di Railway, kolom **Name** diisi `KLIKQRIS_WEBHOOK_URL`; kolom **Value** cukup URL:
`https://DOMAIN_BOT_ANDA/webhooks/klikqris`. Jangan menempelkan `NAMA_VARIABEL=`
di kolom Value. Format tempelan seperti pada laporan sebelumnya kini dikenali,
termasuk kutip pembungkus. API Key/Merchant ID tetap tidak ditampilkan di Telegram.

Buka **/owner → Pengaturan Pembayaran → QRIS Otomatis → Aktifkan KlikQRIS**.
API gateway dibuktikan melalui invoice nyata. Aktivasi tidak membuat tagihan percobaan.
Error konfigurasi menyebut variabel yang perlu diperbaiki, dan kegagalan API
tetap terlihat di panel. Tidak ada Variables atau file runtime baru; schema 201 sebelumnya
menambahkan pencatatan pesan QRIS. Mode MY PG tetap memerlukan merchant terhubung
yang terverifikasi.

## Prioritas rating pembelian

Setelah produk dikirim, SMS OTP diterima, Sosmed selesai, atau aktivasi /tools
berhasil, user memilih **1–5 bintang** sebelum membuka fitur lain atau membeli lagi.
Rating rendah tetap diterima; komentar tertulis opsional. Jika ada beberapa transaksi
yang selesai, rating ditampilkan bergantian. Antrean tersimpan setelah restart;
transaksi lama yang sudah selesai sebelum update tidak dipaksa rating ulang.

Status pembayaran, bukti bayar invoice berjalan, kode OTP/resend/selesai, pembatalan,
riwayat pesanan dan bantuan tetap dapat diakses. Webhook, polling, kredit saldo,
refund dan pengiriman berjalan tanpa menunggu rating. Order pending/gagal/partial
dan isi saldo tidak memicu kewajiban rating. Panel administrasi owner tetap bisa
digunakan; tampilan owner dibatasi ke chat privat. User tidak mendapat tombol admin.

Menu rating memakai pesan yang sama saat user mencoba berpindah fitur. Setelah
rating tersimpan, menu terbuka kembali. Tidak ada file runtime atau Variables baru
untuk fitur rating; gunakan seluruh 16 file rilis v17.29 yang konsisten.

## Jalankan

Python 3.12. Install `pip install -r requirements.txt`, lalu `python main.py`.
Railway: Start Command `python main.py`, health `/health`, satu replica.
Pasang Volume `/data`; Variables `DB_PATH=/data/shop.db`, `BACKUP_DIR=/data/backups`.
Pertahankan database, token, konfigurasi pembayaran, dan kunci enkripsi existing.
Hentikan poller lama sebelum menggunakan token yang sama pada Railway baru.

## Command

`/start` · `/otp` · `/sosmed` · `/tools` · `/owner` · `/ping`.
`/sosmed` membuka panel owner untuk owner dan toko pembeli untuk user.
Owner bisa memilih **Menu Pembeli** untuk belanja memakai wallet pribadinya.
Saldo user dipakai bersama oleh toko, OTP, dan Sosmed.

Pembelian baru **/otp dan /sosmed memakai saldo bot atau QRIS Manual** melalui
konfirmasi pembelian. QRIS manual menggunakan topups, bukti transfer dan approval
owner existing; tanpa membuat deposit/wallet baru. Metode otomatis tidak dibuka
untuk pembelian langsung kedua toko tersebut. Isi Saldo dan checkout produk lain
mempertahankan QRIS Otomatis, QRIS Manual, transfer bank dan gateway existing.

Invoice QRIS OTP lama tetap diproses sesuai status dan kebijakan sebelumnya.
Khusus invoice manual baru v17.29, tidak ada deadline konfirmasi owner dan berlaku
refund harga produk ke wallet jika gagal pasti; hasil timeout tidak dikreditkan
ulang sebelum direkonsiliasi. Tidak ada pembelian provider sebelum pembayaran
manual diverifikasi owner. API key dan saldo provider hanya tampil kepada owner.

## Harga dan layanan Sosmed

Modal & Jual berisi 6 layanan per halaman, nama singkat, dan tarif **per 1.000**.
Owner melihat modal terendah dulu; user melihat harga jual terendah dulu.
Pilih Kategori dan Refresh Layanan memakai katalog asli provider. Menu user
menyediakan pintasan **TikTok** dan **Instagram**, lalu kategori yang benar-benar
tersedia; platform kosong tidak dibuatkan layanan fiktif.
Tarif `price`/`rate` dibaca dengan Decimal tanpa dikalikan 1.000 saat sinkronisasi;
kolom yang bertentangan dinonaktifkan. Modal pecahan rupiah tampil tepat pada owner.
Modal order = tarif API × jumlah ÷ 1.000. Harga jual tetap mengikuti pengaturan
markup, minimum transaksi dan pembulatan existing. Buka detail layanan →
**Rincian Harga** untuk memeriksa penyebab harga jual; pengaturan tidak direset.
Detail user menyebut harga pembelian minimum, dan konfirmasi tetap memakai
jumlah nyata. Price sorting/refresh tidak mengurangi wallet atau membuat order.

Tombol **Cari Layanan** tersedia di menu awal user/owner, kategori, TikTok/Instagram,
Modal & Jual, daftar layanan dan favorit. Ketik kata kunci seperti
`followers`/`likes`; kategori/platform/favorit yang sedang dibuka tetap dipakai.
Owner mendapat hasil Modal & Jual. Gunakan **Hapus Pencarian** untuk kembali
ke daftar tanpa kata kunci/filter. Kembali dan Menu Awal tersedia pada form cari.

Menu kategori memiliki **Cari Kategori** di atas daftar. Ketik nama/kata kunci,
misalnya `follower`, `likes`, atau `livestream`, lalu pilih kategori hasil pencarian.
TikTok/Instagram tetap membatasi hasil ke platform yang dipilih. Daftar berisi
8 kategori per halaman; Kembali dari layanan mempertahankan pencarian dan halaman.
**Hapus Pencarian Kategori** menampilkan kembali daftar kategori pada platform yang
sama. Pencarian ini tersedia juga pada kategori harga dan markup owner.

## Waktu dan invoice foto

Semua waktu tampilan memakai **WIB (Asia/Jakarta)**: transaksi, kedaluwarsa,
riwayat, rekening, OTP, Sosmed, pemeriksaan API, dan laporan harian.
Timestamp internal tetap dipakai sesuai sistem existing; tidak perlu variabel `TZ` baru.
Pembayaran berhasil mengirim invoice PNG privat untuk produk, isi saldo, OTP,
dan Sosmed. Nominal, metode, invoice dan waktu berasal dari pembayaran nyata;
isi saldo memisahkan saldo masuk dengan total transfer/kode unik.
Invoice tersimpan dalam antrean SQLite, dilindungi lease, dan dicoba ulang
setelah gagal/restart. Gagal mengirim foto tidak membatalkan pembayaran atau
menambah saldo kembali. Transaksi lama tidak dikirim massal setelah update.
Telegram belum menjamin pengiriman tepat sekali jika respons sukses hilang.
Tidak ada variabel atau dependency baru; `payment_receipts.py` wajib ikut diupload.

## Rekening transfer

Buka `/owner` → Pengaturan Pembayaran → Rekening Transfer. Tambah/edit bank, nomor,
pemilik, dan catatan; periksa data lama/baru lalu tekan Simpan. Rekening dapat
aktif/nonaktif, dijadikan utama, atau dihapus dari daftar dengan soft delete.
Menu rekening ringkas dalam empat baris. Tambah/Edit membuka form bertahap dengan
tombol Kembali/Batal; input mengganti pesan form yang sama sebelum konfirmasi.
User memilih rekening aktif ketika deposit/checkout. Invoice menyimpan rekening
dan nomor salin sendiri; perubahan rekening tidak mengubah snapshot invoice.
Tidak ada variabel baru atau wallet baru untuk multi-rekening.

## Konfirmasi pembayaran manual

Invoice **QRIS Manual dan Transfer Rekening** untuk pembelian maupun isi saldo
menunggu keputusan owner **tanpa batas waktu kedaluwarsa**. Tampilan user/owner
tidak memakai hitung mundur. Invoice pending lama dinormalisasi saat startup;
timer, cleanup expired, dan restart tidak menutup invoice manual yang menunggu.
Mode AUTO yang diaktifkan kemudian tidak mengubah metode invoice manual lama.

Owner tetap memakai tombol **Konfirmasi / Tolak / Tandai Pending** yang existing.
Invoice manual lama yang terlanjur expired bisa dikonfirmasi owner jika belum
dibatalkan, selesai, dibayar atau ditolak. Transaksi tidak dihidupkan ulang otomatis.
Stok/slot yang reservasinya pernah dilepas diperiksa ulang agar tidak mengambil
reservasi pembeli lain. Jika belum tersedia, pembayaran tercatat PAID dan menunggu
pemenuhan. Konfirmasi ganda aman; pembayaran/log atau kredit wallet disimpan atomik.
User/owner tetap dapat membatalkan invoice yang belum dibayar lewat alur existing.

Payment gateway otomatis tetap mengikuti masa berlaku existing/provider.
Quote harga, nomor/SMS OTP, draft pengaturan rekening dan konfirmasi Hapus Stok
tetap menggunakan masa berlaku yang sesuai; perubahan ini hanya untuk pembayaran
manual yang memerlukan owner. OTP/Sosmed juga menyediakan QRIS Manual di konfirmasi pembelian sejak v17.29.
Tidak ada Variables/dependency/command baru.

## Hapus stok owner

**/owner → Produk & Stok → Hapus Stok → Produk → Varian → Jumlah → Konfirmasi**.
Tombol juga tersedia di **Atur Stok → Varian**. Pilih 1/5/10, jumlah custom,
atau semua stok bebas (maksimal 10.000 per proses). Pilihan produk/varian memakai
8 item per halaman. Kembali/Batal tersedia; custom input mengganti pesan form.
Stok terbaru yang ditambahkan dipilih. Akun yang terjual/dialokasikan, akun
terhubung ke order, dan jumlah reservasi aktif dilindungi. Konfirmasi menyimpan
ID akun dan berlaku 10 menit; perubahan stok/reservasi memerlukan konfirmasi ulang.
Klik ganda/restart tidak menghapus akun lain. Akun ditandai `removed`, dikeluarkan
dari penjualan, dan dicatat pada Riwayat Stok/audit tanpa menghapus riwayat order.
Fitur ini khusus stok akun ready; alur slot Pre-Order/Famhead tetap memakai
pengaturan existing. Wallet, pembayaran dan alur OTP/Sosmed tidak diubah.

## Variabel

Isi `BOT_TOKEN` dan `ADMIN_ID` numerik melalui Railway Variables; daftar contoh ada di `.env.example`.
Sosmed memerlukan **BUZZERPANEL_API_KEY** dan **BUZZERPANEL_SECRET_KEY**.
Endpoint: `BUZZERPANEL_API_URL=https://buzzerpanel.id/api/json.php`.

Sesudah upload, ketik **`/sosmed`** sebagai owner. Gunakan tombol **Status API**
untuk memeriksa koneksi, lalu **Periksa & Buka Toko** untuk mengaktifkan toko.
Tombol berubah menjadi **Tutup Toko** saat aktif. Bot memeriksa profile/services
tanpa membuat order. Semua kontrol ini tersedia dalam menu yang sama.
Status API sekarang memeriksa koneksi saat dibuka, bukan hanya hasil terakhir.
Katalog besar kini dibaca bertahap melalui file sementara dengan batas khusus
64 MiB; decode berjalan pada worker. Respons order/profil tetap memakai batas lama.
Jika katalog gagal, saldo profil yang berhasil dibaca tetap tampil pada owner.
Validasi dilakukan per layanan: angka bulat seperti `100.0` dibaca dengan tepat,
duplikat identik digabung, dan entri invalid/ID konflik tidak dijual. Layanan valid
tetap diproses. Buka **Status API → Rincian Katalog** untuk ID, min/max, alasan
penolakan, serta jumlah layanan yang valid. Seluruh data invalid tetap menghentikan
pembelian; batas pecahan/format ambigu tidak dipaksakan menjadi jumlah.
Status menyebut **Profil/Katalog**, HTTP, dan penyebab yang aman: key ditolak,
izin IP, format respons, atau field saldo/harga yang perlu diperbaiki.
Saldo provider membaca `balance`/`saldo`; nilai hilang/bertentangan tidak dianggap nol.
Field pribadi pada Profile tidak ditampilkan dalam panel.
Katalog standar `id/price/note` tanpa `type` memakai form target + jumlah sesuai API;
catatan `note` tampil sebagai panduan username/URL. Layanan khusus yang belum jelas
bisa diatur owner: Modal & Jual → pilih layanan → **Tipe/Input** → konfirmasi.
Status `Success` berarti selesai; `Error` berarti gagal dengan refund saldo otomatis.
Daftar layanan user/owner berisi **6 pilihan per halaman**, dengan Sebelumnya,
Berikutnya, detail, dan **Refresh Layanan**. Refresh memperbarui harga, min/max,
catatan dan ketersediaan dari API; katalog juga diperbarui mengikuti TTL existing.
Harga/min/max tetap diperiksa ulang sebelum pembayaran. Wallet tidak berubah
karena membuka halaman atau memakai Refresh.
Verifikasi berhasil tersimpan di database dan bertahan setelah restart;
`SOSMED_API_CONTRACT_VERIFIED=true` tidak wajib untuk alur tombol ON ini.

Default `SOSMED_ENABLED=false` hanya untuk kondisi awal; pengaturan ON owner yang
tersimpan diprioritaskan. Kontrak refill/status_refill mengikuti pemeriksaan akun
pada tombol Status API; flag legacy `SOSMED_REFILL_API_VERIFIED=false` tidak
mengalahkan hasil verifikasi tersimpan atau keputusan Jeda Refill owner.
Jika Profile tidak menyebut mata uang, buka **Status API → Mata Uang & Satuan**:
konfirmasi **IDR** setelah saldo akun bertanda Rp, dan **/ 1.000** setelah kolom
harga layanan menyatakan tarif per 1.000. Kedua konfirmasi terpisah, tersimpan,
dan tidak memakai nilai saldo pada foto. Lalu tekan **Periksa & Buka Toko**.
Harga per 1.000 yang belum diketahui perlu dicek pada daftar layanan provider.
Alternatif Variables existing: `BUZZERPANEL_CURRENCY=IDR`, `SOSMED_RATE_UNIT=1000`;
keduanya opsional bila API/konfirmasi owner sudah menyebutnya. Nilai eksplisit API
tetap diperiksa, dan pergantian akun API memerlukan konfirmasi baru.
Cancel dan tipe yang belum didokumentasikan tidak diaktifkan.

OTP tetap memakai Variables existing; jika webhook digunakan, alamatnya
`https://DOMAIN_BOT_ANDA/webhooks/smscode/otp`.

## Isi paket

Sepuluh file Python aktif: `main.py`, `bot.py`, `otp_smscode.py`,
`sosmed_buzzerpanel.py`, `sosmed_ui.py`, `project_backup.py`, `bank_accounts.py`,
`payment_receipts.py`, `klikqris_gateway.py`, `bot_api.py`.
File pendukung: `requirements.txt`, `README.md`, `.env.example`, `.gitignore`,
`.python-version`, `railway.json`.

Tes, fixture bot lama, log, database, arsip backup, dan dokumentasi panjang
tersedia di paket lengkap/backup terpisah. Kode runtime sama dengan rilis
v17.29; hasil verifikasi dan backup tersedia dalam laporan rilis terpisah.

Backup penuh: `python project_backup.py --help`. Simpan arsip dan kunci di luar
project, terpisah dan privat; sertakan volume/DB yang benar-benar tersedia.
Restore ke lokasi baru dahulu; jangan menimpa database produksi dengan snapshot lama.
Jangan upload `.env` asli, database, session, backup privat, atau kunci ke GitHub.


Footer toko pada v17.29: **Maboyy Digital • Since 2020**.
Perubahan footer mempertahankan tombol dan alur pembayaran existing.

## Refill Sosmed

Owner membuka **/sosmed → Status API**: pemeriksaan profile/katalog berhasil
menyimpan kontrak `refill`/`status_refill` untuk akun yang sama. Buka **Status Refill**
untuk daftar 4 pengajuan per halaman, cek status, atau Jeda/Aktifkan Refill.
Tidak ada command/Variables baru dan pemeriksaan ini tidak membuat refill percobaan.
User membuka pesanan selesai → **Request Refill → Ajukan Refill**. Jika katalog
tidak memberi flag refill, kelayakan ditentukan saat pengajuan; flag tidak mendukung
tetap ditolak. Refill mengikuti ketentuan layanan dan tidak memotong saldo bot.
Tombol **Cek Status Refill**/Refresh Pesanan serta worker memperbarui status
melalui ID refill yang benar, termasuk saat toko/pengajuan baru dijeda.
Timeout/hasil tidak pasti tidak diajukan ulang otomatis. Tanpa ID refill, owner
perlu memeriksa pengajuan di akun provider sebelum mengambil tindakan lanjutan.
Kegagalan refill tidak mengubah order asli atau menambah refund saldo.


## QRIS Otomatis KlikQRIS

Variables baru: `KLIKQRIS_API_KEY`, `KLIKQRIS_MERCHANT_ID`; mode awal
`KLIKQRIS_MODE=gateway`, `KLIKQRIS_ENABLED=false`, `KLIKQRIS_SANDBOX=false`.
Buka **/owner → Pengaturan Pembayaran → QRIS Otomatis → Aktifkan KlikQRIS**.
Pemeriksaan koneksi membaca API, tanpa membuat transaksi. QRIS manual, transfer
rekening dan ShopeePay existing dipertahankan. User hanya melihat **⚡ QRIS Otomatis**.
Webhook: `https://DOMAIN_BOT_ANDA/webhooks/klikqris`; atur pada dashboard KlikQRIS.
Opsional `KLIKQRIS_WEBHOOK_URL`; bila kosong memakai PUBLIC_BASE_URL existing.
Polling tetap memantau pembayaran bila webhook terlambat. Provider `total_amount`
menjadi total final; kode unik manual tidak ditambahkan. Fee/penyesuaian ditampilkan.
Signature callback dicocokkan dengan signature invoice. Pembukuan selalu memerlukan
status, referensi dan nominal dari API resmi; polling memakai pemeriksaan API yang
sama. Screenshot tidak dapat menyetujui pembayaran otomatis.

MY PG tetap nonaktif sampai merchant terhubung. Pemilihan mode MY PG meminta ID
transaksi MY PG yang sudah ada untuk pemeriksaan API read-only; tidak memakai
session/cookie Shopee. API publik tidak menyediakan endpoint status koneksi merchant
khusus. Tanpa bukti tersebut, gunakan gateway biasa/manual.
Sandbox hanya untuk pengujian terisolasi; tidak dapat mengkredit wallet/produk nyata.
Jika create timeout, invoice tidak dibuat ulang otomatis. Gunakan Cek Status atau
Rekonsiliasi owner. Pembayaran setelah pembatalan masuk pemeriksaan owner; pilihan
Pindahkan ke Saldo memerlukan konfirmasi, bukti API dan ledger idempotent.
Pembayaran normal dan pemindahan tersebut memakai antrean invoice foto existing.
Tidak ada endpoint cancel/refund provider yang dikarang. Backup helper lama tetap
mencakup seluruh project; jangan upload database, .env, kunci atau backup ke GitHub.
