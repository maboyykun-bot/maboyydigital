"""Private payment-photo outbox; reads confirmed host payments, never moves money."""
import asyncio
import hashlib
import hmac
import html
import io
import json
import logging
import math
import re
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from aiogram.types import BufferedInputFile, InputMediaPhoto
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter
from PIL import Image, ImageDraw, ImageFont

WIB = ZoneInfo("Asia/Jakarta")
SOURCES = ("order", "topup", "otp_payment", "otp_order", "sosmed", "sosmed_payment", "qris_review")
STORE_SOURCES = frozenset({"otp_order", "otp_payment", "sosmed", "sosmed_payment"})


def display_datetime(value):
    """Interpret historical naive Railway dates as UTC, only for display."""
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, datetime):
            result = value
        elif isinstance(value, (int, float)) or re.fullmatch(r"\d{10,13}(?:\.\d+)?", str(value).strip()):
            stamp = float(value)
            if not math.isfinite(stamp):
                return None
            if abs(stamp) >= 100_000_000_000:
                stamp /= 1000  # Provider timestamps can be milliseconds.
            result = datetime.fromtimestamp(stamp, timezone.utc)
        else:
            raw = str(value).strip()
            result = datetime.fromisoformat(raw[:-1]+"+00:00" if raw.endswith("Z") else raw)
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def format_wib(value, *, seconds=False, compact=False, missing="-"):
    result = display_datetime(value)
    if result is None:
        return missing
    pattern = "%d/%m/%Y • %H:%M" if compact else "%d-%m-%Y %H:%M"
    if seconds:
        pattern += ":%S"
    return result.astimezone(WIB).strftime(pattern+" WIB")


def public_text(value, limit=380):
    """Invoice labels contain no provider links, markup, OTP or login data."""
    value = re.sub(r"https?://\S+", "", str(value or ""), flags=re.I)
    value = re.sub(r"\b(?:smscode\s*\.\s*gg|buzzer\s*panel(?:\s*\.\s*id)?)\b", "", value, flags=re.I)
    return " ".join(value.split()).strip(" •|-/")[:limit] or "-"


def rupiah(value):
    return "Rp"+f"{int(value):,}".replace(",", ".")


def method_label(value):
    return {"QRIS_MANUAL": "QRIS", "AUTO_QRIS": "QRIS Otomatis",
            "KLIKQRIS_AUTO": "⚡ QRIS Otomatis",
            "QRIS": "QRIS", "BALANCE": "Saldo Bot", "SALDO": "Saldo Bot",
            "WALLET": "Saldo Bot", "BANK": "Transfer Bank", "TRANSFER": "Transfer Bank",
            "BANK_TRANSFER": "Transfer Bank",
            "SHOPEEPAY": "QRIS Otomatis"}.get(str(value or "").upper(), public_text(value, 80))


def font(size, bold=False):
    filename = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    for path in ("/usr/share/fonts/truetype/dejavu/"+filename, filename):
        try:
            return ImageFont.truetype(path, size=size)
        except OSError:
            pass
    return ImageFont.load_default(size=size)


def wrapped(draw, value, face, width):
    lines, current = [], ""
    for word in str(value).split():
        probe = (current+" "+word).strip()
        if draw.textlength(probe, font=face) <= width:
            current = probe
            continue
        if current:
            lines.append(current)
        current = ""
        for char in word:
            if current and draw.textlength(current+char, font=face) > width:
                lines.append(current)
                current = ""
            current += char
    if current:
        lines.append(current)
    return lines or ["-"]


def render_invoice(snapshot, *, simulation=False, inactive=False):
    """One layout for products, deposits, OTP and Sosmed; return a PNG in memory."""
    value = dict(snapshot)
    amount = int(value["amount"])
    if amount <= 0:
        raise ValueError("A successful payment must have a positive amount")
    title, label_face, face, small = font(42, True), font(24, True), font(25), font(21)
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    rows = [("Invoice", public_text(value["reference"], 90)),
            ("Pembayaran", public_text(value.get("category", "Pembelian"), 80)),
            ("Pelanggan", public_text(value.get("customer", "-"), 80)),
            ("Waktu", format_wib(value.get("paid_at"), seconds=True)),
            ("Layanan / Produk", public_text(value.get("item", "-"))),
            ("Jumlah", public_text(value.get("quantity", "1"), 60)),
            ("Metode", method_label(value.get("method")))]
    if value.get("variant"):
        rows.insert(5, ("Variasi", public_text(value["variant"], 180)))
    if value.get('vip_until'):
        rows.append(('VIP aktif hingga',format_wib(value['vip_until'])))
    if value.get("subtotal"):
        rows.append(("Subtotal", rupiah(value["subtotal"])))
    if value.get("discount"):
        rows.append(("Diskon", "-"+rupiah(value["discount"])))
    if value.get("unique_code"):
        rows.append(("Kode unik", "+"+str(int(value["unique_code"]))))
    if value.get("qris_adjustment"):
        rows.append(("Biaya/penyesuaian QRIS", rupiah(value['qris_adjustment'])))
    if value.get("credit"):
        rows.append(("Saldo masuk", rupiah(value["credit"])))
    measured = [(label, wrapped(probe, data, face, 540)) for label, data in rows]
    detail_height = 88+sum(max(56, len(lines)*37+18) for _, lines in measured)
    total_y = 274+detail_height+24
    height = total_y+230
    img = Image.new("RGB", (1080, height), "#edf1f8")
    draw = ImageDraw.Draw(img)
    draw.rectangle((0, 0, 1080, 236), fill="#15223b")
    draw.rectangle((0, 236, 1080, 242), fill="#8158ef")
    draw.text((56, 38), "MABOYY DIGITAL", font=title, fill="white")
    draw.text((56, 103), "INVOICE PEMBAYARAN", font=font(29), fill="#c4cbda")
    draw.rounded_rectangle((56, 157, 390, 211), radius=16, fill="#b42335" if inactive else "#16834c")
    draw.text((78, 167), "INVOICE HANGUS" if inactive else "PEMBAYARAN BERHASIL", font=font(22, True), fill="white")
    if simulation:
        draw.rounded_rectangle((803, 49, 1022, 103), radius=14, fill="#fbbf24")
        draw.text((826, 61), "SIMULASI", font=font(25, True), fill="#15223b")
    draw.rounded_rectangle((48, 274, 1032, 274+detail_height), radius=23, fill="white")
    draw.text((76, 300), "RINGKASAN TRANSAKSI", font=font(26, True), fill="#15223b")
    y = 362
    for label, lines in measured:
        draw.text((76, y), label, font=label_face, fill="#64748b")
        for index, line in enumerate(lines):
            draw.text((438, y+index*37), line, font=face, fill="#15223b")
        y += max(56, len(lines)*37+18)
    draw.rounded_rectangle((48, total_y, 1032, total_y+108), radius=23, fill="#15223b")
    draw.text((76, total_y+37), "TOTAL DIBAYAR", font=font(26, True), fill="#c4cbda")
    total = rupiah(amount)
    total_face = font(40, True)
    draw.text((996-draw.textlength(total, font=total_face), total_y+28), total, font=total_face, fill="white")
    draw.text((56, total_y+135), "Terima kasih telah berbelanja di Maboyy Digital.", font=small, fill="#475569")
    footer = "CONTOH • DATA SIMULASI, BUKAN BUKTI PEMBAYARAN" if simulation else "Bukti pembayaran • Semua waktu dalam WIB"
    draw.text((56, total_y+173), footer, font=font(19, True), fill="#8158ef")
    output = io.BytesIO()
    img.save(output, "PNG", optimize=True)
    return output.getvalue()


def init_schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS payment_receipts(
        source TEXT NOT NULL,entity_id TEXT NOT NULL,user_id INTEGER NOT NULL,
        snapshot_json TEXT NOT NULL DEFAULT '{}',status TEXT NOT NULL DEFAULT 'PENDING',
        attempts INTEGER NOT NULL DEFAULT 0,next_retry_at REAL NOT NULL DEFAULT 0,
        lease_token TEXT,lease_until REAL NOT NULL DEFAULT 0,message_id INTEGER,sent_at REAL,
        error_code TEXT,created_at REAL NOT NULL,PRIMARY KEY(source,entity_id))""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payment_receipts_queue ON payment_receipts(status,next_retry_at,lease_until)")
    conn.execute("CREATE TABLE IF NOT EXISTS payment_receipt_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
    conn.execute("""CREATE TABLE IF NOT EXISTS transaction_channel_events(
        source TEXT NOT NULL,entity_id TEXT NOT NULL,channel_id TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'PENDING',
        attempts INTEGER NOT NULL DEFAULT 0,next_retry_at REAL NOT NULL DEFAULT 0,
        lease_token TEXT,lease_until REAL NOT NULL DEFAULT 0,message_id INTEGER,
        created_at REAL NOT NULL,sent_at REAL,error_code TEXT,
        PRIMARY KEY(source,entity_id))""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_transaction_channel_queue ON transaction_channel_events(status,next_retry_at,lease_until)")
    if 'caption_hash' not in {row[1] for row in conn.execute('PRAGMA table_info(payment_receipts)')}:
        conn.execute("ALTER TABLE payment_receipts ADD COLUMN caption_hash TEXT NOT NULL DEFAULT ''")
    first = conn.execute("INSERT OR IGNORE INTO payment_receipt_meta VALUES('initialized','16.99')").rowcount
    if first:
        # Past transactions already had text confirmations. Do not flood buyers
        # with their history after deployment; unfinished deposits remain eligible.
        old = {
            "order": "SELECT id,user_id FROM orders WHERE payment_status='paid' AND invoice_sent=1",
            "topup": "SELECT id,user_id FROM topups WHERE status='completed'",
            "otp_payment": "SELECT payment_id,user_id FROM otp_payments WHERE paid_at IS NOT NULL",
            "otp_order": "SELECT id,buyer_user_id FROM otp_orders",
            "sosmed": "SELECT id,user_id FROM sosmed_orders",
        }
        for source, sql in old.items():
            conn.execute("""INSERT OR IGNORE INTO payment_receipts(source,entity_id,user_id,status,created_at)
                SELECT ?,CAST(id AS TEXT),user_id,'LEGACY',? FROM ("""+
                sql.replace("payment_id,user_id", "payment_id AS id,user_id").replace("id,buyer_user_id", "id,buyer_user_id AS user_id")+
                ")", (source, time.time()))


class ReceiptService:
    def __init__(self, host):
        self.host = host
        self._worker = None
        self._caption_key=str(getattr(host,'BOT_TOKEN','')).encode() or secrets.token_bytes(32)
        self.channel=TransactionChannel(self)

    def store_key(self, source, entity, user=None):
        """Use one receipt for a product and its linked manual payment."""
        if source in {'otp_payment','sosmed_payment'} and user is not None:
            with self.host.db() as conn:
                if not conn.execute(f"SELECT 1 FROM {'otp_payments' if source=='otp_payment' else 'sosmed_payments'} WHERE payment_id=? AND user_id=?",(str(entity),user)).fetchone():return None
        if source not in {'otp_order','sosmed'}:return source,str(entity)
        otp=source=='otp_order'
        store=self.host.OTP_STORE if otp else self.host.SOSMED_STORE
        table,field=('otp_orders','buyer_user_id') if otp else ('sosmed_orders','user_id')
        order=store.repo.one(f'SELECT * FROM {table} WHERE id=?',(entity,))
        if not order or (user is not None and order[field]!=user):return None
        payment=store.repo.one(f'SELECT payment_id FROM {store.payments.table} WHERE attempt_id=? AND paid_at IS NOT NULL',(order['attempt_id'],))
        return (store.payments.receipt_source,payment['payment_id']) if payment else (source,str(entity))

    def view(self, row):
        """Build a private caption from live state; secrets never enter snapshots."""
        data=json.loads(row['snapshot_json']);source=row['source'];entity=row['entity_id']
        caption=('✅ <b>PEMBAYARAN BERHASIL</b>\n'+f"🧾 {html.escape(data['reference'])}\n"
            +f"💰 Total: <b>{rupiah(data['amount'])}</b>\n🕒 {format_wib(data['paid_at'],seconds=True)}")
        keyboard=None
        if data.get('vip_until'):caption+='\n👑 VIP aktif hingga '+format_wib(data['vip_until'])
        if source in {'otp_order','otp_payment','sosmed','sosmed_payment'}:
            otp=source.startswith('otp_');store=self.host.OTP_STORE if otp else self.host.SOSMED_STORE
            payment=store.repo.one(f'SELECT * FROM {store.payments.table} WHERE payment_id=?',(entity,)) if source.endswith('_payment') else None
            table,field=('otp_orders','buyer_user_id') if otp else ('sosmed_orders','user_id')
            order=store.repo.one(f'SELECT * FROM {table} WHERE '+('attempt_id=?' if payment else 'id=?'),(payment['attempt_id'] if payment else entity,))
            if order and order[field]==row['user_id']:
                caption,keyboard=store.ui.receipt_view(order,data)
            elif payment:
                wallet=payment['state']=='WALLET_CREDITED'
                caption+=('\n↩️ Dana tersedia di saldo bot. Produk belum dibeli; tidak perlu membayar QRIS lagi.' if wallet else '\n⏳ Pembayaran diterima. Produk sedang diproses; hasil diperbarui pada invoice ini.')
                keyboard=store.ui.navigation(row['user_id'])
        return caption,keyboard

    def caption_digest(self, caption):
        # A keyed digest avoids an offline guessing oracle for short OTP codes.
        return hmac.new(self._caption_key,b'Maboyy invoice caption v1\0'+caption.encode(),hashlib.sha256).hexdigest()

    def inactive_reason(self, row):
        """Receipt validity only; this never changes fulfillment or wallet state."""
        source=row['source']
        if source not in STORE_SOURCES:return None
        if row['status'] in {'RETIRING','RETIRED'}:return row['error_code'] or 'EXPIRED'
        otp=source.startswith('otp_');table,owner=('otp_orders','buyer_user_id') if otp else ('sosmed_orders','user_id')
        with self.host.db() as conn:
            if source.endswith('_payment'):
                payment=conn.execute(f"SELECT attempt_id FROM {'otp_payments' if otp else 'sosmed_payments'} WHERE payment_id=? AND user_id=? AND paid_at IS NOT NULL",(row['entity_id'],row['user_id'])).fetchone()
                order=conn.execute(f'SELECT * FROM {table} WHERE attempt_id=? AND {owner}=?',(payment['attempt_id'],row['user_id'])).fetchone() if payment else None
            else:order=conn.execute(f'SELECT * FROM {table} WHERE id=? AND {owner}=?',(row['entity_id'],row['user_id'])).fetchone()
        if not order:return None
        if order['status'] in {'CANCELED','CANCELLED','EXPIRED','FAILED'}:return order['status']
        if otp and order['status']!='COMPLETED':
            deadline=display_datetime(order['expires_at'])
            if deadline and deadline.timestamp()<=time.time():return 'EXPIRED'
        return None  # SOSMED has no documented deadline; never invent one.

    async def retire_if_inactive(self, bot, source, entity):
        if source not in STORE_SOURCES:return False
        with self.host.db() as conn:
            found=conn.execute('SELECT * FROM payment_receipts WHERE source=? AND entity_id=?',(source,str(entity))).fetchone()
        if not found:return False
        row=dict(found);reason=self.inactive_reason(row)
        if not reason:return False
        if row['status'] in {'RETIRED','LEGACY'}:return True
        # A request already in flight must keep its lease until the actual
        # message ID is acknowledged. The sender rechecks after delivery.
        if row['status'] in {'DISPATCHING','UNKNOWN'} and not row['message_id']:return True
        now,token=time.time(),secrets.token_hex(16)
        if not row['message_id']:
            with self.host.db() as conn:
                conn.execute("""UPDATE payment_receipts SET status='RETIRED',error_code=?,lease_token=NULL,lease_until=0
                    WHERE source=? AND entity_id=? AND status IN ('PENDING','SENDING')""",(reason,source,str(entity)))
            return True
        with self.host.db() as conn:
            changed=conn.execute("""UPDATE payment_receipts SET status='RETIRING',error_code=?,lease_token=?,lease_until=?
                WHERE source=? AND entity_id=? AND status IN ('SENT','RETIRING','UNKNOWN') AND lease_until<=? AND next_retry_at<=?""",
                (reason,token,now+120,source,str(entity),now,now)).rowcount
        if not changed:return True
        try:
            try:
                await bot.delete_message(row['user_id'],row['message_id'])
            except TelegramBadRequest as exc:
                if 'message to delete not found' not in str(exc).lower():
                    # Telegram can refuse deletion of an older photo. Replace
                    # that same message with a visibly inactive card, no actions.
                    pool=ThreadPoolExecutor(max_workers=1,thread_name_prefix='inactive-invoice')
                    future=pool.submit(render_invoice,json.loads(row['snapshot_json']),inactive=True)
                    try:
                        while not future.done():await asyncio.sleep(.01)
                        photo=future.result()
                    finally:
                        while not future.done():await asyncio.sleep(.01)
                        pool.shutdown(wait=False)
                    caption=('⌛ <b>INVOICE PESANAN HANGUS</b>\n'
                        +html.escape(json.loads(row['snapshot_json'])['reference'])
                        +'\nPesanan dibatalkan, gagal, atau masa berlakunya habis.\nLihat riwayat /otp atau /sosmed untuk status pesanan dan refund.')
                    try:
                        await bot.edit_message_media(chat_id=row['user_id'],message_id=row['message_id'],
                            media=InputMediaPhoto(media=BufferedInputFile(photo,filename='Invoice_hangus.png'),caption=caption,parse_mode='HTML'),reply_markup=None)
                    except TelegramBadRequest as edit:
                        if 'message is not modified' not in str(edit).lower() and 'message to edit not found' not in str(edit).lower():raise
            with self.host.db() as conn:
                conn.execute("UPDATE payment_receipts SET status='RETIRED',lease_token=NULL,lease_until=0,next_retry_at=0 WHERE source=? AND entity_id=? AND status='RETIRING' AND lease_token=?",(source,str(entity),token))
            await self.retire_duplicate_controls(bot,row)
        except BaseException as exc:
            with self.host.db() as conn:
                conn.execute("UPDATE payment_receipts SET lease_token=NULL,lease_until=0,next_retry_at=? WHERE source=? AND entity_id=? AND status='RETIRING' AND lease_token=?",(time.time()+max(10,getattr(exc,'retry_after',0)),source,str(entity),token))
            if isinstance(exc,asyncio.CancelledError):raise
            logging.warning('Invoice retirement deferred source=%s type=%s',source,type(exc).__name__)
        return True

    async def present(self, bot, source, entity, *, user=None,force=False):
        if source not in {'otp_order','otp_payment','sosmed','sosmed_payment'}:
            return await self.send_for(bot,source,entity)
        key=self.store_key(source,entity,user)
        if key is None:return False
        source,entity=key
        if await self.retire_if_inactive(bot,source,entity):return False
        await self.send_for(bot,source,entity)
        if await self.retire_if_inactive(bot,source,entity):return False
        with self.host.db() as conn:
            row=conn.execute('SELECT * FROM payment_receipts WHERE source=? AND entity_id=?',(source,str(entity))).fetchone()
        if not row or row['status']!='SENT' or not row['message_id']:return False
        row=dict(row)
        if source not in {'otp_order','otp_payment','sosmed','sosmed_payment'}:return True
        caption,keyboard=self.view(row);digest=self.caption_digest(caption)
        if row['caption_hash']==digest and not force:
            await self.retire_duplicate_controls(bot,row)
            return True
        token=secrets.token_hex(16);now=time.time()
        with self.host.db() as conn:
            changed=conn.execute("""UPDATE payment_receipts SET lease_token=?,lease_until=?
                WHERE source=? AND entity_id=? AND status='SENT' AND (caption_hash!=? OR ?)
                  AND lease_until<=? AND next_retry_at<=?""",(token,now+120,source,str(entity),digest,force,now,now)).rowcount
        if not changed:return True  # Another editor owns this existing photo.
        try:
            try:
                await bot.edit_message_caption(chat_id=row['user_id'],message_id=row['message_id'],caption=caption,reply_markup=keyboard,parse_mode='HTML')
            except TelegramBadRequest as exc:
                detail=str(exc).lower()
                if 'message to edit not found' in detail:
                    with self.host.db() as conn:
                        changed=conn.execute("UPDATE payment_receipts SET status='PENDING',message_id=NULL,caption_hash='',lease_token=NULL,lease_until=0,next_retry_at=0 WHERE source=? AND entity_id=? AND status='SENT' AND lease_token=?",(source,str(entity),token)).rowcount
                    return await self.send_for(bot,source,entity) if changed else False
                if 'message is not modified' not in detail:raise
            with self.host.db() as conn:
                conn.execute("UPDATE payment_receipts SET caption_hash=?,lease_token=NULL,lease_until=0,error_code=NULL WHERE source=? AND entity_id=? AND lease_token=?",(digest,source,str(entity),token))
            if await self.retire_if_inactive(bot,source,entity):return False
            await self.retire_duplicate_controls(bot,row)
            return True
        except BaseException as exc:
            with self.host.db() as conn:
                conn.execute("UPDATE payment_receipts SET caption_hash='',lease_token=NULL,lease_until=0,error_code=?,next_retry_at=? WHERE source=? AND entity_id=? AND lease_token=?",(type(exc).__name__,time.time()+max(5,getattr(exc,'retry_after',0)),source,str(entity),token))
            if isinstance(exc,asyncio.CancelledError):raise
            return True  # Keep the known photo; the worker retries its edit.

    async def retire_source(self, message, user, source, order_id):
        key=self.store_key(source,order_id,user)
        if key is None:return
        with self.host.db() as conn:
            receipt=conn.execute("SELECT message_id FROM payment_receipts WHERE source=? AND entity_id=? AND status='SENT'",key).fetchone()
        if not receipt:return
        native=getattr(message,'message',message)
        message_id=getattr(message,'target_id',None) or getattr(native,'message_id',None)
        if (not message_id or message_id==receipt['message_id'] or getattr(native.chat,'id',None)!=user
                or not getattr(getattr(native,'from_user',None),'is_bot',False)):return
        text=str(getattr(native,'text',None) or getattr(native,'caption',None) or '')
        if not re.search(r'#\s*'+re.escape(str(order_id))+r'\b',text):return
        duplicate=any(x in text for x in ('Nomor berhasil dibeli','PEMBELIAN BERHASIL','PESANAN BERHASIL DIBUAT'))
        try:
            if duplicate and getattr(native,'text',None):
                await message.bot.delete_message(user,message_id)
            elif any(getattr(button,'copy_text',None) for row in getattr(getattr(native,'reply_markup',None),'inline_keyboard',[]) for button in row):
                await message.bot.edit_message_reply_markup(chat_id=user,message_id=message_id,reply_markup=None)
        except Exception:pass

    async def retire_duplicate_controls(self, bot, receipt):
        """Only old recorded messages of this exact buyer/order may be retired."""
        source=receipt['source'];otp=source.startswith('otp_')
        if source not in {'otp_order','otp_payment','sosmed','sosmed_payment'}:return
        store=self.host.OTP_STORE if otp else self.host.SOSMED_STORE
        if source.endswith('_payment'):
            payment=store.repo.one(f'SELECT attempt_id FROM {store.payments.table} WHERE payment_id=?',(receipt['entity_id'],))
            order=store.repo.one(f"SELECT * FROM {'otp_orders' if otp else 'sosmed_orders'} WHERE attempt_id=?",(payment['attempt_id'],)) if payment else None
        else:order=store.repo.one(f"SELECT * FROM {'otp_orders' if otp else 'sosmed_orders'} WHERE id=?",(receipt['entity_id'],))
        if not order or order['buyer_user_id' if otp else 'user_id']!=receipt['user_id']:return
        if otp:
            jobs=store.repo.rows("SELECT notification_id,telegram_message_id FROM otp_notifications WHERE order_id=? AND user_id=? AND kind='PURCHASE' AND telegram_message_id IS NOT NULL AND telegram_message_id!=?",(order['id'],receipt['user_id'],receipt['message_id']))
            for job in jobs:
                try:await bot.delete_message(receipt['user_id'],job['telegram_message_id'])
                except Exception:
                    try:await bot.edit_message_reply_markup(chat_id=receipt['user_id'],message_id=job['telegram_message_id'],reply_markup=None)
                    except Exception:continue
                store.repo.execute('UPDATE otp_notifications SET telegram_message_id=? WHERE notification_id=? AND telegram_message_id=?',(receipt['message_id'],job['notification_id'],job['telegram_message_id']))
        else:
            payment=store.repo.one('SELECT * FROM sosmed_payments WHERE attempt_id=?',(order['attempt_id'],))
            if payment and payment['notice_message_id'] and payment['notice_message_id']!=receipt['message_id']:
                try:await bot.delete_message(receipt['user_id'],payment['notice_message_id'])
                except Exception:
                    try:await bot.edit_message_reply_markup(chat_id=receipt['user_id'],message_id=payment['notice_message_id'],reply_markup=None)
                    except Exception:return
                store.repo.execute('UPDATE sosmed_payments SET notice_message_id=? WHERE payment_id=? AND notice_message_id=?',(receipt['message_id'],payment['payment_id'],payment['notice_message_id']))

    @staticmethod
    def candidates(source):
        # All selectors require durable confirmed payment state. Pending holds,
        # canceled invoices, failed purchases and unknown outcomes are excluded.
        return {
            "order": "SELECT o.id AS entity_id FROM orders o WHERE o.payment_status='paid' AND o.payment_method!='OWNER_FREE' AND COALESCE(NULLIF(o.payment_total,0),o.total)>0 AND NOT EXISTS(SELECT 1 FROM tools_vip_purchases v WHERE v.order_id=o.id AND v.activated_at IS NULL)",
            "topup": "SELECT t.id AS entity_id FROM topups t WHERE t.status='completed' AND NOT EXISTS(SELECT 1 FROM otp_payments p WHERE p.topup_id=t.id) AND NOT EXISTS(SELECT 1 FROM sosmed_payments p WHERE p.topup_id=t.id)",
            "otp_payment": "SELECT p.payment_id AS entity_id FROM otp_payments p WHERE p.paid_at IS NOT NULL",
            "otp_order": "SELECT o.id AS entity_id FROM otp_orders o JOIN otp_purchase_attempts a ON a.attempt_id=o.attempt_id WHERE a.state='CAPTURED' AND NOT EXISTS(SELECT 1 FROM otp_payments p WHERE p.attempt_id=o.attempt_id AND p.paid_at IS NOT NULL)",
            "sosmed": "SELECT o.id AS entity_id FROM sosmed_orders o JOIN sosmed_purchase_attempts a ON a.attempt_id=o.attempt_id WHERE a.state='SUCCESS' AND NOT EXISTS(SELECT 1 FROM sosmed_payments p WHERE p.attempt_id=o.attempt_id AND p.paid_at IS NOT NULL)",
            "sosmed_payment": "SELECT p.payment_id AS entity_id FROM sosmed_payments p WHERE p.paid_at IS NOT NULL",
            "qris_review": "SELECT t.id AS entity_id FROM klikqris_transactions t JOIN wallet_ledger w ON w.id=t.review_ledger_id WHERE t.state='SETTLED_BALANCE' AND t.sandbox=0 AND w.user_id=t.user_id AND w.amount=t.amount AND w.type='TOPUP' AND w.reference='AQ-REVIEW-'||t.id",
        }[source]

    @staticmethod
    def customer(conn, user, username=""):
        if not username:
            found = conn.execute("SELECT username FROM verified_users WHERE user_id=?", (user,)).fetchone()
            username = found[0] if found else ""
        if re.fullmatch(r"@?[A-Za-z0-9_]{3,32}", str(username or "")):
            return "@"+str(username).lstrip("@")
        return "User #"+str(int(user))

    def snapshot(self, conn, source, entity_id):
        eligible = conn.execute("SELECT 1 FROM ("+self.candidates(source)+") WHERE CAST(entity_id AS TEXT)=?", (str(entity_id),)).fetchone()
        if not eligible:
            return None
        if source == "order":
            row = dict(conn.execute("SELECT o.*,p.name AS product_name,v.name AS variant_name FROM orders o LEFT JOIN products p ON p.id=o.product_id LEFT JOIN product_variants v ON v.id=o.variant_id WHERE o.id=?", (entity_id,)).fetchone())
            user = row["user_id"]
            result = dict(reference=self.host.invoice(row["id"]), category="Produk Digital", item=row["product_name"] or "Produk Digital",
                variant=row["variant_name"], quantity=row["qty"], amount=row["payment_total"] or row["total"], subtotal=row["total"],
                discount=row["discount_amount"], unique_code=row["unique_code"], method=row["payment_method"],
                paid_at=row["payment_verified_at"] or row["completed_at"] or row["created_at"])
            result["customer"] = self.customer(conn, user, row["username"])
            vip=conn.execute('SELECT access_expires_at FROM tools_vip_purchases WHERE order_id=? AND activated_at IS NOT NULL',(row['id'],)).fetchone()
            if vip:
                result.update(category='VIP /tools',item='VIP /tools',variant='1 bulan',vip_until=vip['access_expires_at'])
            if row['payment_method']=='KLIKQRIS_AUTO':
                result['qris_adjustment']=max(0,int(result['amount'])-int(row['total'])+int(row['discount_amount'] or 0))
        elif source == "topup":
            row = dict(conn.execute("SELECT * FROM topups WHERE id=?", (entity_id,)).fetchone())
            user = row["user_id"]
            result = dict(reference=self.host.topup_invoice(row["id"]), category="Isi Saldo", item="Saldo Bot • seluruh fitur",
                quantity=1, amount=row["payment_total"] or row["amount"], credit=row["amount"],
                unique_code=row["unique_code"], method=row["payment_method"], paid_at=row["verified_at"] or row["updated_at"] or row["created_at"])
            result["customer"] = self.customer(conn, user, row["username"])
            if row['payment_method']=='KLIKQRIS_AUTO':
                result['qris_adjustment']=max(0,int(result['amount'])-int(row['amount']))
        elif source == 'qris_review':
            row=dict(conn.execute('SELECT * FROM klikqris_transactions WHERE id=?',(entity_id,)).fetchone())
            user=row['user_id']
            result=dict(reference=self.host.topup_invoice(row['entity_id']) if row['purpose']=='topup' else self.host.invoice(row['entity_id']),
                category='Isi Saldo',item='Pembayaran QRIS dipindahkan ke saldo',quantity=1,
                amount=row['total_amount'],credit=row['amount'],qris_adjustment=row['total_amount']-row['amount'],
                method='KLIKQRIS_AUTO',paid_at=row['api_verified_at'])
        elif source == "otp_payment":
            row = dict(conn.execute("SELECT p.*,q.product FROM otp_payments p JOIN otp_quotes q ON q.quote_id=p.quote_id WHERE p.payment_id=?", (entity_id,)).fetchone())
            product = json.loads(row["product"])
            user = row["user_id"]
            result = dict(reference=row["partner_reference"], category="Nomor OTP", item=public_text(product.get("service_name") or product.get("platform_name") or "Nomor OTP"),
                variant=public_text(product.get("country_name", "")), quantity=1, amount=row["payment_total_idr"],
                subtotal=row["amount_idr"], unique_code=row["payment_total_idr"]-row["amount_idr"], method=row["method"], paid_at=row["paid_at"])
        elif source == "sosmed_payment":
            row = dict(conn.execute('SELECT p.*,q.service_snapshot,q.quantity FROM sosmed_payments p JOIN sosmed_quotes q ON q.quote_id=p.quote_id WHERE p.payment_id=?',(entity_id,)).fetchone())
            service, user = json.loads(row['service_snapshot']), row['user_id']
            result = dict(reference=row['partner_reference'],category='Layanan Sosmed',item=public_text(service.get('name') or 'Layanan Sosmed'),
                quantity=row['quantity'],amount=row['payment_total_idr'],subtotal=row['amount_idr'],
                unique_code=row['payment_total_idr']-row['amount_idr'],method=row['method'],paid_at=row['paid_at'])
        elif source == "otp_order":
            row = dict(conn.execute("SELECT * FROM otp_orders WHERE id=?", (entity_id,)).fetchone())
            user = row["buyer_user_id"]
            result = dict(reference="OTP-"+str(row["provider_order_id"]), category="Nomor OTP", item=public_text(row["platform_name"]),
                variant=public_text(row["country_name"]), quantity=1, amount=row["selling_price_idr"], method="WALLET", paid_at=row["created_at"])
        else:
            row = dict(conn.execute("SELECT * FROM sosmed_orders WHERE id=?", (entity_id,)).fetchone())
            user = row["user_id"]
            result = dict(reference="SMM-"+str(row["id"]).zfill(6), category="Layanan Sosmed", item=public_text(row["service_name_snapshot"]),
                quantity=row["quantity"], amount=row["selling_price"], method="WALLET", paid_at=row["created_at"])
        if source not in {"order", "topup"}:
            result["customer"] = self.customer(conn, user)
        if int(user) <= 0 or int(result["amount"]) <= 0:
            raise ValueError("Invalid receipt identity/amount")
        result["user_id"] = int(user)
        # Never put raw provider response, credentials, OTP or wallet owner
        # balance in a receipt. Only these selected buyer-facing fields persist.
        return result

    def discover(self, limit=50):
        conn = self.host.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            count = 0
            for source in SOURCES:
                pending = conn.execute("SELECT c.entity_id FROM ("+self.candidates(source)+") c LEFT JOIN payment_receipts r ON r.source=? AND r.entity_id=CAST(c.entity_id AS TEXT) WHERE r.entity_id IS NULL LIMIT ?", (source, limit)).fetchall()
                for item in pending:
                    entity = str(item[0])
                    data = self.snapshot(conn, source, entity)
                    if data:
                        count += conn.execute("INSERT OR IGNORE INTO payment_receipts(source,entity_id,user_id,snapshot_json,created_at) VALUES(?,?,?,?,?)", (source, entity, data["user_id"], json.dumps(data, ensure_ascii=False), time.time())).rowcount
            conn.commit()
            return count
        finally:
            if conn.in_transaction:
                conn.rollback()
            conn.close()

    def enqueue(self, source, entity):
        if source not in SOURCES:
            return False
        conn = self.host.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT 1 FROM payment_receipts WHERE source=? AND entity_id=?", (source, str(entity))).fetchone()
            if not existing:
                data = self.snapshot(conn, source, entity)
                if data is None:
                    return False
                conn.execute("INSERT INTO payment_receipts(source,entity_id,user_id,snapshot_json,created_at) VALUES(?,?,?,?,?)", (source, str(entity), data["user_id"], json.dumps(data, ensure_ascii=False), time.time()))
            conn.commit()
            return True
        finally:
            if conn.in_transaction:
                conn.rollback()
            conn.close()

    def claim(self, source, entity):
        now, token = time.time(), secrets.token_hex(16)
        conn = self.host.db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            changed = conn.execute("""UPDATE payment_receipts SET status='SENDING',lease_token=?,lease_until=?,attempts=attempts+1
                WHERE source=? AND entity_id=? AND status IN ('PENDING','SENDING') AND next_retry_at<=? AND lease_until<=?""", (token, now+120, source, str(entity), now, now)).rowcount
            row = conn.execute("SELECT * FROM payment_receipts WHERE source=? AND entity_id=? AND lease_token=?", (source, str(entity), token)).fetchone() if changed else None
            conn.commit()
            return dict(row) if row else None
        finally:
            if conn.in_transaction:
                conn.rollback()
            conn.close()

    def finish(self, row, *, message_id=None, error=None, retry_after=0, caption_hash=''):
        conn = self.host.db()
        try:
            if error is None:
                changed = conn.execute("""UPDATE payment_receipts SET status='SENT',sent_at=?,message_id=?,lease_token=NULL,lease_until=0,error_code=NULL,caption_hash=?
                    WHERE source=? AND entity_id=? AND lease_token=?""", (time.time(), message_id,caption_hash,row["source"], row["entity_id"], row["lease_token"])).rowcount
                if changed and row["source"] == "order":
                    conn.execute("UPDATE orders SET invoice_sent=1 WHERE id=?", (row["entity_id"],))
            else:
                delay = max(float(retry_after or 0), min(3600, 10*2**min(row["attempts"], 8)))
                conn.execute("""UPDATE payment_receipts SET status=CASE WHEN status='UNKNOWN' THEN 'UNKNOWN' ELSE 'PENDING' END,
                    next_retry_at=?,lease_token=NULL,lease_until=0,error_code=CASE WHEN error_code='QRIS_EDIT' THEN error_code ELSE ? END
                    WHERE source=? AND entity_id=? AND lease_token=?""", (time.time()+delay, str(error)[:80], row["source"], row["entity_id"], row["lease_token"]))
            conn.commit()
        finally:
            conn.close()

    async def send_for(self, bot, source, entity):
        if not self.enqueue(source, entity):
            return False
        if await self.retire_if_inactive(bot,source,entity):return False
        row = self.claim(source, entity)
        if row is None:
            return False  # Already sent, backed off, or another instance owns it.
        pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="invoice-photo")
        future,dispatching = None,False
        try:
            data = json.loads(row["snapshot_json"])
            future = pool.submit(render_invoice, data)
            while not future.done():
                await asyncio.sleep(.01)
            photo = BufferedInputFile(future.result(), filename="Invoice_"+re.sub(r"[^A-Za-z0-9_-]", "_", data["reference"])+".png")
            if await self.retire_if_inactive(bot,source,entity):return False
            caption,keyboard=self.view(row)
            gateway = getattr(self.host, "KLIKQRIS_GATEWAY", None)
            linked = gateway.receipt_transaction(source, entity) if gateway is not None else None
            if not linked and not callable(getattr(bot,'send_photo',None)):
                raise ValueError('Photo transport unavailable')
            if source in {'otp_order','otp_payment','sosmed','sosmed_payment'}:
                with self.host.db() as conn:
                    changed=conn.execute("""UPDATE payment_receipts SET status='DISPATCHING'
                        WHERE source=? AND entity_id=? AND status='SENDING' AND lease_token=? AND lease_until>?""",
                        (source,str(entity),row['lease_token'],time.time())).rowcount
                if not changed:return False
                dispatching=True
            if linked:
                message = await asyncio.wait_for(gateway.deliver_receipt_photo(bot, row, photo, caption), timeout=40)
            else:
                options={'reply_markup':keyboard} if keyboard is not None else {}
                message = await asyncio.wait_for(bot.send_photo(row["user_id"], photo, caption=caption,parse_mode="HTML",**options), timeout=40)
            message_id = getattr(message, "message_id", None)
            if not isinstance(message_id, int) or isinstance(message_id, bool) or message_id <= 0:
                raise ValueError("Photo delivery not acknowledged")
            self.finish(row, message_id=message_id,caption_hash=self.caption_digest(caption))
            if await self.retire_if_inactive(bot,source,entity):return False
            if linked:
                try:
                    await gateway.retire_paid_messages(bot, linked['id'])
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logging.warning("QRIS cleanup deferred type=%s", type(exc).__name__)
            return True
        except asyncio.CancelledError:
            if dispatching:
                with self.host.db() as conn:conn.execute("UPDATE payment_receipts SET status='UNKNOWN' WHERE source=? AND entity_id=? AND lease_token=? AND COALESCE(error_code,'')!='QRIS_EDIT'",(source,str(entity),row['lease_token']))
            self.finish(row, error="CANCELLED")
            raise
        except Exception as exc:
            if dispatching and not isinstance(exc,(TelegramBadRequest,TelegramForbiddenError,TelegramRetryAfter)):
                with self.host.db() as conn:conn.execute("UPDATE payment_receipts SET status='UNKNOWN' WHERE source=? AND entity_id=? AND lease_token=? AND COALESCE(error_code,'')!='QRIS_EDIT'",(source,str(entity),row['lease_token']))
            self.finish(row, error=type(exc).__name__, retry_after=getattr(exc, "retry_after", 0))
            logging.warning("Invoice photo deferred source=%s entity=%s type=%s", source, entity, type(exc).__name__)
            return False
        finally:
            # No default asyncio executor; cancellation waits for the small PNG
            # render to release its memory before shutting down the worker.
            if future is not None:
                while not future.done():
                    await asyncio.sleep(.01)
            pool.shutdown(wait=False)

    async def run_once(self, bot):
        self.discover()
        conn = self.host.db()
        try:
            conn.execute("""UPDATE payment_receipts SET status=CASE WHEN error_code='QRIS_EDIT' AND message_id>0 THEN 'PENDING' ELSE 'UNKNOWN' END
                WHERE status='DISPATCHING' AND lease_until<=?""",(time.time(),))
            conn.commit()
            rows = conn.execute("""SELECT source,entity_id FROM payment_receipts
                WHERE status IN ('PENDING','SENDING') AND next_retry_at<=? AND lease_until<=?
                ORDER BY created_at LIMIT 20""", (time.time(), time.time())).fetchall()
        finally:
            conn.close()
        with self.host.db() as conn:
            inactive=conn.execute("""SELECT r.source,r.entity_id FROM payment_receipts r
                LEFT JOIN otp_orders o ON o.buyer_user_id=r.user_id AND
                  ((r.source='otp_order' AND CAST(o.id AS TEXT)=r.entity_id) OR
                   (r.source='otp_payment' AND o.attempt_id=(SELECT attempt_id FROM otp_payments WHERE payment_id=r.entity_id AND user_id=r.user_id)))
                LEFT JOIN sosmed_orders s ON s.user_id=r.user_id AND
                  ((r.source='sosmed' AND CAST(s.id AS TEXT)=r.entity_id) OR
                   (r.source='sosmed_payment' AND s.attempt_id=(SELECT attempt_id FROM sosmed_payments WHERE payment_id=r.entity_id AND user_id=r.user_id)))
                WHERE r.source IN ('otp_order','otp_payment','sosmed','sosmed_payment')
                  AND r.status NOT IN ('LEGACY','RETIRED') AND r.next_retry_at<=?
                  AND (r.status='RETIRING' OR o.status IN ('CANCELED','CANCELLED','EXPIRED','FAILED')
                    OR s.status IN ('CANCELED','CANCELLED','EXPIRED','FAILED')
                    OR (o.status!='COMPLETED' AND (julianday(o.expires_at)<=julianday(?,'unixepoch')
                      OR (CAST(o.expires_at AS REAL)>=1000000000 AND
                        CAST(o.expires_at AS REAL)/CASE WHEN CAST(o.expires_at AS REAL)>=100000000000 THEN 1000 ELSE 1 END<=?))))
                ORDER BY r.created_at LIMIT 50""",(time.time(),time.time(),time.time())).fetchall()
        for row in inactive:await self.retire_if_inactive(bot,row['source'],row['entity_id'])
        for row in rows:
            await self.send_for(bot, row["source"], row["entity_id"])
        with self.host.db() as conn:
            previous=conn.execute("""SELECT source,entity_id FROM payment_receipts WHERE status='SENT' AND message_id>0
                AND source IN ('otp_order','otp_payment','sosmed','sosmed_payment') AND caption_hash=''
                AND lease_until<=? AND next_retry_at<=? ORDER BY created_at DESC LIMIT 20""",(time.time(),time.time())).fetchall()
        for row in previous:await self.present(bot,row['source'],row['entity_id'])
        try:await self.channel.run_once(bot)
        except asyncio.CancelledError:raise
        except Exception as exc:logging.warning('Transaction channel deferred type=%s',type(exc).__name__)

    async def worker(self, bot):
        while True:
            try:
                await self.run_once(bot)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logging.warning("Invoice worker deferred type=%s", type(exc).__name__)
            await asyncio.sleep(5)

    def start(self, bot):
        if self._worker is not None and not self._worker.done():
            return []
        self._worker = asyncio.create_task(self.worker(bot), name="payment-invoice-worker")
        return [self._worker]


class TransactionChannel:
    """Public success-photo outbox; independent of private invoices and money."""
    def __init__(self, receipts):
        self.receipts,self.host=receipts,receipts.host

    @staticmethod
    def configuration(conn):
        values=dict(conn.execute("SELECT key,value FROM settings WHERE key IN ('transaction_channel_id','transaction_channel_enabled','transaction_channel_title')").fetchall())
        return values.get('transaction_channel_id',''),values.get('transaction_channel_enabled','0')=='1',values.get('transaction_channel_title','')

    @staticmethod
    def candidates():
        return """SELECT 'order' source,CAST(o.id AS TEXT) entity_id FROM orders o
            WHERE o.status='completed' AND o.fulfillment_status='delivered' AND o.payment_status='paid' AND o.payment_method!='OWNER_FREE'
            UNION ALL SELECT 'topup',CAST(t.id AS TEXT) FROM topups t WHERE t.status='completed'
              AND NOT EXISTS(SELECT 1 FROM otp_payments p WHERE p.topup_id=t.id)
              AND NOT EXISTS(SELECT 1 FROM sosmed_payments p WHERE p.topup_id=t.id)
            UNION ALL SELECT 'otp_order',CAST(o.id AS TEXT) FROM otp_orders o
              JOIN otp_purchase_attempts a ON a.attempt_id=o.attempt_id
              WHERE a.state='CAPTURED' AND o.status IN ('OTP_RECEIVED','COMPLETED') AND o.last_sms_revision>0 AND o.refund_idr=0
            UNION ALL SELECT 'sosmed',CAST(o.id AS TEXT) FROM sosmed_orders o
              JOIN sosmed_purchase_attempts a ON a.attempt_id=o.attempt_id
              WHERE a.state='SUCCESS' AND o.status='COMPLETED' AND o.refund_amount=0
            UNION ALL SELECT 'qris_review',CAST(t.id AS TEXT) FROM klikqris_transactions t
              JOIN wallet_ledger w ON w.id=t.review_ledger_id
              WHERE t.state='SETTLED_BALANCE' AND t.sandbox=0 AND w.user_id=t.user_id AND w.amount=t.amount
                AND w.type='TOPUP' AND w.reference='AQ-REVIEW-'||t.id"""

    def discover(self, conn, target, *, historical=False):
        rows=conn.execute('SELECT c.* FROM ('+self.candidates()+''') c
            LEFT JOIN transaction_channel_events e ON e.source=c.source AND e.entity_id=c.entity_id
            WHERE e.source IS NULL'''+('' if historical else ' LIMIT 50')).fetchall()
        for row in rows:
            if historical:data={}
            else:
                key=self.receipts.store_key(row['source'],row['entity_id'])
                if key is None:continue
                snapshot=self.receipts.snapshot(conn,*key)
                if not snapshot:continue
                # No buyer identity, phone, SMS, account credentials, target,
                # provider cost or private order controls enter the channel.
                allowed={'reference','category','item','variant','quantity','amount','subtotal','discount','unique_code','qris_adjustment','credit','method','paid_at','vip_until'}
                data={k:v for k,v in snapshot.items() if k in allowed}
                data['customer']='Pelanggan Maboyy Digital'
            conn.execute("""INSERT OR IGNORE INTO transaction_channel_events(source,entity_id,channel_id,snapshot_json,status,created_at)
                VALUES(?,?,?,?,?,?)""",(row['source'],row['entity_id'],target,json.dumps(data,ensure_ascii=False),'SKIPPED' if historical else 'PENDING',time.time()))

    def set_target(self, target, title):
        with self.host.db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute("UPDATE transaction_channel_events SET status='SKIPPED',lease_token=NULL,lease_until=0 WHERE status IN ('PENDING','SENDING','BLOCKED')")
            for key,value in (('transaction_channel_id',str(target)),('transaction_channel_title',str(title)[:150]),('transaction_channel_enabled','0')):
                conn.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',(key,value))

    def enable(self, enabled):
        with self.host.db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            target,previous,_=self.configuration(conn)
            if enabled and not target:raise ValueError('Channel belum diatur')
            if enabled and not previous:
                self.discover(conn,target,historical=True)  # No historical flood.
                conn.execute("UPDATE transaction_channel_events SET status='PENDING',next_retry_at=0 WHERE channel_id=? AND status='BLOCKED'",(target,))
            elif not enabled:
                conn.execute("UPDATE transaction_channel_events SET status='SKIPPED',lease_token=NULL,lease_until=0 WHERE status IN ('PENDING','SENDING','BLOCKED')")
            conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('transaction_channel_enabled',?)",('1' if enabled else '0',))

    async def verify(self, bot, raw):
        value=str(raw).strip()
        if value.startswith('https://t.me/'):value='@'+value[len('https://t.me/'):].strip('/')
        if not re.fullmatch(r'(?:-100\d{6,16}|@[A-Za-z][A-Za-z0-9_]{4,31})',value):
            raise ValueError('Gunakan ID channel -100… atau @username_channel.')
        target=int(value) if value.startswith('-100') else value
        chat=await bot.get_chat(target)
        if str(getattr(chat.type,'value',chat.type))!='channel':raise ValueError('Tujuan harus berupa channel Telegram.')
        me=await bot.get_me();member=await bot.get_chat_member(chat.id,me.id)
        status=str(getattr(member.status,'value',member.status))
        if status not in {'administrator','creator','owner'} or (status=='administrator' and getattr(member,'can_post_messages',False) is not True):
            raise ValueError('Jadikan bot admin channel dan aktifkan izin mengirim pesan.')
        return str(chat.id),str(chat.title or 'Channel')[:150]

    async def run_once(self, bot):
        now=time.time()
        with self.host.db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute("UPDATE transaction_channel_events SET status='UNKNOWN',lease_token=NULL,lease_until=0,error_code='DELIVERY_UNCERTAIN' WHERE status='DISPATCHING' AND lease_until<=?",(now,))
            target,enabled,_=self.configuration(conn)
            if not enabled or not target:return
            self.discover(conn,target)
            jobs=conn.execute("SELECT * FROM transaction_channel_events WHERE channel_id=? AND status IN ('PENDING','SENDING') AND lease_until<=? AND next_retry_at<=? ORDER BY created_at LIMIT 10",(target,now,now)).fetchall()
        for job in jobs:
            token=secrets.token_hex(16);dispatching=False;future=None
            pool=ThreadPoolExecutor(max_workers=1,thread_name_prefix='channel-invoice')
            try:
                with self.host.db() as conn:
                    changed=conn.execute("""UPDATE transaction_channel_events SET status='SENDING',lease_token=?,lease_until=?,attempts=attempts+1
                        WHERE source=? AND entity_id=? AND channel_id=? AND status IN ('PENDING','SENDING') AND lease_until<=?""",
                        (token,time.time()+120,job['source'],job['entity_id'],target,time.time())).rowcount
                if not changed:continue
                data=json.loads(job['snapshot_json']);future=pool.submit(render_invoice,data)
                while not future.done():await asyncio.sleep(.01)
                photo=BufferedInputFile(future.result(),filename='Invoice_'+re.sub(r'[^A-Za-z0-9_-]','_',data['reference'])+'.png')
                caption=('✅ <b>TRANSAKSI BERHASIL</b>\n<b>MABOYY DIGITAL</b>\n'
                    +f"🧾 {html.escape(data['reference'])}\n📦 {html.escape(public_text(data['item'],140))}\n"
                    +f"🔢 Jumlah: {int(data.get('quantity',1))}\n💰 Total: <b>{rupiah(data['amount'])}</b>\n"
                    +f"💳 {html.escape(method_label(data.get('method')))}\n🕒 {format_wib(data['paid_at'],seconds=True)}")
                with self.host.db() as conn:
                    conn.execute('BEGIN IMMEDIATE');current,on,_=self.configuration(conn)
                    eligible=conn.execute('SELECT 1 FROM ('+self.candidates()+') WHERE source=? AND entity_id=?',(job['source'],job['entity_id'])).fetchone()
                    changed=conn.execute("UPDATE transaction_channel_events SET status='DISPATCHING' WHERE source=? AND entity_id=? AND status='SENDING' AND lease_token=?",(job['source'],job['entity_id'],token)).rowcount if on and current==target and eligible else 0
                    if not changed:conn.execute("UPDATE transaction_channel_events SET status='SKIPPED',lease_token=NULL,lease_until=0 WHERE source=? AND entity_id=? AND status='SENDING' AND lease_token=?",(job['source'],job['entity_id'],token))
                if not changed:continue
                dispatching=True
                sent=await asyncio.wait_for(bot.send_photo(int(target),photo,caption=caption,parse_mode='HTML'),timeout=40)
                message_id=getattr(sent,'message_id',None)
                if not isinstance(message_id,int) or isinstance(message_id,bool) or message_id<=0:raise ValueError('Photo delivery not acknowledged')
                with self.host.db() as conn:
                    conn.execute("UPDATE transaction_channel_events SET status='SENT',message_id=?,sent_at=?,lease_token=NULL,lease_until=0,error_code=NULL WHERE source=? AND entity_id=? AND lease_token=?",(message_id,time.time(),job['source'],job['entity_id'],token))
            except BaseException as exc:
                known=isinstance(exc,(TelegramBadRequest,TelegramForbiddenError,TelegramRetryAfter))
                state='UNKNOWN' if dispatching and not known else 'BLOCKED' if isinstance(exc,(TelegramBadRequest,TelegramForbiddenError)) else 'PENDING'
                with self.host.db() as conn:
                    conn.execute("UPDATE transaction_channel_events SET status=?,error_code=?,next_retry_at=?,lease_token=NULL,lease_until=0 WHERE source=? AND entity_id=? AND lease_token=?",(state,type(exc).__name__,time.time()+max(10,getattr(exc,'retry_after',0),min(3600,10*2**min(job['attempts'],8))),job['source'],job['entity_id'],token))
                if isinstance(exc,asyncio.CancelledError):raise
                logging.warning('Channel invoice deferred type=%s',type(exc).__name__)
            finally:
                if future is not None:
                    while not future.done():await asyncio.sleep(.01)
                pool.shutdown(wait=False)


async def notify(host, bot, source, entity):
    """A delivery failure never interrupts payment, fulfillment or other menus."""
    service = getattr(host, "PAYMENT_RECEIPTS", None)
    if service is None:
        return False
    try:
        return await service.present(bot, source, entity)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logging.warning("Invoice enqueue deferred source=%s type=%s", source, type(exc).__name__)
        return False


def queue(host, source, entity):
    """Commit an image job quickly; account delivery never waits for the photo."""
    service = getattr(host, "PAYMENT_RECEIPTS", None)
    if service is None:
        return False
    try:
        return service.enqueue(source, entity)
    except Exception as exc:
        logging.warning("Invoice enqueue deferred source=%s type=%s", source, type(exc).__name__)
        return False
