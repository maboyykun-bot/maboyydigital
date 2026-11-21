"""Manual Binance Pay configuration and immutable IDR-to-USDT quotations.

This module never contacts Binance, credits a wallet, or confirms payment.
Only the existing owner proof-review flow can approve a native order.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_UP, localcontext
import html
import json
import re
import sqlite3
import time

from aiogram import F
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup


ADAPTER_VERSION = '17.69'
PREFIX = 'bpay:'
SETTINGS_PREFIX = 'binance_pay.'
INVOICE_PREFIX = SETTINGS_PREFIX + 'invoice.'
FORM_SECONDS = 900
MAX_IDR = 1_000_000_000_000
FIELDS = ('enabled', 'recipient', 'recipient_name', 'qr_file_id', 'idr_per_usdt')
SNAPSHOT_FIELDS = frozenset({'version', 'order_id', 'buyer_user_id', 'quoted_idr',
    'currency', 'idr_per_usdt', 'usdt_due', 'recipient', 'recipient_name',
    'qr_file_id', 'created_at'})


class BinancePayError(Exception):
    pass


class BinancePayState(StatesGroup):
    field = State()
    qr = State()


def _ident(value):
    return type(value) is int and 0 < value <= 9_223_372_036_854_775_807


def _idr(value):
    if type(value) is not int or not 1 <= value <= MAX_IDR:
        raise BinancePayError('Nominal rupiah tidak valid.')
    return value


def _rate(value):
    if (not isinstance(value, str) or len(value) > 20
            or not re.fullmatch(r'(?:0|[1-9][0-9]{0,9})(?:\.[0-9]{1,6})?', value)):
        raise BinancePayError('Kurs harus berupa angka tanpa pemisah ribuan, maksimal 6 desimal.')
    try:
        result = Decimal(value)
    except InvalidOperation:
        raise BinancePayError('Kurs tidak valid.') from None
    if not result.is_finite() or not Decimal('0') < result <= Decimal('1000000000'):
        raise BinancePayError('Kurs harus lebih dari nol dan maksimal 1.000.000.000 rupiah per USDT.')
    return result


def _decimal_text(value):
    text = format(value, 'f')
    return text.rstrip('0').rstrip('.') if '.' in text else text


def _recipient(value):
    if not isinstance(value, str) or len(value) > 100:
        raise BinancePayError('Gunakan Pay ID Binance 4–40 digit atau email penerima.')
    value = value.strip()
    if (re.fullmatch(r'[0-9]{4,40}', value)
            or re.fullmatch(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}', value)):
        return value
    raise BinancePayError('Gunakan Pay ID Binance 4–40 digit atau email penerima.')


def _name(value):
    if (not isinstance(value, str) or len(value) > 100
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise BinancePayError('Nama penerima maksimal 100 karakter dalam satu baris.')
    return value.strip()


def _qr(value):
    if not isinstance(value, str) or (value and not re.fullmatch(r'[A-Za-z0-9_+\-/=]{6,1024}', value)):
        raise BinancePayError('Gunakan gambar QR Binance Pay yang diunggah ke Telegram.')
    return value


def quote_usdt(idr_amount, rate):
    """Round up to 0.000001 USDT; native ledger values always remain integer IDR."""
    amount = _idr(idr_amount)
    exchange = _rate(rate)
    with localcontext() as ctx:
        ctx.prec = 40
        result = (Decimal(amount) / exchange).quantize(Decimal('0.000001'), rounding=ROUND_UP)
    return format(result, '.6f')


def _keyboard(rows):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=label, callback_data=data) for label, data in row]
        for row in rows])


def _validate_snapshot(value):
    if (not isinstance(value, dict) or set(value) != SNAPSHOT_FIELDS
            or value.get('version') != 1 or type(value.get('version')) is not int
            or not _ident(value.get('order_id')) or not _ident(value.get('buyer_user_id'))
            or value.get('currency') != 'USDT'):
        raise BinancePayError('Data invoice Binance Pay tidak valid. Hubungi owner.')
    amount = _idr(value.get('quoted_idr'))
    rate = _decimal_text(_rate(value.get('idr_per_usdt')))
    if (rate != value['idr_per_usdt'] or value.get('usdt_due') != quote_usdt(amount, rate)
            or _recipient(value.get('recipient')) != value['recipient']
            or _name(value.get('recipient_name')) != value['recipient_name']
            or _qr(value.get('qr_file_id')) != value['qr_file_id']):
        raise BinancePayError('Data invoice Binance Pay tidak konsisten. Hubungi owner.')
    try:
        stamp = value.get('created_at')
        if not isinstance(stamp, str) or len(stamp) > 50:
            raise ValueError
        instant = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        raise BinancePayError('Waktu invoice Binance Pay tidak valid.') from None
    return dict(value)


class Gateway:
    def __init__(self, host):
        self.host = host

    @contextmanager
    def _connection(self, write=False):
        conn = self.host.db()
        try:
            if write:
                self.host.begin_immediate_retry(conn)
            yield conn
            if write:
                conn.commit()
        except Exception:
            if write:
                conn.rollback()
            raise
        finally:
            conn.close()

    def _raw_config(self, conn):
        rows = conn.execute('SELECT key,value FROM settings WHERE key IN (' +
            ','.join('?' for _ in FIELDS) + ')', tuple(SETTINGS_PREFIX + field for field in FIELDS))
        saved = {row['key'][len(SETTINGS_PREFIX):]: row['value'] for row in rows}
        return {field: str(saved.get(field) or '') for field in FIELDS}

    def config(self, conn=None):
        if conn is None:
            with self._connection() as opened:
                return self.config(opened)
        raw = self._raw_config(conn)
        return {'enabled': raw['enabled'].lower() in {'1', 'true', 'yes', 'on'},
                'recipient': _recipient(raw['recipient']),
                'recipient_name': _name(raw['recipient_name']),
                'qr_file_id': _qr(raw['qr_file_id']),
                'idr_per_usdt': _decimal_text(_rate(raw['idr_per_usdt']))}

    def ready(self):
        try:
            return self.config()['enabled'] is True
        except (BinancePayError, sqlite3.Error):
            return False

    @staticmethod
    def _native(conn, order_id):
        if not _ident(order_id):
            raise BinancePayError('Invoice Binance Pay tidak valid.')
        row = conn.execute('SELECT id,user_id,payment_method,payment_total,status,payment_status '
                           'FROM orders WHERE id=?', (order_id,)).fetchone()
        if (not row or str(row['payment_method'] or '').strip().upper() != 'BINANCE_PAY'
                or not _ident(row['user_id'])):
            raise BinancePayError('Invoice Binance Pay tidak ditemukan atau metode berbeda.')
        _idr(row['payment_total'])
        return row

    def snapshot(self, conn, order_id, idr_amount):
        amount = _idr(idr_amount)
        native = self._native(conn, order_id)
        if native['payment_total'] != amount:
            raise BinancePayError('Nominal invoice Binance Pay tidak sesuai pesanan.')
        row = conn.execute('SELECT value FROM settings WHERE key=?',
                           (INVOICE_PREFIX + str(order_id),)).fetchone()
        if row:
            return self.invoice(conn, order_id)
        if native['status'] != 'pending' or native['payment_status'] != 'unpaid':
            raise BinancePayError('Invoice baru hanya dapat dibuat untuk pesanan belum dibayar.')
        config = self.config(conn)
        if not config['enabled']:
            raise BinancePayError('Binance Pay sedang nonaktif. Pilih metode pembayaran lain.')
        value = dict(version=1, order_id=order_id, buyer_user_id=native['user_id'],
            quoted_idr=amount, currency='USDT', idr_per_usdt=config['idr_per_usdt'],
            usdt_due=quote_usdt(amount, config['idr_per_usdt']), recipient=config['recipient'],
            recipient_name=config['recipient_name'], qr_file_id=config['qr_file_id'],
            created_at=datetime.now(timezone.utc).isoformat(timespec='seconds'))
        _validate_snapshot(value)
        conn.execute('INSERT INTO settings(key,value) VALUES(?,?)',
                     (INVOICE_PREFIX + str(order_id), json.dumps(value, separators=(',', ':'), ensure_ascii=False)))
        return value

    def invoice(self, conn, order_id):
        native = self._native(conn, order_id)
        row = conn.execute('SELECT value FROM settings WHERE key=?',
                           (INVOICE_PREFIX + str(order_id),)).fetchone()
        if not row or not isinstance(row['value'], str) or len(row['value']) > 8192:
            raise BinancePayError('Rincian Binance Pay untuk invoice ini belum tersedia. Hubungi owner.')
        try:
            value = _validate_snapshot(json.loads(row['value']))
        except (ValueError, TypeError):
            raise BinancePayError('Data invoice Binance Pay tidak valid. Hubungi owner.') from None
        if (value['order_id'] != order_id or value['buyer_user_id'] != native['user_id']
                or value['quoted_idr'] != native['payment_total']):
            raise BinancePayError('Data invoice Binance Pay tidak sesuai pesanan.')
        return value

    def text(self, snapshot):
        value = _validate_snapshot(snapshot)
        rate = self._rupiah_rate(value['idr_per_usdt'])
        text = ('💛 <b>BINANCE PAY • USDT</b>\n'
            'Harga produk: <b>' + self.host.rupiah(value['quoted_idr']) + '</b>\n'
            'Bayar: <b>' + value['usdt_due'] + ' USDT</b>\n'
            'Kurs invoice: ' + rate + ' / USDT\n')
        if value['recipient_name']:
            text += 'Penerima: <b>' + html.escape(value['recipient_name']) + '</b>\n'
        text += 'Pay ID / email: <code>' + html.escape(value['recipient']) + '</code>\n'
        text += 'Dibuat: ' + html.escape(self.host.format_wib_datetime(value['created_at'], compact=True))
        return text

    @staticmethod
    def _rupiah_rate(value):
        whole, dot, fraction = _decimal_text(_rate(value)).partition('.')
        whole = format(int(whole), ',').replace(',', '.')
        return 'Rp' + whole + (',' + fraction if dot else '')

    def keyboard(self, order_id, base_markup):
        with self._connection() as conn:
            value = self.invoice(conn, order_id)
        rows = [[InlineKeyboardButton(text='📋 Salin Pay ID / Email',
                        copy_text=CopyTextButton(text=value['recipient'])),
                 InlineKeyboardButton(text='📋 Salin USDT',
                        copy_text=CopyTextButton(text=value['usdt_due']))]]
        if base_markup is not None:
            rows += [list(row) for row in base_markup.inline_keyboard]
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def _allowed(self, event):
        user = getattr(event, 'from_user', None)
        message = getattr(event, 'message', None)
        chat = getattr(event, 'chat', None) or getattr(message, 'chat', None)
        return bool(user and chat and str(chat.type) == 'private' and chat.id == user.id
                    and self.host.is_owner(user.id) and not self.host.security_blocked(user.id))

    async def _notice(self, event, text):
        if hasattr(event, 'data'):
            return await self.host.safe_callback_notice(event, text, show_alert=True)
        return await event.answer(text)

    async def _access(self, event):
        if self._allowed(event):
            return True
        await self._notice(event, 'Pengaturan Binance Pay hanya untuk owner melalui chat privat bot.')
        return False

    @staticmethod
    async def _clear(state):
        if state is None:
            return
        data = await state.get_data()
        for key in ('binance_pay_field', 'binance_pay_form_at', 'binance_pay_owner'):
            data.pop(key, None)
        await state.set_data(data)
        if await state.get_state() in {BinancePayState.field.state, BinancePayState.qr.state}:
            await state.set_state(None)

    def _set(self, field, value):
        if field not in FIELDS:
            raise BinancePayError('Pengaturan Binance Pay tidak valid.')
        with self._connection(True) as conn:
            conn.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) '
                         'DO UPDATE SET value=excluded.value', (SETTINGS_PREFIX + field, value))

    async def _show(self, event, text, rows):
        if not self._allowed(event):
            return
        if hasattr(event, 'data'):
            return await self.host.safe_edit_or_answer(event, text, reply_markup=_keyboard(rows), parse_mode='HTML')
        return await event.answer(text, reply_markup=_keyboard(rows), parse_mode='HTML')

    async def menu(self, call, state=None):
        if not await self._access(call):
            return
        await self._clear(state)
        with self._connection() as conn:
            raw = self._raw_config(conn)
        try:
            config = self.config()
            valid = True
        except BinancePayError:
            valid = False
            config = None
        enabled = bool(valid and config['enabled'])
        recipient = html.escape(raw['recipient'][:100]) or 'Belum diatur'
        name = html.escape(raw['recipient_name'][:100]) or 'Belum diatur'
        rate = self._rupiah_rate(config['idr_per_usdt']) + ' / USDT' if valid else 'Belum valid'
        text = ('💛 <b>BINANCE PAY</b>\n\nStatus: <b>' + ('AKTIF' if enabled else 'NONAKTIF')
            + '</b>\nPay ID / email: <code>' + recipient + '</code>\nPenerima: ' + name
            + '\nKurs: ' + rate + '\nQR: ' + ('Tersimpan' if raw['qr_file_id'] else 'Belum dipasang')
            + '\n\nHarga mengikuti total produk dalam IDR dan dikonversi ke USDT. '
              'Nominal dibulatkan ke atas pada 0,000001 USDT (6 desimal). '
              'Kurs serta penerima dikunci per invoice. Pembayaran dikonfirmasi owner dari bukti.')
        rows = [[('🆔 Atur Pay ID / Email', PREFIX + 'edit:recipient')],
                [('👤 Nama Penerima', PREFIX + 'edit:recipient_name'), ('📈 Atur Kurs', PREFIX + 'edit:idr_per_usdt')],
                [('🖼️ Pasang QR', PREFIX + 'edit:qr_file_id'), ('👁️ Preview QR', PREFIX + 'preview')],
                [('🗑️ Hapus QR', PREFIX + 'clear_qr')],
                [(('🔴 Nonaktifkan' if enabled else '🟢 Aktifkan'), PREFIX + ('disable' if enabled else 'enable'))],
                [('⬅️ Pengaturan Pembayaran', 'owner:qris_settings')]]
        return await self._show(call, text, rows)

    async def callback(self, call, state):
        if not await self._access(call):
            return
        await self.host.safe_callback_notice(call)
        if not self._allowed(call):
            return
        data = str(call.data or '')
        try:
            if data in {PREFIX + 'menu', PREFIX + 'cancel'}:
                return await self.menu(call, state)
            if data == PREFIX + 'enable':
                self.config()
                if not self._allowed(call):
                    return
                self._set('enabled', '1')
                return await self.menu(call, state)
            if data == PREFIX + 'disable':
                self._set('enabled', '0')
                return await self.menu(call, state)
            if data == PREFIX + 'clear_qr':
                self._set('qr_file_id', '')
                return await self.menu(call, state)
            if data == PREFIX + 'preview':
                with self._connection() as conn:
                    raw = self._raw_config(conn)
                photo = _qr(raw['qr_file_id'])
                if not photo:
                    return await self._notice(call, 'QR Binance Pay belum dipasang.')
                if self._allowed(call):
                    try:
                        return await call.message.answer_photo(photo=photo, caption='💛 QR BINANCE PAY',
                            reply_markup=_keyboard([[('⬅️ Binance Pay', PREFIX + 'menu')]]))
                    except Exception:
                        return await self._notice(call, 'Preview QR belum dapat ditampilkan.')
            match = re.fullmatch(re.escape(PREFIX) + r'edit:(recipient|recipient_name|idr_per_usdt|qr_file_id)', data)
            if not match:
                raise BinancePayError('Menu Binance Pay tidak valid.')
            field = match[1]
            await self._clear(state)
            await state.update_data(binance_pay_field=field, binance_pay_form_at=time.time(),
                                    binance_pay_owner=int(call.from_user.id))
            await state.set_state(BinancePayState.qr if field == 'qr_file_id' else BinancePayState.field)
            prompt = {'recipient': 'Kirim Pay ID Binance (4–40 digit) atau email penerima.',
                      'recipient_name': 'Kirim nama penerima. Kirim - untuk mengosongkan.',
                      'idr_per_usdt': 'Kirim kurs IDR untuk 1 USDT, misalnya 16000. Tanpa pemisah ribuan; desimal memakai titik.',
                      'qr_file_id': 'Kirim QR penerima Binance Pay tanpa nominal tetap, sebagai foto Telegram.'}[field]
            return await self._show(call, '💛 <b>ATUR BINANCE PAY</b>\n\n' + prompt,
                                    [[('✖️ Batal', PREFIX + 'cancel')]])
        except BinancePayError as exc:
            return await self._notice(call, str(exc))
        except sqlite3.Error:
            return await self._notice(call, 'Pengaturan Binance Pay belum dapat disimpan. Coba lagi.')

    async def _form(self, message, state, expected):
        data = await state.get_data()
        stamp = data.get('binance_pay_form_at')
        if (data.get('binance_pay_owner') != message.from_user.id
                or data.get('binance_pay_field') not in expected
                or type(stamp) not in (int, float) or not 0 <= time.time() - stamp < FORM_SECONDS):
            await self._clear(state)
            raise BinancePayError('Form Binance Pay kedaluwarsa. Buka pengaturan kembali.')
        return data['binance_pay_field']

    async def field_input(self, message, state):
        if not await self._access(message):
            return
        try:
            field = await self._form(message, state, {'recipient', 'recipient_name', 'idr_per_usdt'})
            value = str(message.text or '').strip()
            value = (_recipient(value) if field == 'recipient' else
                     _name('' if value == '-' else value) if field == 'recipient_name' else
                     _decimal_text(_rate(value)))
            if not self._allowed(message):
                return
            self._set(field, value)
            await self._clear(state)
            return await self.menu(message, state)
        except BinancePayError as exc:
            return await self._notice(message, str(exc))
        except sqlite3.Error:
            return await self._notice(message, 'Pengaturan Binance Pay belum dapat disimpan. Coba lagi.')

    async def qr_input(self, message, state):
        if not await self._access(message):
            return
        try:
            await self._form(message, state, {'qr_file_id'})
            photos = getattr(message, 'photo', None)
            if not photos:
                raise BinancePayError('Kirim QR Binance Pay sebagai foto Telegram.')
            photo = _qr(photos[-1].file_id)
            if not photo or not self._allowed(message):
                return
            self._set('qr_file_id', photo)
            await self._clear(state)
            return await self.menu(message, state)
        except BinancePayError as exc:
            return await self._notice(message, str(exc))
        except sqlite3.Error:
            return await self._notice(message, 'QR Binance Pay belum dapat disimpan. Coba lagi.')


def register(router, gateway):
    router.callback_query.register(gateway.callback, F.data.startswith(PREFIX))
    router.message.register(gateway.field_input, BinancePayState.field, F.text & ~F.text.startswith('/'))
    router.message.register(gateway.qr_input, BinancePayState.qr,
                            F.photo | F.document | (F.text & ~F.text.startswith('/')))
    return gateway
