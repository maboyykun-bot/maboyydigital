"""Choose a provider for NEW invoices; existing payments keep their original provider."""
import os
import hashlib
import json
import re
import secrets
import sqlite3

from aiogram import F
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from klikqris_gateway import GatewayError, buyer_error, environment_value

METHODS = frozenset({'KLIKQRIS_AUTO', 'PAYINAJA_AUTO'})
ADAPTER_VERSION = '17.52'


def checkout_callback(variant, qty):
    return f'processauto:{variant}:{qty}:{secrets.token_hex(8)}'


def parse_checkout_callback(host, data):
    parts = str(data or '').split(':')
    if len(parts) not in {3, 4} or parts[0] != 'processauto':
        return None
    token = parts[3] if len(parts) == 4 else None
    if token is not None and not re.fullmatch('[0-9a-f]{16}', token):
        return None
    numbers = host.callback_positive_numbers(':'.join(parts[:3]), 'processauto', 2)
    return (*numbers, token) if numbers else None


def legacy_checkout_request(call, variant, qty):
    """Give old Telegram shop buttons a stable attempt identity as well."""
    message_id = getattr(getattr(call, 'message', None), 'message_id', None)
    user = getattr(getattr(call, 'from_user', None), 'id', None)
    if any(type(value) is not int or value <= 0 for value in (message_id, user, variant, qty)):
        return None
    return hashlib.sha256(f'legacy-shop:{user}:{message_id}:{variant}:{qty}'.encode()).hexdigest()[:16]


def _request_key(user, variant, qty, token):
    if (any(type(value) is not int or value <= 0 for value in (user, variant, qty))
            or not isinstance(token, str) or not re.fullmatch('[0-9a-f]{16}', token)):
        raise GatewayError('INPUT')
    return 'auto_qris_request:' + str(user) + ':' + token


def load_checkout_request(host, user, variant, qty, token, conn=None):
    if token is None:
        return None
    key = _request_key(user, variant, qty, token)
    own = conn is None
    conn = host.db() if own else conn
    try:
        found = conn.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        if found is None:
            return None
        try:
            if not isinstance(found[0], (str, bytes)) or len(found[0]) > 2048:
                raise ValueError
            data = json.loads(found[0])
            if (not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] != 1
                    or data.get('provider') not in {'klikqris', 'payinaja'}
                    or any(type(data.get(field)) is not int for field in ('user_id', 'variant_id', 'qty'))
                    or not isinstance(data.get('transaction_id'), str)
                    or not re.fullmatch('[A-Za-z0-9_-]{1,96}', data['transaction_id'])):
                raise ValueError
        except (ValueError, TypeError, UnicodeError):
            raise GatewayError('STORAGE') from None
        if (data['user_id'], data['variant_id'], data['qty']) != (user, variant, qty):
            raise GatewayError('INPUT')
        return data
    finally:
        if own:
            conn.close()


def checkout_request_row(host, provider, user, variant, qty, token, conn=None):
    own = conn is None
    conn = host.db() if own else conn
    try:
        record = load_checkout_request(host, user, variant, qty, token, conn=conn)
        if record is None:
            return None
        if record['provider'] != provider:
            raise GatewayError('CHECKOUT_BOUND')
        if provider == 'payinaja':
            row = host.PAYINAJA_GATEWAY.transaction(record['transaction_id'], user, conn=conn)
        else:
            found = conn.execute('SELECT * FROM klikqris_transactions WHERE id=? AND user_id=?',
                                 (record['transaction_id'], user)).fetchone()
            if found is None:
                raise GatewayError('STORAGE')
            row = dict(found)
        native = conn.execute('SELECT * FROM orders WHERE id=? AND user_id=? AND variant_id=? AND qty=?',
                              (row['entity_id'], user, variant, qty)).fetchone()
        expected = 'PAYINAJA_AUTO' if provider == 'payinaja' else 'KLIKQRIS_AUTO'
        if row['purpose'] != 'order' or not native or native['payment_method'] != expected:
            raise GatewayError('STORAGE')
        return row
    finally:
        if own:
            conn.close()


def save_checkout_request(host, provider, conn, user, variant, qty, token, transaction_id):
    if token is None:
        return
    key = _request_key(user, variant, qty, token)
    if provider not in {'klikqris', 'payinaja'} or not re.fullmatch('[A-Za-z0-9_-]{1,96}', transaction_id):
        raise GatewayError('INPUT')
    record = dict(version=1, user_id=user, provider=provider, variant_id=variant, qty=qty,
                  transaction_id=transaction_id)
    # Immutable request identity is committed atomically with its order/reservation.
    conn.execute('INSERT INTO settings(key,value) VALUES(?,?)', (key, json.dumps(record, sort_keys=True)))


def managed(row):
    try:
        return str(row['payment_method'] or '').strip().upper() in METHODS
    except (KeyError, IndexError, TypeError):
        return False


def selected(host):
    if 'AUTO_QRIS_PROVIDER' in os.environ:
        value, _ = environment_value('AUTO_QRIS_PROVIDER')
    else:
        conn = host.db()
        try:
            found = conn.execute("SELECT value FROM settings WHERE key='auto_qris_provider'").fetchone()
            value = found[0] if found else 'klikqris'
        finally:
            conn.close()
    name = value.strip().lower()
    if name not in {'klikqris', 'payinaja'}:
        raise GatewayError('CONFIG')
    return name


def active(host):
    return host.PAYINAJA_GATEWAY if selected(host) == 'payinaja' else host.KLIKQRIS_GATEWAY


def ready(host):
    try:
        return active(host).ready()
    except (GatewayError, sqlite3.Error):
        return False


def available(host):
    """Configured + owner-enabled may authenticate on click; this is not verified readiness."""
    try:
        gateway = active(host)
        return gateway.can_attempt() if gateway is host.PAYINAJA_GATEWAY else gateway.ready()
    except (GatewayError, sqlite3.Error):
        return False


def handles_checkout(host):
    try:
        return selected(host) == 'payinaja' or ready(host)
    except (GatewayError, sqlite3.Error):
        return True  # Surface CONFIG; never fall through to another provider.


def legacy_allowed(host):
    try:
        return selected(host) == 'klikqris'
    except (GatewayError, sqlite3.Error):
        return False


def active_method(host):
    return 'PAYINAJA_AUTO' if selected(host) == 'payinaja' else 'KLIKQRIS_AUTO'


def for_native(host, purpose, entity, conn=None):
    if purpose not in {'order', 'topup'}:
        return None
    own = conn is None
    conn = host.db() if own else conn
    try:
        row = conn.execute('SELECT payment_method FROM ' + ('orders' if purpose == 'order' else 'topups') + ' WHERE id=?',
                           (entity,)).fetchone()
        method = str(row[0] or '').strip().upper() if row else ''
        return (host.PAYINAJA_GATEWAY if method == 'PAYINAJA_AUTO' else
                host.KLIKQRIS_GATEWAY if method == 'KLIKQRIS_AUTO' else None)
    finally:
        if own:
            conn.close()


def linked(host, purpose, entity):
    gateway = for_native(host, purpose, entity)
    return gateway.linked(purpose, entity) if gateway is not None else None


def for_receipt(host, source, entity):
    if source == 'qris_review':
        return host.KLIKQRIS_GATEWAY
    return for_native(host, source, int(entity)) if source in {'order', 'topup'} else None


def protected_receipt(host, user, message):
    return (host.KLIKQRIS_GATEWAY.protected_receipt_message(user, message)
            or host.PAYINAJA_GATEWAY.protected_receipt_message(user, message))


def payment_authorized(host, conn, purpose, entity, *, settled=False):
    gateway = for_native(host, purpose, entity, conn)
    if gateway is host.PAYINAJA_GATEWAY:
        return gateway.payment_authorized(conn, purpose, entity, settled=settled)
    return bool(gateway and gateway.payment_authorized(conn, purpose, entity))


def record_failure(host, exc):
    provider = getattr(exc, 'provider', None)
    if provider is None:
        try:
            provider = selected(host)
        except (GatewayError, sqlite3.Error):
            provider = 'klikqris'
    if provider == 'payinaja':
        return host.PAYINAJA_GATEWAY.diagnostic(exc, 'checkout')
    return host.KLIKQRIS_GATEWAY.record_checkout_failure(exc)


def other_pending(host, purpose, user, *, variant=None, qty=None, amount=None):
    if selected(host) == 'klikqris':
        row = host.PAYINAJA_GATEWAY.resumable(purpose, user, variant=variant, qty=qty, amount=amount)
        return (host.PAYINAJA_GATEWAY, row) if row else (None, None)
    gateway = host.KLIKQRIS_GATEWAY
    if purpose == 'order':
        sql = """SELECT t.* FROM klikqris_transactions t JOIN orders n ON n.id=t.entity_id
            WHERE t.purpose='order' AND t.user_id=? AND n.variant_id=? AND n.qty=?
            AND n.payment_status!='paid' AND (n.status='pending' OR t.state IN ('REQUESTING','CREATE_UNKNOWN','CANCELLED_LOCAL'))
            AND t.state IN ('NEW','REQUESTING','CREATE_UNKNOWN','PENDING','PAID_VERIFIED','CANCELLED_LOCAL')
            AND NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||t.id)
            ORDER BY t.created_at DESC LIMIT 1"""
        args = (user, variant, qty)
    else:
        sql = """SELECT t.* FROM klikqris_transactions t JOIN topups n ON n.id=t.entity_id
            WHERE t.purpose='topup' AND t.user_id=? AND t.amount=?
            AND (n.status='pending' OR t.state IN ('REQUESTING','CREATE_UNKNOWN','CANCELLED_LOCAL'))
            AND t.state IN ('NEW','REQUESTING','CREATE_UNKNOWN','PENDING','PAID_VERIFIED','CANCELLED_LOCAL')
            AND NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||t.id)
            ORDER BY t.created_at DESC LIMIT 1"""
        args = (user, amount)
    row = gateway.one(sql, args)
    return (gateway, row) if row else (None, None)


async def checkout(host, call, bot, state, variant, qty, *, request_id=None):
    if not call.message or str(call.message.chat.type) != 'private' or call.message.chat.id != call.from_user.id:
        raise GatewayError('FORBIDDEN')
    await host.safe_callback_notice(call)
    await host.safe_edit_or_answer(call, '⏳ <b>Menyiapkan QRIS Otomatis</b>\n\nMohon tunggu, bot sedang menyiapkan pembayaran.',
        parse_mode='HTML', reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text='🏠 Menu Awal', callback_data='home')]]))
    gateway = None
    try:
        if request_id is not None:
            record = load_checkout_request(host, call.from_user.id, variant, qty, request_id)
            name = record['provider'] if record else selected(host)
            gateway = host.PAYINAJA_GATEWAY if name == 'payinaja' else host.KLIKQRIS_GATEWAY
            if record:
                row = checkout_request_row(host, name, call.from_user.id, variant, qty, request_id)
                if row['state'] != 'NEW':
                    return await gateway.show_status(call, row['id'])
            return await gateway.checkout(call, bot, state, variant, qty, request_id=request_id)
        gateway, row = other_pending(host, 'order', call.from_user.id, variant=variant, qty=qty)
        if row and gateway is host.PAYINAJA_GATEWAY and gateway.is_prior_session(row):
            row = await gateway.prior_checkout(row['id'])
            if row:
                return await gateway.show_prior_hold(call, row['id'])
            gateway = None
        gateway = gateway or active(host)
        if row:
            # Read/check the old invoice. Never replace it using another provider.
            if gateway is host.PAYINAJA_GATEWAY and row['cancel_requested']:
                return await gateway.show_existing_cancellation(call, row['id'])
            return await gateway.show_status(call, row['id'])
        return await gateway.checkout(call, bot, state, variant, qty)
    except (GatewayError, sqlite3.Error) as exc:
        if getattr(exc, 'code', '') == 'CHECKOUT_BOUND' and request_id is not None:
            record = load_checkout_request(host, call.from_user.id, variant, qty, request_id)
            gateway = host.PAYINAJA_GATEWAY if record['provider'] == 'payinaja' else host.KLIKQRIS_GATEWAY
            return await gateway.show_status(call, record['transaction_id'])
        if gateway is not None:
            exc.provider = 'payinaja' if gateway is host.PAYINAJA_GATEWAY else 'klikqris'
        row = None
        try:
            if request_id is not None:
                record = load_checkout_request(host, call.from_user.id, variant, qty, request_id)
                if record:
                    gateway = host.PAYINAJA_GATEWAY if record['provider'] == 'payinaja' else host.KLIKQRIS_GATEWAY
                    row = checkout_request_row(host, record['provider'], call.from_user.id, variant, qty, request_id)
            elif gateway is host.PAYINAJA_GATEWAY:
                row = gateway.resumable('order', call.from_user.id, variant=variant, qty=qty)
            elif gateway is not None:
                row = gateway.one("""SELECT t.* FROM klikqris_transactions t JOIN orders n ON n.id=t.entity_id
                    WHERE t.purpose='order' AND t.user_id=? AND n.variant_id=? AND n.qty=?
                    AND t.state IN ('NEW','REQUESTING','CREATE_UNKNOWN','PENDING','PAID_VERIFIED','CANCELLED_LOCAL')
                    AND NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||t.id)
                    ORDER BY t.created_at DESC LIMIT 1""", (call.from_user.id, variant, qty))
        except (GatewayError, sqlite3.Error):
            pass
        if row is not None:
            await host.safe_edit_or_answer(call, gateway.status_text(row) + '\nBot melanjutkan pemeriksaan secara otomatis.',
                parse_mode='HTML', reply_markup=gateway.user_keyboard(row))
        else:
            await host.safe_edit_or_answer(call, checkout_error_text(exc), parse_mode='HTML',
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text='🏠 Menu Awal', callback_data='home')]]))
        raise


def checkout_error_text(exc):
    code = getattr(exc, 'code', '')
    if code in {'STOCK', 'FORBIDDEN', 'RATE_LIMIT', 'LIMIT'}:
        return {'STOCK': 'Stok tidak mencukupi.', 'FORBIDDEN': 'Akses pembayaran ditolak.',
                'RATE_LIMIT': 'Terlalu banyak permintaan pembayaran. Tunggu sebentar.',
                'LIMIT': 'Batas pembelian tercapai. Hubungi owner.'}[code]
    if code in {'AUTH', 'MERCHANT_INACTIVE', 'CONFIG', 'NOT_READY'}:
        return 'QRIS Otomatis belum tersedia. Hubungi owner untuk memeriksa pengaturan pembayaran.'
    return 'QRIS belum dapat ditampilkan. Status invoice tetap diperiksa otomatis; hubungi owner jika belum muncul.'


async def prompt_buyer_cancel(host, call, purpose, entity):
    """Route legacy native buttons to the same Payinaja confirmation flow."""
    try:
        gateway = for_native(host, purpose, entity)
        if gateway is not host.PAYINAJA_GATEWAY:
            return False
        row = gateway.linked(purpose, entity)
        if row is None:
            raise GatewayError('NOT_FOUND')
        await gateway.prompt_cancel(call, row['id'])
    except (GatewayError, sqlite3.Error) as exc:
        await host.safe_callback_notice(call, 'Invoice belum dapat dibatalkan. Buka detail QRIS Otomatis.', show_alert=True)
    return True


async def owner_provider_menu(host, call):
    if not host.is_owner(call.from_user.id):
        raise GatewayError('FORBIDDEN')
    try:
        name = selected(host)
    except GatewayError:
        name = 'Konfigurasi AUTO_QRIS_PROVIDER perlu diperbaiki'
    text = ('⚙️ <b>PROVIDER QRIS OTOMATIS</b>\n\nPilihan untuk invoice baru: ' + name +
            '\nInvoice existing tetap diperiksa melalui provider asal. Pemilihan tidak membuat invoice atau mengaktifkan gateway.'
            '\nJika AUTO_QRIS_PROVIDER diisi di hosting, nilainya mengalahkan pilihan database.')
    rows = [
        [InlineKeyboardButton(text='Pilih KlikQRIS', callback_data='qrpg:select:klikqris'),
         InlineKeyboardButton(text='Pilih Payinaja', callback_data='qrpg:select:payinaja')],
        [InlineKeyboardButton(text='Panel KlikQRIS', callback_data='qrpg:open:klikqris'),
         InlineKeyboardButton(text='Panel Payinaja', callback_data='qrpg:open:payinaja')],
        [InlineKeyboardButton(text='⬅️ Kembali', callback_data='owner:auto_qris')]]
    await host.safe_edit_or_answer(call, text, parse_mode='HTML', reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))


def register(router, host):
    async def guard(call):
        if (not host.is_owner(call.from_user.id) or not call.message
                or str(call.message.chat.type) != 'private' or call.message.chat.id != call.from_user.id):
            raise GatewayError('FORBIDDEN')
        ok, _ = host.persistent_rate_limit(call.from_user.id, 'autoqris_callback', limit=20, window_seconds=60)
        if not ok:
            raise GatewayError('RATE_LIMIT')
        await host.safe_callback_notice(call)

    @router.callback_query((F.data == 'owner:auto_qris') | F.data.startswith('qrpg:'))
    async def automatic_qris_owner(call, state):
        try:
            await guard(call)
            await state.clear()
            if call.data == 'owner:auto_qris':
                return await active(host).owner_panel(call)
            parts = str(call.data).split(':')
            if parts == ['qrpg', 'menu']:
                return await owner_provider_menu(host, call)
            if len(parts) != 3 or parts[1] not in {'select', 'open'} or parts[2] not in {'klikqris', 'payinaja'}:
                raise GatewayError('INPUT')
            if parts[1] == 'select':
                if 'AUTO_QRIS_PROVIDER' in os.environ and selected(host) != parts[2]:
                    raise GatewayError('CONFIG')
                with host.db() as conn:
                    host.begin_immediate_retry(conn)
                    conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('auto_qris_provider',?)", (parts[2],))
            gateway = host.PAYINAJA_GATEWAY if parts[2] == 'payinaja' else host.KLIKQRIS_GATEWAY
            await gateway.owner_panel(call)
        except (GatewayError, sqlite3.Error) as exc:
            text = ('Akses ditolak.' if getattr(exc, 'code', '') == 'FORBIDDEN' else
                    'Provider belum dapat dipilih. Periksa AUTO_QRIS_PROVIDER dan database hosting.')
            await host.safe_callback_notice(call, text, show_alert=True)

    @router.callback_query(F.data.startswith('topupmethod:auto:'))
    async def automatic_qris_topup(call, state):
        gateway = None
        try:
            parts = str(call.data).split(':')
            if len(parts) != 3 or not parts[2].isdigit() or not 1 <= len(parts[2]) <= 12:
                raise GatewayError('INPUT')
            if not call.message or str(call.message.chat.type) != 'private' or call.message.chat.id != call.from_user.id:
                raise GatewayError('FORBIDDEN')
            amount = int(parts[2])
            await host.safe_callback_notice(call)
            gateway, row = other_pending(host, 'topup', call.from_user.id, amount=amount)
            if row and gateway is host.PAYINAJA_GATEWAY and gateway.is_prior_session(row):
                row = await gateway.prior_checkout(row['id'])
                if row:
                    return await gateway.show_prior_hold(call, row['id'])
                gateway = None
            if row:
                if gateway is host.PAYINAJA_GATEWAY and row['cancel_requested']:
                    return await gateway.show_existing_cancellation(call, row['id'])
                return await gateway.show_status(call, row['id'])
            gateway = active(host)
            await gateway.topup(call, amount, state)
        except (GatewayError, sqlite3.Error) as exc:
            if gateway is not None:
                exc.provider = 'payinaja' if gateway is host.PAYINAJA_GATEWAY else 'klikqris'
            record_failure(host, exc)
            text = ('Minimum QRIS Payinaja Rp500.' if getattr(exc, 'code', '') == 'MIN_AMOUNT' else buyer_error(exc))
            await host.safe_callback_notice(call, text, show_alert=True)
