"""Choose a provider for NEW invoices; existing payments keep their original provider."""
import os
import sqlite3

from aiogram import F
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from klikqris_gateway import GatewayError, buyer_error, environment_value

METHODS = frozenset({'KLIKQRIS_AUTO', 'PAYINAJA_AUTO'})
ADAPTER_VERSION = '17.43'


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


async def checkout(host, call, bot, state, variant, qty):
    if not call.message or str(call.message.chat.type) != 'private' or call.message.chat.id != call.from_user.id:
        raise GatewayError('FORBIDDEN')
    gateway, row = other_pending(host, 'order', call.from_user.id, variant=variant, qty=qty)
    gateway = gateway or active(host)
    try:
        if row:
            # Read/check the old invoice. Never replace it using another provider.
            if gateway is host.PAYINAJA_GATEWAY and row['cancel_requested']:
                return await gateway.show_existing_cancellation(call, row['id'])
            return await gateway.show_status(call, row['id'])
        return await gateway.checkout(call, bot, state, variant, qty)
    except (GatewayError, sqlite3.Error) as exc:
        exc.provider = 'payinaja' if gateway is host.PAYINAJA_GATEWAY else 'klikqris'
        raise


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
