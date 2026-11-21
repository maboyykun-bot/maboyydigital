"""Private manual AM activation, separate from every legacy/Temp Mail flow.

Only encrypted email and safe evidence are stored in settings. Magic links live
in the input handler's stack only. A committed POST claim is irreversible except
for an explicit provider HTTP 429 rejection, so restarts and button replays never
repeat a possibly completed request.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import html
import json
import re
import secrets
import sqlite3
import time
from urllib.parse import parse_qsl, urlsplit

from Crypto.Cipher import AES
from aiogram import F
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from am_service_client import (BASE_URL, AMServiceClient, AMServiceConfig,
                               AMServiceError, _email, _magic_link)

ADAPTER_VERSION = '17.68'
JOB_PREFIX = 'ammanual.flow.'
FSM_KEY = 'ammanual_job_id'
FORM_SECONDS = 15 * 60
IDENT = r'[0-9a-f]{16}'
TERMINAL = {'PREMIUM_ACTIVE', 'UNKNOWN', 'FAILED', 'ACCOUNT_CHANGED', 'EXPIRED'}
SAFE_CODES = {
    'AUTH', 'CONFIG', 'DISABLED', 'RATE_LIMITED', 'UPSTREAM', 'HTTP', 'TIMEOUT',
    'DNS', 'TLS', 'NETWORK', 'INVALID_JSON', 'SCHEMA', 'REJECTED', 'BAD_REQUEST',
    'INVALID_EMAIL', 'INVALID_MAGIC_LINK', 'MISMATCH', 'RESPONSE_TOO_LARGE',
    'NOT_FOUND', 'REDIRECT', 'QUOTA', 'ACCOUNT_CHANGED', 'SEND_UNKNOWN',
    'VERIFY_UNKNOWN', 'UNCONFIRMED', 'FORM_EXPIRED', 'LOCAL_ERROR',
}


class ManualState(StatesGroup):
    email = State()
    confirm = State()
    link = State()


# A descriptive alias is useful to integrations without coupling the FSM name.
AMManualState = ManualState


def _http(value):
    return value if type(value) is int and 100 <= value <= 599 else 0


def _safe_code(exc):
    code = getattr(exc, 'code', '')
    return code if isinstance(code, str) and code in SAFE_CODES else 'LOCAL_ERROR'


def _keyboard(rows):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=text, callback_data=data) for text, data in row]
        for row in rows])


def input_reply_form(message):
    """Identify our input prompt without storing the private reply or link."""
    reply = getattr(message, 'reply_to_message', None)
    text = str(getattr(reply, 'text', '') or '')
    if not text.startswith('🔗 MASUKKAN MAGIC LINK\n'):
        return None
    match = re.search(r'\nForm AM: (' + IDENT + r')\Z', text)
    return match[1] if match else None


class GatewayManual:
    def __init__(self, host, config=None):
        self.host = host
        self.config = config if config is not None else AMServiceConfig.from_env()
        self.client = AMServiceClient(self.config)
        self._state_locks = {}
        self._input_callbacks = {}

    async def close(self):
        await self.client.close()
        self._state_locks.clear()
        self._input_callbacks.clear()

    def configured(self):
        return self.config.enabled is True and self.config.valid()

    def _key(self):
        key = self.host.temp_mail_encryption_key()
        if not isinstance(key, bytes) or len(key) not in {16, 24, 32}:
            raise AMServiceError('CONFIG')
        return key

    def fingerprint(self):
        # Only hashes are persisted; neither provider nor encryption keys leave
        # the process. Timeout changes do not alter account identity.
        identity = [BASE_URL, self.config.api_key, hashlib.sha256(self._key()).hexdigest()]
        return hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()

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

    @staticmethod
    def _load(conn, ident):
        if not isinstance(ident, str) or not re.fullmatch(IDENT, ident):
            return None
        row = conn.execute('SELECT value FROM settings WHERE key=?', (JOB_PREFIX + ident,)).fetchone()
        if not row:
            return None
        try:
            job = json.loads(row['value'])
        except (ValueError, TypeError):
            return None
        if (not isinstance(job, dict) or job.get('id') != ident
                or type(job.get('actor_id')) is not int
                or not isinstance(job.get('nonce'), str)
                or not re.fullmatch(IDENT, job['nonce'])):
            return None
        return job

    @staticmethod
    def _save(conn, job):
        conn.execute('INSERT INTO settings(key,value) VALUES(?,?) '
                     'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                     (JOB_PREFIX + job['id'], json.dumps(job, separators=(',', ':'))))

    @classmethod
    def _rows(cls, conn, actor):
        rows = conn.execute('SELECT key FROM settings WHERE key LIKE ? ORDER BY rowid DESC',
                            (JOB_PREFIX + '%',)).fetchall()
        return [job for row in rows
                if (job := cls._load(conn, row['key'][len(JOB_PREFIX):]))
                and job['actor_id'] == actor]

    def job(self, actor, ident):
        with self._connection() as conn:
            job = self._load(conn, ident)
        return job if job and job['actor_id'] == int(actor) else None

    def _update(self, actor, ident, nonce, **changes):
        with self._connection(True) as conn:
            job = self._load(conn, ident)
            if not job or job['actor_id'] != actor or job['nonce'] != nonce:
                return None
            job.update(changes, updated_at=time.time())
            self._save(conn, job)
            return job

    def _draft(self, actor):
        job = dict(id=secrets.token_hex(8), nonce=secrets.token_hex(8), actor_id=actor,
                   fingerprint=self.fingerprint(), created_at=time.time(), updated_at=time.time(),
                   active=False, status='DRAFT', email_secret='', send_state='NEW',
                   verify_state='NEW', code='', http_status=0, retry_at=0,
                   lease_token='', lease_until=0, valid_until='', plan_name='')
        with self._connection(True) as conn:
            self._save(conn, job)
        return job

    def _deactivate(self, actor, ident=None):
        with self._connection(True) as conn:
            for job in self._rows(conn, actor):
                if job.get('active') and (ident is None or job['id'] == ident):
                    job.update(active=False, updated_at=time.time())
                    self._save(conn, job)

    def _erase(self, actor, ident, nonce):
        """Forget one cancelled form without resetting consumed request usage."""
        with self._connection(True) as conn:
            job = self._load(conn, ident)
            if (not job or job['actor_id'] != actor or job['nonce'] != nonce
                    or not job.get('active') or job.get('status') == 'PREMIUM_ACTIVE'):
                return False
            conn.execute('DELETE FROM settings WHERE key=?', (JOB_PREFIX + ident,))
            # The request has already consumed provider allowance. Keep units
            # and request outcomes, but remove the cancelled form's email.
            conn.execute("UPDATE tool_account_quotas SET target_email='' WHERE owner_id=? AND quota_key=?",
                         (actor, 'flow:ammanual:' + ident))
            return True

    def _activate(self, actor, ident, nonce, *, resume=False):
        with self._connection(True) as conn:
            job = self._load(conn, ident)
            if (not job or job['actor_id'] != actor or job['nonce'] != nonce
                    or self._expired(job) or job['status'] in TERMINAL):
                return None
            others = [row for row in self._rows(conn, actor)
                      if row.get('active') and row['id'] != ident]
            if resume:
                # An old history button must never hijack a newer input session.
                if others or job['status'] != 'WAIT_LINK':
                    return None
                # Keep an active card usable when Telegram rejects its edit.
                # Reopening an abandoned history form still invalidates its
                # previous buttons before starting a new input session.
                if not job.get('active'):
                    job['nonce'] = secrets.token_hex(8)
            else:
                if job['status'] != 'DRAFT' or any(row['created_at'] > job['created_at'] for row in others):
                    return None
                for row in others:
                    row['active'] = False
                    self._save(conn, row)
                job['status'] = 'EMAIL'
            job.update(active=True, updated_at=time.time())
            self._save(conn, job)
            return job

    @staticmethod
    def _expired(job):
        return time.time() - float(job['created_at']) >= FORM_SECONDS

    def _encrypt_email(self, job, email):
        cipher = AES.new(self._key(), AES.MODE_GCM)
        cipher.update(f"MaboyyDigital/AMManual/v1:{job['actor_id']}:{job['id']}".encode())
        encrypted, tag = cipher.encrypt_and_digest(email.encode())
        return 'v1:' + base64.urlsafe_b64encode(cipher.nonce + tag + encrypted).decode()

    def _set_email(self, job, secret):
        with self._connection(True) as conn:
            current = self._load(conn, job['id'])
            if (not current or current['actor_id'] != job['actor_id']
                    or current['nonce'] != job['nonce'] or not current.get('active')
                    or current['status'] != 'EMAIL' or current['send_state'] != 'NEW'
                    or self._expired(current)):
                return None
            current.update(email_secret=secret, status='CONFIRM_SEND', updated_at=time.time())
            self._save(conn, current)
            return current

    def _decrypt_email(self, job):
        try:
            if job['fingerprint'] != self.fingerprint():
                raise ValueError
            secret = job['email_secret']
            if not isinstance(secret, str) or not secret.startswith('v1:') or len(secret) > 1024:
                raise ValueError
            raw = base64.b64decode(secret[3:], altchars=b'-_', validate=True)
            if len(raw) < 33:
                raise ValueError
            cipher = AES.new(self._key(), AES.MODE_GCM, nonce=raw[:16])
            cipher.update(f"MaboyyDigital/AMManual/v1:{job['actor_id']}:{job['id']}".encode())
            return _email(cipher.decrypt_and_verify(raw[32:], raw[16:32]).decode())
        except Exception:
            raise AMServiceError('ACCOUNT_CHANGED') from None

    def _live(self, event):
        user = getattr(event, 'from_user', None)
        chat = getattr(event, 'chat', None) or getattr(getattr(event, 'message', None), 'chat', None)
        if not user or not chat or str(chat.type) != 'private' or chat.id != user.id:
            return False
        actor = int(user.id)
        if self.host.security_blocked(actor):
            return False
        return bool(self.host.is_owner(actor) or self.host.tools_user_allowed(actor))

    async def _access(self, event, state):
        # The public guard applies to owners too, including blocked accounts.
        if not await self.host.tools_vip_public_guard(event):
            await self._deny_session(event, state)
            return False
        chat = getattr(event, 'chat', None) or getattr(getattr(event, 'message', None), 'chat', None)
        if not chat or str(chat.type) != 'private' or chat.id != event.from_user.id:
            await self._deny_session(event, state)
            return False
        if not self.host.is_owner(event.from_user.id):
            if not await self.host.require_tools_user(event, state):
                await self._deny_session(event, state)
                return False
        allowed = self._live(event)
        if not allowed:
            await self._deny_session(event, state)
        return allowed

    async def _deny_session(self, event, state):
        data = await state.get_data()
        actor = int(event.from_user.id)
        job = self.job(actor, data.get(FSM_KEY))
        if job:
            self._deactivate(actor, job['id'])
        await self._clear_manual(state)

    async def _session(self, event, state, job):
        if not job:
            return False
        data = await state.get_data()
        current_state = await state.get_state()
        current = self.job(job['actor_id'], job['id'])
        return bool(self._live(event) and data.get(FSM_KEY) == job['id'] and current
                    and current_state in {ManualState.email.state, ManualState.confirm.state, ManualState.link.state}
                    and current.get('active') and current['nonce'] == job['nonce'])

    async def _clear_manual(self, state, *, ident=None):
        # Never erase legacy tools/checkout data or a newer manual session.
        data = await state.get_data()
        if ident is not None and data.get(FSM_KEY) != ident:
            return
        if FSM_KEY in data:
            data.pop(FSM_KEY, None)
            await state.set_data(data)
        current = await state.get_state()
        if current in {ManualState.email.state, ManualState.confirm.state, ManualState.link.state}:
            await state.set_state(None)

    def _lock(self, actor):
        return self._state_locks.setdefault(actor, asyncio.Lock())

    async def _ui(self, event, text, rows):
        markup = _keyboard(rows)
        if hasattr(event, 'data') and getattr(event, 'message', None) is not None:
            return await self.host.safe_edit_or_answer(event, text, reply_markup=markup, parse_mode='HTML')
        return await event.answer(text, reply_markup=markup, parse_mode='HTML')

    async def _edit_card(self, message, text, rows):
        """Edit a known card once; an uncertain edit must not send a duplicate."""
        try:
            await message.edit_text(text, reply_markup=_keyboard(rows), parse_mode='HTML')
            return True
        except Exception as exc:
            return 'message is not modified' in str(exc).lower()

    async def _notice(self, event, text):
        if hasattr(event, 'data'):
            return await self.host.safe_callback_notice(event, text, show_alert=True)
        return await event.answer(text)

    @staticmethod
    def _button(action, job):
        return 'amman:' + action + ':' + job['id'] + ':' + job['nonce']

    def _back(self, actor):
        return ('⬅️ Owner Tools', 'tools:home') if self.host.is_owner(actor) else ('⬅️ /tools', 'utools:home')

    def _title(self, actor):
        return 'AM MANUAL • API BARU' if self.host.is_owner(actor) else 'AKTIVASI AM PRO'

    async def menu(self, call, state, *, history_only=False):
        if not await self._access(call, state):
            return
        if hasattr(call, 'data'):
            await self.host.safe_callback_notice(call)
            if not await self._access(call, state):
                return
        actor = int(call.from_user.id)
        self._deactivate(actor)
        async with self._lock(actor):
            await self._clear_manual(state)
        if not await self._access(call, state):
            return
        with self._connection() as conn:
            jobs = [job for job in self._rows(conn, actor) if job['status'] != 'DRAFT'][:5]
        details = ('Web: <b>am-api-service.vercel.app</b>\n'
                   'Paket Free: <b>50 requests/hari</b>, dibagi seluruh pemakai API key yang sama. '
                   'Satu aktivasi biasanya memakai 2 requests (send + verify).\n\n'
                   if self.host.is_owner(actor) else
                   'Batas layanan bersama: <b>50 requests/hari</b>. '
                   'Satu aktivasi biasanya memakai 2 requests.\n\n')
        text = ('⚡ <b>' + self._title(actor) + '</b>\n\n' + details +
                '1. Masukkan email milik Anda.\n'
                '2. Kirim Magic Link ke email tersebut.\n'
                '3. Salin tautan dari email, lalu tempel ke bot.\n\n'
                'Form berlaku 15 menit.')
        owner = self.host.is_owner(actor)
        if not owner:
            text = ('📧 <b>AKTIVASI AM PRO</b>\n\n'
                    '<b>Langkah 1/3 — Masukkan email</b>\n'
                    '1. Masukkan email milik Anda.\n'
                    '2. Kirim Magic Link ke email tersebut.\n'
                    '3. Salin tautan dari email, lalu tempel ke bot.\n\n'
                    'Form berlaku 15 menit.')
        if history_only:
            text = ('📋 <b>RIWAYAT AKTIVASI</b>\n\n'
                    'Pilih proses untuk melihat hasil atau melanjutkan input tautan dari email Anda.'
                    if jobs else '📋 <b>RIWAYAT AKTIVASI</b>\n\nBelum ada proses aktivasi tersimpan.')
        rows = []
        if self.configured() and not history_only:
            try:
                draft = self._draft(actor)
                rows.append([('📧 Mulai dengan Email', self._button('new', draft))])
            except Exception:
                text += '\n\nStatus: CONFIG'
        elif not history_only:
            text += '\n\nStatus: ' + ('DISABLED' if not self.config.enabled else 'CONFIG')
        if history_only:
            rows += [[('📋 ' + job['id'] + ' • ' + job['status'], self._button('view', job))] for job in jobs]
            rows.append([('⬅️ Aktivasi AM Pro', 'amman:menu')])
        else:
            rows.append([('📋 Riwayat Aktivasi', 'amman:history')])
            rows.append([self._back(actor)])
        if self._live(call):
            return await self._ui(call, text, rows)

    async def _render(self, event, state, job, *, session=False, output=None):
        if not job:
            return
        if not await self._access(event, state):
            return
        current = self.job(int(event.from_user.id), job['id'])
        if not current or current['nonce'] != job['nonce']:
            return
        if session and not await self._session(event, state, current):
            return
        labels = {'EMAIL': 'Masukkan email', 'CONFIRM_SEND': 'Konfirmasi kirim',
                  'WAIT_LINK': 'Menunggu Magic Link', 'RUNNING': 'Diproses',
                  'PREMIUM_ACTIVE': '✅ PREMIUM ACTIVE', 'UNKNOWN': 'Hasil belum terkonfirmasi',
                  'FAILED': 'Belum berhasil', 'ACCOUNT_CHANGED': 'Konfigurasi akun berubah',
                  'EXPIRED': 'Form kedaluwarsa'}
        if not self.host.is_owner(event.from_user.id):
            labels['WAIT_LINK'] = 'Langkah 2/3 — Kirim Magic Link'
            labels['CONFIRM_SEND'] = 'Langkah 1/3 — Konfirmasi email'
        text = ('⚡ <b>' + self._title(int(event.from_user.id)) + '</b>\n\nCID: <code>' + current['id']
                + '</code>\nStatus: <b>' + labels.get(current['status'], 'Menunggu') + '</b>\n')
        try:
            email = self._decrypt_email(current) if current.get('email_secret') else ''
        except AMServiceError:
            email = ''
            text += 'Kode: ACCOUNT_CHANGED\n'
        if email:
            text += 'Email: <code>' + html.escape(email) + '</code>\n'
        rows = []
        if current['status'] == 'CONFIRM_SEND':
            text += '\nTekan Kirim untuk mengirim Magic Link ke email ini. Pengiriman bukan bukti premium aktif.'
            if current['send_state'] == 'NEW' and not self._expired(current):
                rows.append([('📨 Kirim Magic Link', self._button('send', current))])
        elif current['status'] == 'WAIT_LINK':
            text += ('\n1. Buka Inbox/Spam.\n'
                     '2. Salin tautan tombol Masuk / Sign in di email.\n'
                     '3. Tekan <b>Masukkan Magic Link</b>, lalu tempel URL ke bot.\n\n'
                     'Belum masuk? Periksa alamat/Spam atau hubungi owner.')
            if not self._expired(current):
                rows.append([('🔗 Masukkan Magic Link', self._button('resume', current))])
        elif current['status'] == 'PREMIUM_ACTIVE':
            text += 'Berlaku sampai: <b>' + html.escape(self.host.format_wib_datetime(
                current['valid_until'], seconds=True, compact=True)) + '</b>\n'
            if current.get('plan_name'):
                plan = current['plan_name'] if self.host.is_owner(event.from_user.id) else 'Alight Motion Pro'
                text += 'Paket: ' + html.escape(plan) + '\n'
        notes = {
            'SEND_UNKNOWN': 'Pengiriman belum pasti; permintaan tidak diulang. Jika email masuk, gunakan link dari email ini.',
            'VERIFY_UNKNOWN': 'Hasil verifikasi belum pasti. Verifikasi tidak diulang; periksa akun Anda.',
            'UNCONFIRMED': 'Respons belum membuktikan premium aktif beserta masa berlakunya.',
            'RATE_LIMITED': 'Provider menolak dengan HTTP 429. Tunggu batas Retry-After lalu lakukan tindakan lagi secara manual.',
            'QUOTA': 'Kuota /tools belum tersedia. Pengiriman belum dilakukan.',
            'FORM_EXPIRED': 'Form melewati 15 menit. Hasil tersimpan; permintaan baru dari form ini ditolak.',
        }
        code = current.get('code', '')
        if code in SAFE_CODES:
            text += '\nKode: ' + code + '\n' + notes.get(code, '')
        if current.get('verify_state') == 'UNKNOWN' and code not in {'VERIFY_UNKNOWN', 'UNCONFIRMED'}:
            text += '\n' + notes['VERIFY_UNKNOWN']
        elif current.get('send_state') == 'UNKNOWN' and current.get('verify_state') == 'NEW' and code != 'SEND_UNKNOWN':
            text += '\n' + notes['SEND_UNKNOWN']
        if _http(current.get('http_status')):
            text += '\nHTTP: ' + str(current['http_status'])
        if current.get('retry_at', 0) > time.time():
            text += '\nCoba manual lagi setelah: ' + self.host.format_wib_datetime(
                current['retry_at'], seconds=True, compact=True)
        if current.get('active') and current['status'] not in TERMINAL:
            rows.append([('✖️ Batalkan Form', self._button('cancel', current))])
        if self._rating_eligible(current):
            rows.append([('⭐ Rating Toko', self._button('rating', current))])
        rows.append([('⬅️ Aktivasi AM Pro', 'amman:menu')])
        if self._live(event):
            if output is not None:
                delivered = await self._edit_card(output, text, rows)
                if not delivered and self._live(event):
                    # A repeated edit targets the same message, so it cannot
                    # duplicate cards or repeat a provider request.
                    delivered = await self._edit_card(output, text, rows)
                return delivered
            return await self._ui(event, text, rows)

    def _rating_eligible(self, job):
        if (not job or self.host.is_owner(job['actor_id'])
                or job.get('status') != 'PREMIUM_ACTIVE' or job.get('verify_state') != 'DONE'
                or job.get('send_state') not in {'DONE', 'UNKNOWN'} or job.get('http_status') != 200):
            return False
        try:
            # Completed use can be reviewed later, including after expiry or
            # a key change. The original result already passed strict proof.
            until = datetime.fromisoformat(job.get('valid_until', '').replace('Z', '+00:00'))
            return until.tzinfo is not None and until.utcoffset() is not None
        except (ValueError, TypeError, AttributeError):
            return False

    def rating_entry(self, actor):
        """Expose only the latest owned success's callback, never its email."""
        try:
            with self._connection() as conn:
                job = next((row for row in self._rows(conn, actor) if self._rating_eligible(row)), None)
        except sqlite3.Error:
            return None
        return ('⭐ Rating Toko', self._button('rating', job)) if job else None

    async def _rating(self, call, state, job, stars=None):
        if not await self._access(call, state):
            return
        actor = int(call.from_user.id)
        try:
            with self._connection(stars is not None) as conn:
                current = self._load(conn, job['id'])
                if (not current or current['actor_id'] != actor or current['nonce'] != job['nonce']
                        or not self._rating_eligible(current) or not self._live(call)):
                    raise ValueError('Rating tersedia setelah aktivasi Anda berhasil.')
                existing = conn.execute("SELECT user_id,rating FROM purchase_rating_requests "
                    "WHERE source='ammanual' AND entity_key=?", (current['id'],)).fetchone()
                if existing and existing['user_id'] != actor:
                    raise ValueError('Rating tidak valid.')
                if existing and (type(existing['rating']) is not int or not 1 <= existing['rating'] <= 5):
                    raise ValueError('Rating tidak valid.')
                if stars is not None:
                    if type(stars) is not int or not 1 <= stars <= 5:
                        raise ValueError('Rating tidak valid.')
                    if not existing:
                        conn.execute("INSERT INTO purchase_rating_requests(source,entity_key,user_id,reference,"
                            "item_name,rating,rated_at) VALUES('ammanual',?,?,?,?,?,?)",
                            (current['id'], actor, 'AM-' + current['id'], 'Alight Motion Pro', stars,
                             datetime.now(timezone.utc).isoformat(timespec='seconds')))
                        saved_stars = stars
                    else:
                        saved_stars = int(existing['rating'])
                else:
                    saved_stars = int(existing['rating']) if existing and existing['rating'] else 0
        except ValueError as exc:
            return await self._notice(call, str(exc))
        except sqlite3.Error:
            return await self._notice(call, 'Rating belum dapat diproses. Coba lagi sebentar.')
        if not await self._access(call, state):
            return
        back = self._button('view', current)
        if saved_stars:
            text = self.host.rating_receipt_text(saved_stars, subtitle='Penilaian Anda sudah tersimpan.')
            rows = [[('⬅️ Hasil Aktivasi', back)], [('⭐ Rating Toko', self._button('rating', current))],
                    [('⬅️ Aktivasi AM Pro', 'amman:menu')]]
            return await self._ui(call, text, rows)
        text = ('⭐ <b>RATING TOKO</b>\n\n' + self.host.rating_summary_card(self.host.store_rating_summary())
                + '\n\nAktivasi berhasil. Pilih penilaian 1–5:\n' + self.host.rating_scale_text())
        keyboard = self.host.rating_choice_keyboard(self._button('rate', current), back, '⬅️ Hasil Aktivasi')
        if self._live(call):
            return await self.host.safe_edit_or_answer(call, text, reply_markup=keyboard, parse_mode='HTML')

    def _recover(self, job):
        # Reload and transition inside one write transaction. A stale reader
        # cannot replace another process's fresh lease or completed evidence.
        with self._connection(True) as conn:
            current = self._load(conn, job['id'])
            if not current or current['actor_id'] != job['actor_id'] or current['nonce'] != job['nonce']:
                return None
            if current.get('lease_until', 0) > time.time():
                return current
            for stage in ('verify', 'send'):
                if current.get(stage + '_state') == 'CLAIMED':
                    current.update(**{stage + '_state': 'UNKNOWN'},
                                   status='UNKNOWN' if stage == 'verify' else 'WAIT_LINK',
                                   code='VERIFY_UNKNOWN' if stage == 'verify' else 'SEND_UNKNOWN',
                                   lease_token='', lease_until=0, updated_at=time.time())
                    self._save(conn, current)
                    break
            return current

    def _lease(self, job, stage):
        with self._connection(True) as conn:
            current = self._load(conn, job['id'])
            if (not current or current['actor_id'] != job['actor_id'] or current['nonce'] != job['nonce']
                    or not current.get('active') or current.get(stage + '_state') != 'NEW'
                    or current.get('lease_until', 0) > time.time()
                    or current.get('retry_at', 0) > time.time()):
                return None
            current.update(lease_token=secrets.token_hex(16),
                           lease_until=time.time() + self.config.timeout_seconds + 60)
            self._save(conn, current)
            return current

    def _claim(self, job, stage):
        with self._connection(True) as conn:
            current = self._load(conn, job['id'])
            if (not current or current['actor_id'] != job['actor_id'] or current['nonce'] != job['nonce']
                    or not current.get('active') or current.get(stage + '_state') != 'NEW'
                    or current.get('lease_token') != job['lease_token'] or self._expired(current)):
                return None
            current.update(**{stage + '_state': 'CLAIMED'}, status='RUNNING', code='', http_status=0)
            self._save(conn, current)
            return current

    def _claimed_update(self, job, stage, **changes):
        # Navigation may deactivate the form, but cannot discard in-flight evidence.
        with self._connection(True) as conn:
            current = self._load(conn, job['id'])
            if (not current or current['actor_id'] != job['actor_id'] or current['nonce'] != job['nonce']
                    or current.get('lease_token') != job['lease_token']
                    or current.get(stage + '_state') != 'CLAIMED'):
                return None
            current.update(changes, updated_at=time.time(), lease_token='', lease_until=0)
            self._save(conn, current)
            return current

    def _release(self, job):
        with self._connection(True) as conn:
            current = self._load(conn, job['id'])
            if current is None:
                # Another process may cancel after our last session check but
                # before metering commits. Do not let that reservation restore
                # the deleted form's plaintext email.
                conn.execute("UPDATE tool_account_quotas SET target_email='' WHERE owner_id=? AND quota_key=?",
                             (job['actor_id'], 'flow:ammanual:' + job['id']))
            if current and current.get('lease_token') == job.get('lease_token'):
                current.update(lease_token='', lease_until=0)
                self._save(conn, current)

    def _finish(self, request, status, http_status=0):
        try:
            self.host._finish_tool_provider_request(request, status, _http(http_status))
        except Exception:
            pass

    def _ready_job(self, job):
        code = ''
        if not self.configured():
            code = 'DISABLED' if not self.config.enabled else 'CONFIG'
        elif getattr(self.client, 'config', self.config) != self.config:
            code = 'CONFIG'
        else:
            try:
                if job['fingerprint'] != self.fingerprint():
                    code = 'ACCOUNT_CHANGED'
            except Exception:
                code = 'CONFIG'
        if not code and self._expired(job):
            code = 'FORM_EXPIRED'
        if code:
            changes = {'code': code}
            if code == 'ACCOUNT_CHANGED':
                changes['status'] = 'ACCOUNT_CHANGED'
            return self._update(job['actor_id'], job['id'], job['nonce'], **changes), False
        return job, True

    @staticmethod
    def _validate_link(raw, email):
        link = _magic_link(raw)
        # Some documented Firebase links carry an email in an outer or nested
        # query. Such a recipient must agree with the encrypted original email.
        pending, seen = [link], set()
        for _ in range(5):
            if not pending:
                break
            value = pending.pop()
            if value in seen:
                continue
            seen.add(value)
            try:
                fields = parse_qsl(urlsplit(value).query, keep_blank_values=True, max_num_fields=64)
            except (ValueError, UnicodeError):
                raise AMServiceError('INVALID_MAGIC_LINK') from None
            for key, item in fields:
                if key.casefold() == 'email' and _email(item) != email:
                    raise AMServiceError('MISMATCH')
                if key.casefold() in {'link', 'continueurl', 'deep_link_id'} and item.startswith('https://'):
                    pending.append(item)
        if pending:
            raise AMServiceError('INVALID_MAGIC_LINK')
        return link

    def _evidence(self, result):
        if not isinstance(result, dict) or result.get('status') != 'PREMIUM_ACTIVE' or _http(result.get('http_status')) != 200:
            return None
        until = result.get('valid_until')
        if not isinstance(until, str) or len(until) > 64:
            return None
        try:
            stamp = datetime.fromisoformat(until.replace('Z', '+00:00'))
            if stamp.tzinfo is None or stamp.utcoffset() is None or stamp <= datetime.now(timezone.utc):
                return None
        except (ValueError, OverflowError):
            return None
        plan = result.get('plan_name')
        if (not isinstance(plan, str) or not 1 <= len(plan) <= 120
                or not all(char.isprintable() for char in plan)
                or any(marker in plan for marker in ('://', '@', '<', '>', self.config.api_key))):
            plan = ''
        return stamp.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'), plan

    async def _post(self, event, state, job, *, link=None):
        stage = 'verify' if link is not None else 'send'
        job = self._recover(job)
        if not job or job.get(stage + '_state') != 'NEW':
            if job:
                return await self._render(event, state, job, session=True)
            return
        job, ready = self._ready_job(job)
        if not ready:
            return await self._render(event, state, job, session=True)
        # The UI await is deliberately before both quota and dispatch claims.
        # Access/session are checked again after it, so navigation/revocation
        # while Telegram is slow cannot issue an abandoned POST.
        if not await self._session(event, state, job):
            return
        sent = await self._ui(event, '⏳ Memproses AM Manual…\nCID: <code>' + job['id'] + '</code>',
                              [[('⬅️ AM Manual', 'amman:menu')]])
        # A message input creates one progress card. Replace that exact card
        # with its result instead of leaving its processing button behind.
        output = None if hasattr(event, 'data') else sent
        if (type(getattr(output, 'message_id', None)) is not int
                or getattr(getattr(output, 'chat', None), 'id', None) != job['actor_id']):
            output = None
        if not await self._access(event, state) or not await self._session(event, state, job):
            return
        job, ready = self._ready_job(job)
        if not ready:
            return await self._render(event, state, job, session=True, output=output)
        try:
            email = self._decrypt_email(job)
        except AMServiceError:
            job = self._update(job['actor_id'], job['id'], job['nonce'], status='ACCOUNT_CHANGED', code='ACCOUNT_CHANGED')
            return await self._render(event, state, job, session=True, output=output)
        leased = self._lease(job, stage)
        if not leased:
            return await self._render(event, state, self.job(job['actor_id'], job['id']), session=True, output=output)
        request = 0
        try:
            # Reservation uses its own SQLite transaction, outside our lease CAS.
            if not self._live(event):
                return
            request = self.host._reserve_tool_provider_request(
                job['actor_id'], 'POST', target_email=email,
                correlation_id='ammanual:' + job['id'], count_account=True)
            if not request:
                current = self._update(job['actor_id'], job['id'], job['nonce'], code='QUOTA')
                self._release(leased)
                return await self._render(event, state, current, session=True, output=output)
            # No await separates this live check, the durable claim and POST.
            if (not self._live(event) or not self.configured()
                    or getattr(self.client, 'config', self.config) != self.config
                    or job['fingerprint'] != self.fingerprint()):
                self._finish(request, 'failed')
                return
            claimed = self._claim(leased, stage)
            if not claimed:
                self._finish(request, 'failed')
                return
            try:
                if stage == 'verify':
                    result = await self.client.verify_link(email, link)
                else:
                    result = await self.client.send_link(email)
            except asyncio.CancelledError:
                self._finish(request, 'unknown')
                self._claimed_update(claimed, stage, **{stage + '_state': 'UNKNOWN'},
                                     status='UNKNOWN' if stage == 'verify' else 'WAIT_LINK',
                                     code='VERIFY_UNKNOWN' if stage == 'verify' else 'SEND_UNKNOWN')
                raise
            except Exception as exc:
                code, status = _safe_code(exc), _http(getattr(exc, 'http_status', 0))
                retryable = isinstance(exc, AMServiceError) and code == 'RATE_LIMITED' and status == 429 and not exc.uncertain
                uncertain = not isinstance(exc, AMServiceError) or bool(exc.uncertain)
                self._finish(request, 'unknown' if uncertain else 'failed', status)
                if retryable:
                    delay = getattr(exc, 'retry_after', 60)
                    delay = min(86400, max(1, delay)) if type(delay) is int else 60
                    self._claimed_update(claimed, stage, **{stage + '_state': 'NEW'},
                                         status='WAIT_LINK' if stage == 'verify' else 'CONFIRM_SEND',
                                         code=code, http_status=status, retry_at=time.time() + delay)
                else:
                    self._claimed_update(claimed, stage, **{stage + '_state': 'UNKNOWN' if uncertain else 'FAILED'},
                                         status=('UNKNOWN' if stage == 'verify' else 'WAIT_LINK') if uncertain else 'FAILED',
                                         code=code, http_status=status, retry_at=0)
            else:
                status = _http(result.get('http_status')) if isinstance(result, dict) else 0
                if stage == 'verify':
                    evidence = self._evidence(result)
                    self._finish(request, 'success' if evidence else 'unknown', status)
                    self._claimed_update(claimed, stage, verify_state='DONE' if evidence else 'UNKNOWN',
                                         status='PREMIUM_ACTIVE' if evidence else 'UNKNOWN',
                                         code='' if evidence else 'UNCONFIRMED', http_status=status,
                                         valid_until=evidence[0] if evidence else '', plan_name=evidence[1] if evidence else '', retry_at=0)
                else:
                    accepted = isinstance(result, dict) and result.get('accepted') is True and status == 200
                    self._finish(request, 'success' if accepted else 'unknown', status)
                    self._claimed_update(claimed, stage, send_state='DONE' if accepted else 'UNKNOWN',
                                         status='WAIT_LINK', code='' if accepted else 'SEND_UNKNOWN', http_status=status, retry_at=0)
        finally:
            self._release(leased)
        # A revoked actor can regain access to their saved evidence later. No
        # private account value is sent to an abandoned/newer form meanwhile.
        latest = self.job(job['actor_id'], job['id'])
        if not await self._access(event, state) or not await self._session(event, state, latest):
            if output is not None and self._live(event):
                await self._edit_card(output, 'ℹ️ Proses pada form ini sudah ditutup.',
                                      [[('⬅️ Aktivasi AM Pro', 'amman:menu')]])
            return
        if latest['status'] == 'WAIT_LINK':
            async with self._lock(job['actor_id']):
                if await self._session(event, state, latest):
                    await state.set_state(ManualState.link)
        return await self._render(event, state, latest, session=True, output=output)

    async def callback(self, call, state):
        if call.data == 'amman:menu':
            return await self.menu(call, state)
        if call.data == 'amman:history':
            return await self.menu(call, state, history_only=True)
        if not await self._access(call, state):
            return
        await self.host.safe_callback_notice(call)
        if not await self._access(call, state):
            return
        match = re.fullmatch(r'amman:(new|send|view|resume|cancel|rating|rate):(' + IDENT + '):(' + IDENT + r')(?::([1-5]))?', str(call.data or ''))
        if not match:
            return await self._notice(call, 'Tombol AM Manual tidak valid.')
        action, ident, nonce, stars = match.groups()
        if (action == 'rate') != (stars is not None):
            return await self._notice(call, 'Tombol AM Manual tidak valid.')
        actor = int(call.from_user.id)
        job = self.job(actor, ident)
        if not job or job['nonce'] != nonce:
            return await self._notice(call, 'Form tidak ditemukan atau tombol sudah tidak aktif.')
        job = self._recover(job)
        if not job:
            return await self._notice(call, 'Form sudah berubah. Buka AM Manual lagi.')
        if action in {'rating', 'rate'}:
            return await self._rating(call, state, job, int(stars) if stars else None)
        if action == 'view':
            return await self._render(call, state, job)
        if action == 'new':
            job, ready = self._ready_job(job)
            if not ready:
                return await self._render(call, state, job)
            async with self._lock(actor):
                job = self._activate(actor, ident, nonce)
                if job:
                    await self._clear_manual(state)
                    await state.update_data(**{FSM_KEY: ident})
                    await state.set_state(ManualState.email)
            if not job:
                return await self._notice(call, 'Form lama tidak dapat menggantikan sesi yang lebih baru.')
            if not await self._access(call, state) or not await self._session(call, state, job):
                return
            return await self._ui(call,
                '📧 <b>EMAIL AKTIVASI</b>\n\nKirim alamat email milik Anda.\nForm berlaku 15 menit.',
                [[('✖️ Batalkan Form', self._button('cancel', job))]])
        if action == 'resume':
            async with self._lock(actor):
                data = await state.get_data()
                if data.get(FSM_KEY) and data[FSM_KEY] != ident:
                    job = None
                else:
                    job = self._activate(actor, ident, nonce, resume=True)
                if job:
                    await state.update_data(**{FSM_KEY: ident})
                    await state.set_state(ManualState.link)
                    # A Telegram redelivery of the same callback must not
                    # repeat the input edit. A deliberate later click may
                    # reopen the input card without resending any email.
                    key = (actor, ident, job['nonce'], str(call.id))
                    prompt = key not in self._input_callbacks
                    self._input_callbacks[key] = True
                    if len(self._input_callbacks) > 256:
                        self._input_callbacks.pop(next(iter(self._input_callbacks)))
            if not job:
                return await self._notice(call, 'Sesi lain sedang aktif atau form sudah kedaluwarsa.')
            return await self._link_prompt(call, state, job, prompt=prompt)
        if not await self._session(call, state, job):
            return await self._notice(call, 'Tombol berasal dari form yang sudah ditinggalkan.')
        if action == 'cancel':
            async with self._lock(actor):
                if not await self._session(call, state, job) or not self._erase(actor, ident, nonce):
                    return await self._notice(call, 'Form sudah tidak aktif.')
                await self._clear_manual(state, ident=ident)
            if not await self._access(call, state):
                return
            return await self._ui(call, '✖️ <b>FORM DIBATALKAN</b>\n\nRiwayat form ini telah dihapus.',
                                  [[self._back(actor)]])
        if action == 'send' and job['status'] in {'CONFIRM_SEND', 'WAIT_LINK', 'RUNNING'}:
            return await self._post(call, state, job)
        return await self._notice(call, 'Tahap form ini tidak sesuai.')

    async def _link_prompt(self, call, state, job, *, prompt=True):
        if not prompt:
            return
        if not await self._access(call, state) or not await self._session(call, state, job):
            return
        current = self.job(job['actor_id'], job['id'])
        if not current or current['nonce'] != job['nonce'] or not current.get('active'):
            return
        current, ready = self._ready_job(current)
        if (not ready or current['status'] != 'WAIT_LINK'
                or current.get('verify_state') != 'NEW'
                or current.get('send_state') not in {'DONE', 'UNKNOWN'}):
            return await self._render(call, state, current, session=True)
        text = ('🔗 <b>MASUKKAN MAGIC LINK</b>\n\n'
                'Tempel tautan tombol <b>Masuk / Sign in</b> dari email langsung ke chat bot.\n'
                'Form AM: ' + job['id'])
        delivered = await self._edit_card(call.message, text, [
            [('✖️ Batalkan Form', self._button('cancel', job))],
            [('⬅️ Aktivasi AM Pro', 'amman:menu')]])
        if not await self._access(call, state) or not await self._session(call, state, job):
            return
        current = self.job(job['actor_id'], job['id'])
        if not current or current['nonce'] != job['nonce'] or not current.get('active'):
            return
        current, ready = self._ready_job(current)
        if (not ready or current['status'] != 'WAIT_LINK'
                or current.get('verify_state') != 'NEW'
                or current.get('send_state') not in {'DONE', 'UNKNOWN'}):
            # Link submission may complete while the card edit is in flight.
            # Restore that result on the same card.
            return await self._render(call, state, current, session=True, output=call.message)
        if not delivered:
            return await self._notice(call, 'Input sudah aktif. Tempel Magic Link dari email ke chat bot.')

    async def email_input(self, message, state):
        if not await self._access(message, state):
            return
        if input_reply_form(message):
            return await self._notice(message, 'Balasan berasal dari langkah Magic Link lama. Masukkan email pada form saat ini.')
        data = await state.get_data()
        job = self.job(int(message.from_user.id), data.get(FSM_KEY))
        if not job or job['status'] != 'EMAIL' or not await self._session(message, state, job):
            return await self._notice(message, 'Sesi email tidak aktif. Buka AM Manual lagi.')
        job, ready = self._ready_job(job)
        if not ready:
            return await self._render(message, state, job, session=True)
        try:
            email = _email(str(message.text or '').strip())
            secret = self._encrypt_email(job, email)
        except AMServiceError as exc:
            return await self._notice(message, 'Email tidak valid. Gunakan format nama@example.test.' if exc.code == 'INVALID_EMAIL' else 'Konfigurasi email belum tersedia.')
        # No plaintext email enters FSM, settings, logs, or quota until dispatch.
        job = self._set_email(job, secret)
        if not job:
            return
        async with self._lock(job['actor_id']):
            if await self._session(message, state, job):
                await state.set_state(ManualState.confirm)
        return await self._render(message, state, job, session=True)

    async def link_input(self, message, state):
        if not await self._access(message, state):
            return
        data = await state.get_data()
        job = self.job(int(message.from_user.id), data.get(FSM_KEY))
        if not job or not await self._session(message, state, job):
            return await self._notice(message, 'Sesi Magic Link tidak aktif. Buka AM Manual lagi.')
        reply_form = input_reply_form(message)
        if reply_form and reply_form != job['id']:
            return await self._notice(message, 'Balasan berasal dari form lama. Gunakan Magic Link untuk form yang sedang aktif.')
        job = self._recover(job)
        if not job:
            return await self._notice(message, 'Sesi Magic Link sudah berubah. Buka AM Manual lagi.')
        if job['status'] != 'WAIT_LINK' or job['send_state'] not in {'DONE', 'UNKNOWN'}:
            return await self._render(message, state, job, session=True)
        job, ready = self._ready_job(job)
        if not ready:
            return await self._render(message, state, job, session=True)
        try:
            email = self._decrypt_email(job)
            link = self._validate_link(str(message.text or '').strip(), email)
        except AMServiceError as exc:
            text = 'Magic Link tidak sesuai dengan email form ini.' if exc.code == 'MISMATCH' else 'Magic Link tidak valid. Kirim URL lengkap dari email yang sama.'
            return await self._notice(message, text)
        return await self._post(message, state, job, link=link)


Gateway = GatewayManual


def register(router, gateway):
    router.callback_query.register(gateway.callback, F.data.startswith('amman:'))
    router.message.register(gateway.email_input, ManualState.email, F.text & ~F.text.startswith('/'))
    router.message.register(gateway.link_input, ManualState.link, F.text & ~F.text.startswith('/'))
    return gateway
