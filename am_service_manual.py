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
import time
from urllib.parse import parse_qsl, urlsplit

from Crypto.Cipher import AES
from aiogram import F
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from am_service_client import (BASE_URL, AMServiceClient, AMServiceConfig,
                               AMServiceError, _email, _magic_link)

ADAPTER_VERSION = '17.58'
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


class GatewayManual:
    def __init__(self, host, config=None):
        self.host = host
        self.config = config if config is not None else AMServiceConfig.from_env()
        self.client = AMServiceClient(self.config)
        self._state_locks = {}

    async def close(self):
        await self.client.close()
        self._state_locks.clear()

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

    async def _notice(self, event, text):
        if hasattr(event, 'data'):
            return await self.host.safe_callback_notice(event, text, show_alert=True)
        return await event.answer(text)

    @staticmethod
    def _button(action, job):
        return 'amman:' + action + ':' + job['id'] + ':' + job['nonce']

    def _back(self, actor):
        return ('⬅️ Owner Tools', 'tools:home') if self.host.is_owner(actor) else ('⬅️ /tools', 'utools:home')

    async def menu(self, call, state):
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
        text = ('⚡ <b>AM MANUAL • API BARU</b>\n\n'
                'Web: <b>am-api-service.vercel.app</b>\n'
                'Paket Free: <b>50 requests/hari</b>, dibagi seluruh pemakai API key yang sama. '
                'Satu aktivasi biasanya memakai 2 requests (send + verify).\n\n'
                'Gunakan email milik Anda, lalu tempel Magic Link dari inbox email yang sama. '
                'Premium aktif hanya ditampilkan setelah bukti lengkap terkonfirmasi.\n'
                'Form berlaku 15 menit. Kuota /tools mengikuti aturan akun Anda.')
        rows = []
        if self.configured():
            try:
                draft = self._draft(actor)
                rows.append([('📧 Mulai dengan Email', self._button('new', draft))])
            except Exception:
                text += '\n\nStatus: CONFIG'
        else:
            text += '\n\nStatus: ' + ('DISABLED' if not self.config.enabled else 'CONFIG')
        rows += [[('📋 ' + job['id'] + ' • ' + job['status'], self._button('view', job))] for job in jobs]
        rows.append([self._back(actor)])
        if self._live(call):
            return await self._ui(call, text, rows)

    async def _render(self, event, state, job, *, session=False):
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
        text = ('⚡ <b>AM MANUAL • API BARU</b>\n\nCID: <code>' + current['id']
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
            text += '\nBuka inbox email yang sama, lalu tempel URL Magic Link lengkap di chat ini. '
            text += 'Contoh format: https://alightcreative.com/__/auth/action?oobCode=CONTOH\n'
            text += 'Jangan kirim password, API key, ID token, atau refresh token.'
            if not session and not self._expired(current):
                rows.append([('🔗 Lanjutkan Input Link', self._button('resume', current))])
        elif current['status'] == 'PREMIUM_ACTIVE':
            text += 'Berlaku sampai: <b>' + html.escape(current['valid_until']) + '</b>\n'
            if current.get('plan_name'):
                text += 'Paket: ' + html.escape(current['plan_name']) + '\n'
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
            text += '\nCoba manual lagi setelah: ' + datetime.fromtimestamp(
                current['retry_at'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        if current.get('active'):
            rows.append([('✖️ Batalkan Form', self._button('cancel', current))])
        rows.append([('⬅️ AM Manual', 'amman:menu')])
        if self._live(event):
            return await self._ui(event, text, rows)

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
        await self._ui(event, '⏳ Memproses AM Manual…\nCID: <code>' + job['id'] + '</code>',
                       [[('⬅️ AM Manual', 'amman:menu')]])
        if not await self._access(event, state) or not await self._session(event, state, job):
            return
        job, ready = self._ready_job(job)
        if not ready:
            return await self._render(event, state, job, session=True)
        try:
            email = self._decrypt_email(job)
        except AMServiceError:
            job = self._update(job['actor_id'], job['id'], job['nonce'], status='ACCOUNT_CHANGED', code='ACCOUNT_CHANGED')
            return await self._render(event, state, job, session=True)
        leased = self._lease(job, stage)
        if not leased:
            return await self._render(event, state, self.job(job['actor_id'], job['id']), session=True)
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
                return await self._render(event, state, current, session=True)
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
            return
        if latest['status'] == 'WAIT_LINK':
            async with self._lock(job['actor_id']):
                if await self._session(event, state, latest):
                    await state.set_state(ManualState.link)
        return await self._render(event, state, latest, session=True)

    async def callback(self, call, state):
        if call.data == 'amman:menu':
            return await self.menu(call, state)
        if not await self._access(call, state):
            return
        await self.host.safe_callback_notice(call)
        if not await self._access(call, state):
            return
        match = re.fullmatch(r'amman:(new|send|view|resume|cancel):(' + IDENT + '):(' + IDENT + ')', str(call.data or ''))
        if not match:
            return await self._notice(call, 'Tombol AM Manual tidak valid.')
        action, ident, nonce = match.groups()
        actor = int(call.from_user.id)
        job = self.job(actor, ident)
        if not job or job['nonce'] != nonce:
            return await self._notice(call, 'Form tidak ditemukan atau tombol sudah tidak aktif.')
        job = self._recover(job)
        if not job:
            return await self._notice(call, 'Form sudah berubah. Buka AM Manual lagi.')
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
                '📧 <b>EMAIL AM MANUAL</b>\n\nKirim alamat email milik Anda. '
                'Contoh: nama@example.test\nJangan kirim password, API key, atau token.\nForm berlaku 15 menit.',
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
            if not job:
                return await self._notice(call, 'Sesi lain sedang aktif atau form sudah kedaluwarsa.')
            return await self._render(call, state, job, session=True)
        if not await self._session(call, state, job):
            return await self._notice(call, 'Tombol berasal dari form yang sudah ditinggalkan.')
        if action == 'cancel':
            self._deactivate(actor, ident)
            async with self._lock(actor):
                await self._clear_manual(state, ident=ident)
            return await self.menu(call, state)
        if action == 'send' and job['status'] in {'CONFIRM_SEND', 'WAIT_LINK', 'RUNNING'}:
            return await self._post(call, state, job)
        return await self._notice(call, 'Tahap form ini tidak sesuai.')

    async def email_input(self, message, state):
        if not await self._access(message, state):
            return
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
