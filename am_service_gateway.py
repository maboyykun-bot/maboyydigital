"""Owner-only AM activation using existing Temp Mail and two service POSTs.

Settings hold safe job metadata and durable, one-way dispatch claims. A callback
ticket is the job ID, so replaying a Telegram button cannot create another job.
Magic links exist only in the worker's stack and are never saved or logged.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import html
import json
import re
import secrets
import time
from types import SimpleNamespace

from aiogram import F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from am_service_client import BASE_URL, AMServiceClient, AMServiceConfig, AMServiceError, _magic_link


ADAPTER_VERSION = '17.58'
JOB_PREFIX = 'amservice.job.'
DUE_PREFIX = 'amservice.due.'
WORK_SECONDS = 90
POLL_SECONDS = 5
MAIL_RETRY_SECONDS = 15
MAX_MAIL_WATCH_SECONDS = 3600
TERMINAL = {'PREMIUM_ACTIVE', 'FAILED', 'UNKNOWN', 'ACCOUNT_CHANGED'}
SAFE_CODES = {
    'AUTH', 'CONFIG', 'DISABLED', 'RATE_LIMIT', 'UPSTREAM', 'HTTP', 'TIMEOUT',
    'DNS', 'TLS', 'NETWORK', 'JSON_INVALID', 'SCHEMA', 'REJECTED',
    'INVALID_EMAIL', 'INVALID_MAGIC_LINK', 'EMAIL_MISMATCH', 'RESPONSE_TOO_LARGE',
    'ENDPOINT_NOT_FOUND', 'QUOTA', 'ACCOUNT_CHANGED', 'MAILBOX_UNKNOWN',
    'MAILBOX_MISMATCH', 'SEND_UNKNOWN', 'VERIFY_UNKNOWN', 'UNCONFIRMED',
    'INBOX_UNAVAILABLE', 'MAIL_WAIT_EXPIRED', 'LOCAL_ERROR', 'JOB_BUDGET',
}


def _stamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _status(value):
    return value if type(value) is int and 100 <= value <= 599 else 0


def _code(exc):
    value = getattr(exc, 'code', '')
    value = {'RATE_LIMITED': 'RATE_LIMIT', 'INVALID_JSON': 'JSON_INVALID',
             'BAD_REQUEST': 'REJECTED', 'NOT_FOUND': 'ENDPOINT_NOT_FOUND',
             'REDIRECT': 'HTTP', 'MISMATCH': 'EMAIL_MISMATCH'}.get(value, value)
    return value if value in SAFE_CODES else 'LOCAL_ERROR'


def _delay(exc, default=60):
    value = getattr(exc, 'retry_after', 0)
    return min(86400, max(5, value)) if type(value) is int and value else default


class Gateway:
    def __init__(self, host, config=None):
        self.host = host
        self.config = config if config is not None else AMServiceConfig.from_env()
        self.client = AMServiceClient(self.config)
        self._task = None
        self._views = {}  # Explicit requests in this process only; never persisted.
        self._rendered = {}

    def fingerprint(self):
        values = [BASE_URL, self.config.api_key]
        return hashlib.sha256(json.dumps(values, separators=(',', ':')).encode()).hexdigest()

    def work_budget(self):
        # Mail creation and both service calls may each use their full timeout.
        return max(WORK_SECONDS, 3 * self.config.timeout_seconds + 30)

    def configured(self):
        return self.config.enabled and self.config.valid()

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
        row = conn.execute('SELECT value FROM settings WHERE key=?', (JOB_PREFIX + ident,)).fetchone()
        if not row:
            return None
        try:
            value = json.loads(row['value'])
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, dict) and value.get('id') == ident else None

    @staticmethod
    def _save(conn, job):
        conn.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                     (JOB_PREFIX + job['id'], json.dumps(job, separators=(',', ':'))))
        key = DUE_PREFIX + job['id']
        if job['status'] not in TERMINAL:
            due = max(float(job.get('retry_at', 0)), float(job.get('lease_until', 0)))
            conn.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                         (key, str(due)))
        else:
            conn.execute('DELETE FROM settings WHERE key=?', (key,))

    def job(self, owner, ident):
        if not isinstance(ident, str) or not re.fullmatch('[0-9a-f]{16}', ident):
            return None
        with self._connection() as conn:
            job = self._load(conn, ident)
        return job if job and job['owner_id'] == int(owner) else None

    def _new(self, owner, ticket):
        with self._connection(True) as conn:
            job = self._load(conn, ticket)
            if job:
                return job if job['owner_id'] == int(owner) else None
            provider = self.host.auto_am_mail_provider()
            if provider not in {'grabmail', 'guerrilla', 'mailtm', 'maildrop'}:
                raise ValueError('MAILBOX_MISMATCH')
            job = dict(id=ticket, owner_id=int(owner), fingerprint=self.fingerprint(),
                       provider=provider, created_at=_stamp(), updated_at=_stamp(),
                       status='WAITING', stage='CREATE_MAILBOX', code='', http_status=0,
                       mailbox_id=0, mailbox_state='NEW', send_state='NEW', verify_state='NEW',
                       magic_sent_at='', retry_at=0, lease_token='', lease_until=0,
                       valid_until='', plan_name='', mail_checked_at='', mail_count=0,
                       mail_candidate_count=0, mail_checked_details=0, mail_scan_code='')
            self._save(conn, job)
            return job

    def _lease(self, owner, ident):
        with self._connection(True) as conn:
            job = self._load(conn, ident)
            now = time.time()
            if (not job or job['owner_id'] != int(owner) or job['status'] in TERMINAL
                    or job['lease_until'] > now or job['retry_at'] > now):
                return None
            job.update(lease_token=secrets.token_hex(16), lease_until=now + self.work_budget() + 30)
            self._save(conn, job)
            return job

    def _change(self, job, **values):
        with self._connection(True) as conn:
            current = self._load(conn, job['id'])
            if not current or current['lease_token'] != job['lease_token']:
                raise RuntimeError('Lease expired')
            current.update(values, updated_at=_stamp())
            self._save(conn, current)
            return current

    def _release(self, job):
        with self._connection(True) as conn:
            current = self._load(conn, job['id'])
            if current and current['lease_token'] == job['lease_token']:
                current.update(lease_token='', lease_until=0)
                self._save(conn, current)

    def _mailbox(self, job):
        row = self.host.temp_mail_owned_row(job['owner_id'], job['mailbox_id'])
        provider = self.host.temp_mail_row_provider(row)
        if (int(row.get('owner_id', 0)) != job['owner_id'] or provider != job['provider']
                or not isinstance(row.get('address'), str) or '@' not in row['address']):
            raise ValueError('MAILBOX_MISMATCH')
        return row

    def _recover(self, job, *, code='LOCAL_ERROR'):
        """A committed dispatch claim is never changed back to NEW on restart."""
        if job['mailbox_state'] == 'CLAIMED':
            return self._change(job, mailbox_state='UNKNOWN', status='UNKNOWN',
                                stage='MAILBOX_UNKNOWN', code='MAILBOX_UNKNOWN', retry_at=0)
        if job['verify_state'] == 'CLAIMED':
            return self._change(job, verify_state='UNKNOWN', status='UNKNOWN',
                                stage='VERIFY_UNKNOWN', code='VERIFY_UNKNOWN', retry_at=0)
        if job['send_state'] == 'CLAIMED':
            return self._change(job, send_state='UNKNOWN', status='WAITING',
                                stage='WAITING_MAIL', code='SEND_UNKNOWN', retry_at=time.time() + MAIL_RETRY_SECONDS)
        return self._change(job, status='WAITING', code=code, retry_at=time.time() + 60)

    def _reserve(self, job, email):
        return self.host._reserve_tool_provider_request(
            job['owner_id'], 'POST', target_email=email,
            correlation_id='amservice:' + job['id'], count_account=True)

    def _finish(self, request, status, http_status):
        # A metering write failure must not discard already committed evidence.
        try:
            self.host._finish_tool_provider_request(request, status, _status(http_status))
        except Exception:
            pass

    def _candidate(self, message, job, email, *, detail=False):
        if not isinstance(message, dict):
            return False
        sender = message.get('from')
        sender = sender.get('address', '') if isinstance(sender, dict) else ''
        if not isinstance(sender, str) or sender.count('@') != 1:
            return False
        local, domain = sender.strip().lower().rsplit('@', 1)
        # Firebase may put its Google bounce envelope in the provider's From
        # field. This exact host is accepted only with the mailbox/time checks
        # below and an Alight action URL validated before a verification claim.
        trusted = domain in {'alight-creative.firebaseapp.com', 'firebaseapp.bounces.google.com'} or any(
            domain == value or domain.endswith('.' + value)
            for value in ('alightcreative.com', 'alightmotion.com'))
        if not local or not trusted:
            return False
        try:
            recipients = self.host.temp_mail_recipient_addresses(message)
            if recipients and email not in recipients:
                return False
            if detail and not recipients:
                binding = message.get('mailbox')
                if (not isinstance(binding, dict) or binding.get('id') != job['mailbox_id']
                        or binding.get('owner_id') != job['owner_id']
                        or str(message.get('address', '')).strip().lower() != email):
                    return False
            sent = datetime.fromisoformat(job['magic_sent_at'].replace('Z', '+00:00'))
            received = datetime.fromisoformat(str(message.get('createdAt', '')).replace('Z', '+00:00'))
            if sent.tzinfo is None:
                sent = sent.replace(tzinfo=timezone.utc)
            if received.tzinfo is None:
                received = received.replace(tzinfo=timezone.utc)
            age = (received - sent).total_seconds()
            return age >= -120 and received.timestamp() <= time.time() + 300
        except Exception:
            return False

    async def _find_link(self, job, email):
        """Use the existing mailbox APIs/extractor with strict AM ownership checks."""
        inbox = await self.host.temp_mail_fetch_inbox(job['owner_id'], job['mailbox_id'])
        binding = inbox.get('mailbox') if isinstance(inbox, dict) else None
        if (not isinstance(binding, dict) or binding.get('id') != job['mailbox_id']
                or binding.get('owner_id') != job['owner_id']
                or str(inbox.get('address', '')).strip().lower() != email):
            self._change(job, mail_checked_at=_stamp(), mail_scan_code='INBOX_MISMATCH')
            return ''
        messages = inbox.get('messages', [])
        if not isinstance(messages, list):
            self._change(job, mail_checked_at=_stamp(), mail_scan_code='INBOX_INVALID')
            return ''
        # Store only bounded counts and reason codes, never mail bodies, sender
        # addresses or magic links. HTTP 200 from send-link is not inbox proof.
        diagnostics = dict(mail_checked_at=_stamp(), mail_count=len(messages[:30]),
                           mail_candidate_count=0, mail_checked_details=0,
                           mail_scan_code='EMPTY' if not messages else 'NO_MATCH')
        checked = set()
        for item in messages[:30]:
            if not self._candidate(item, job, email):
                continue
            ident = item.get('id')
            if not self.host.temp_mail_provider_id(ident) or ident in checked:
                continue
            checked.add(ident)
            if len(checked) > 10:
                break
            diagnostics['mail_candidate_count'] += 1
            try:
                message = await self.host.temp_mail_read_message(job['owner_id'], job['mailbox_id'], ident)
                diagnostics['mail_checked_details'] += 1
                if not self._candidate(message, job, email, detail=True):
                    diagnostics['mail_scan_code'] = 'DETAIL_MISMATCH'
                    continue
                link = self.host.auto_am_extract_magic_link(message)
                if link:
                    # The shared legacy extractor also recognizes other Firebase
                    # projects. The new service only accepts its canonical Alight
                    # URL contract, so reject unrelated links before any POST claim.
                    try:
                        link = _magic_link(link)
                    except AMServiceError:
                        diagnostics['mail_scan_code'] = 'UNTRUSTED_LINK'
                        continue
                    diagnostics['mail_scan_code'] = 'LINK_FOUND'
                    self._change(job, **diagnostics)
                    return link
            except ValueError:
                diagnostics['mail_scan_code'] = 'NO_LINK'
                continue
            except self.host.TempMailError as exc:
                diagnostics['mail_scan_code'] = 'DETAIL_UNAVAILABLE'
                if exc.status not in {404, 409, 422, 502}:
                    self._change(job, **diagnostics)
                    raise
        self._change(job, **diagnostics)
        return ''

    async def _post(self, job, email, *, link=None, deadline=None):
        verify = link is not None
        state = 'verify_state' if verify else 'send_state'
        # Slow mail APIs must not consume a service POST's configured timeout.
        # No quota reservation or dispatch claim exists when this work defers.
        if deadline is not None and deadline - time.monotonic() < self.config.timeout_seconds + 2:
            return self._change(job, status='WAITING', code='JOB_BUDGET',
                                stage='WAITING_MAIL' if verify else 'SEND_LINK',
                                retry_at=time.time() + POLL_SECONDS)
        request = self._reserve(job, email)
        if not request:
            return self._change(job, status='WAITING', code='QUOTA', retry_at=time.time() + 60)
        changes = {state: 'CLAIMED', 'status': 'RUNNING', 'code': '', 'cause_code': '',
                   'stage': 'VERIFYING' if verify else 'SENDING_LINK', 'http_status': 0,
                   'http_stage': 'verify-link' if verify else 'send-link'}
        if not verify:
            changes['magic_sent_at'] = _stamp()
        try:
            job = self._change(job, **changes)
        except Exception:
            self._finish(request, 'failed', 0)
            raise
        try:
            if verify:
                result = await self.client.verify_link(email, link)
            else:
                result = await self.client.send_link(email)
        except asyncio.CancelledError:
            self._finish(request, 'unknown', 0)
            raise
        except Exception as exc:
            uncertain = not isinstance(exc, AMServiceError) or exc.uncertain
            code = _code(exc)
            http_status = _status(getattr(exc, 'http_status', 0))
            self._finish(request, 'unknown' if uncertain else 'failed', http_status)
            if uncertain:
                return self._change(job, **{state: 'UNKNOWN'}, status='UNKNOWN' if verify else 'WAITING',
                                    stage='VERIFY_UNKNOWN' if verify else 'WAITING_MAIL',
                                    code='VERIFY_UNKNOWN' if verify else 'SEND_UNKNOWN', http_status=http_status,
                                    cause_code=code,
                                    retry_at=0 if verify else time.time() + MAIL_RETRY_SECONDS)
            if code == 'RATE_LIMIT':
                return self._change(job, **{state: 'NEW'}, status='WAITING', code=code,
                                    cause_code=code, http_status=http_status, retry_at=time.time() + _delay(exc))
            return self._change(job, **{state: 'FAILED'}, status='FAILED', code=code,
                                cause_code=code, http_status=http_status, retry_at=0)
        http_status = _status(result.get('http_status'))
        if verify:
            active = result.get('status') == 'PREMIUM_ACTIVE'
            until = result.get('valid_until')
            try:
                expires = datetime.fromisoformat(until.replace('Z', '+00:00'))
                active = active and expires.tzinfo is not None and expires > datetime.now(timezone.utc)
            except (AttributeError, TypeError, ValueError):
                active = False
            self._finish(request, 'success' if active else 'unknown', http_status)
            plan = result.get('plan_name')
            plan = plan if (isinstance(plan, str) and len(plan) <= 120
                            and not any(ord(c) < 32 for c in plan)
                            and not any(value in plan for value in ('://', '@', '<', '>', self.config.api_key))) else ''
            return self._change(job, verify_state='DONE' if active else 'UNKNOWN',
                                status='PREMIUM_ACTIVE' if active else 'UNKNOWN',
                                stage='COMPLETE' if active else 'VERIFY_UNKNOWN',
                                code='' if active else 'UNCONFIRMED', cause_code='', http_status=http_status,
                                valid_until=until if active else '', plan_name=plan if active else '', retry_at=0)
        accepted = result.get('accepted')
        self._finish(request, 'success' if accepted is True else 'failed' if accepted is False else 'unknown', http_status)
        return self._change(job, send_state='DONE' if accepted is True else 'FAILED' if accepted is False else 'UNKNOWN',
                            status='FAILED' if accepted is False else 'WAITING', stage='WAITING_MAIL',
                            code='REJECTED' if accepted is False else '' if accepted is True else 'SEND_UNKNOWN',
                            cause_code='', http_status=http_status,
                            retry_at=0 if accepted is False else time.time() + MAIL_RETRY_SECONDS)

    async def _run(self, job, call, deadline=None):
        if not self.configured():
            return self._change(job, status='WAITING', code='DISABLED' if not self.config.enabled else 'CONFIG',
                                retry_at=time.time() + 60)
        if job['fingerprint'] != self.fingerprint():
            return self._change(job, status='ACCOUNT_CHANGED', code='ACCOUNT_CHANGED', retry_at=0)
        if not self.host.TEMPMAIL_ENABLED:
            return self._change(job, status='WAITING', code='DISABLED', retry_at=time.time() + 60)
        if any(job[field] == 'CLAIMED' for field in ('mailbox_state', 'send_state', 'verify_state')):
            job = self._recover(job)
            if job['status'] in TERMINAL:
                return job
        if getattr(self.client, 'config', self.config) != self.config:
            await self.client.close()
            self.client = AMServiceClient(self.config)
        if not job['mailbox_id']:
            allowed, _ = self.host.tools_quota_can_process(
                job['owner_id'], correlation_id='amservice:' + job['id'])
            if not allowed:
                return self._change(job, status='WAITING', code='QUOTA', retry_at=time.time() + 60)
            job = self._change(job, mailbox_state='CLAIMED', status='RUNNING', stage='CREATE_MAILBOX')
            mailbox = await self.host.temp_mail_create_account(job['owner_id'], provider=job['provider'])
            job = self._change(job, mailbox_id=int(mailbox['id']), mailbox_state='DONE')
        try:
            mailbox = self._mailbox(job)
        except Exception:
            return self._change(job, status='UNKNOWN', code='MAILBOX_MISMATCH', retry_at=0)
        email = mailbox['address'].strip().lower()
        if job['send_state'] == 'NEW':
            job = await self._post(job, email, deadline=deadline)
            if job['send_state'] == 'NEW' or job['status'] in TERMINAL:
                return job
        if job['verify_state'] != 'NEW':
            return job
        try:
            sent = datetime.fromisoformat(job['magic_sent_at'].replace('Z', '+00:00'))
            expired = (datetime.now(timezone.utc) - sent).total_seconds() > MAX_MAIL_WATCH_SECONDS
        except (ValueError, TypeError):
            expired = True
        if expired:
            return self._change(job, status='UNKNOWN', code='MAIL_WAIT_EXPIRED', retry_at=0)
        link = await self._find_link(job, email)
        if not link:
            # A recovered, readable inbox clears an earlier read/budget error;
            # retain send ambiguity because a mailbox scan cannot prove a POST.
            return self._change(job, stage='WAITING_MAIL', status='WAITING',
                                code='SEND_UNKNOWN' if job['send_state'] == 'UNKNOWN' else '',
                                cause_code=job.get('cause_code', '') if job['send_state'] == 'UNKNOWN' else '',
                                retry_at=time.time() + MAIL_RETRY_SECONDS)
        return await self._post(job, email, link=link, deadline=deadline)

    async def process(self, owner, ident, call=None):
        job = self._lease(owner, ident)
        if not job:
            return self.job(owner, ident)
        try:
            budget = self.work_budget()
            return await asyncio.wait_for(self._run(job, call, time.monotonic() + budget), budget)
        except asyncio.CancelledError:
            try:
                self._recover(self.job(owner, ident))
            except Exception:
                pass
            raise
        except Exception:
            latest = self.job(owner, ident)
            if latest['status'] not in TERMINAL:
                return self._recover(latest, code='INBOX_UNAVAILABLE' if latest['send_state'] in {'DONE', 'UNKNOWN'} else 'LOCAL_ERROR')
            return latest
        finally:
            self._release(job)

    @staticmethod
    def _keyboard(rows):
        return InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=text, callback_data=data) for text, data in row] for row in rows])

    async def menu(self, call, state=None):
        # The provider chooser includes manual activation, which needs no Temp
        # Mail. Mailbox creation/resume remains behind temp_mail_require_owner.
        if not self.host.is_owner(call.from_user.id):
            return await self.host.deny_owner_callback(call)
        if not await self.host.tools_vip_public_guard(call):
            return
        await self.host.safe_callback_notice(call)
        if state is not None:
            await state.set_state(None)
        owner = int(call.from_user.id)
        with self._connection() as conn:
            rows = conn.execute('SELECT value FROM settings WHERE key LIKE ? ORDER BY rowid DESC LIMIT 30',
                                (JOB_PREFIX + '%',)).fetchall()
        jobs = [json.loads(row['value']) for row in rows]
        jobs = [job for job in jobs if job.get('owner_id') == owner][:5]
        status = 'Konfigurasi tersedia' if self.configured() else 'DISABLED' if not self.config.enabled else 'CONFIG'
        text = ('⚡ <b>am-api-service.vercel.app</b>\n\nStatus: <b>' + status + '</b>\n'
                'Auto Create membuat email melalui Temp Mail yang dipilih. Manual memakai email Anda sendiri.\n'
                'Premium hanya ditampilkan setelah bukti aktivasi dan masa berlaku terkonfirmasi.\n\n'
                'Paket Free: 50 request API/hari, dipakai bersama oleh API key yang sama. '
                'Satu aktivasi biasanya memakai 2 request (kirim + verifikasi), bukan 50 akun/hari.')
        if not self.host.TEMPMAIL_ENABLED:
            text += '\n\nAuto Create memerlukan Temp Mail aktif. Aktivasi Manual tetap tersedia.'
        controls = [[('✉️ Aktivasi Manual • Email Sendiri', 'amman:menu')]]
        if self.configured() and self.host.TEMPMAIL_ENABLED:
            controls.append([('⚡ Buat AM Pro', 'amnew:new:' + secrets.token_hex(8))])
        controls += [[('📋 ' + job['id'] + ' • ' + job['status'], 'amnew:view:' + job['id'])] for job in jobs]
        controls.append([('⬅️ Owner Tools', 'tools:home')])
        return await self.host.safe_edit_or_answer(call, text, reply_markup=self._keyboard(controls), parse_mode='HTML')

    async def render(self, call, job):
        labels = {'PREMIUM_ACTIVE': '✅ PREMIUM ACTIVE', 'WAITING': '⏳ Menunggu',
                  'RUNNING': '⏳ Diproses', 'UNKNOWN': '⚠️ Hasil belum terkonfirmasi',
                  'FAILED': '❌ Belum berhasil', 'ACCOUNT_CHANGED': '⚠️ Konfigurasi akun berubah'}
        text = '⚡ <b>AM AUTO CREATE</b>\n\nJob: <code>' + job['id'] + '</code>\n'
        text += 'Status: <b>' + labels.get(job['status'], 'Menunggu') + '</b>\n'
        stages = {'CREATE_MAILBOX': 'Membuat email', 'SEND_LINK': 'Menyiapkan pengiriman link',
                  'SENDING_LINK': 'Mengirim Magic Link', 'WAITING_MAIL': 'Menunggu email Magic Link',
                  'VERIFYING': 'Memverifikasi Magic Link', 'COMPLETE': 'Selesai',
                  'MAILBOX_UNKNOWN': 'Pembuatan email perlu diperiksa',
                  'VERIFY_UNKNOWN': 'Hasil verifikasi perlu diperiksa'}
        text += 'Tahap: ' + stages.get(job['stage'], 'Memeriksa job') + '\n'
        mailbox = None
        if job['mailbox_id']:
            try:
                mailbox = self._mailbox(job)
                text += 'Email: <code>' + html.escape(mailbox['address']) + '</code>\n'
            except Exception:
                pass
        if job['status'] == 'PREMIUM_ACTIVE':
            text += 'Berlaku sampai: <b>' + html.escape(job['valid_until']) + '</b>\n'
            if job['plan_name']:
                text += 'Paket: ' + html.escape(job['plan_name']) + '\n'
        notes = {'QUOTA': 'Kuota akun per jam habis. Pemeriksaan dijadwalkan kembali.',
                 'SEND_UNKNOWN': 'Pengiriman belum pasti. Bot hanya memeriksa inbox; pengiriman tidak diulang.',
                 'VERIFY_UNKNOWN': 'Verifikasi sudah dikirim. Hasil belum pasti; verifikasi tidak diulang.',
                 'UNCONFIRMED': 'Respons belum membuktikan premium aktif dan masa berlaku.',
                 'MAILBOX_UNKNOWN': 'Pembuatan email belum pasti. Email pengganti tidak dibuat otomatis.',
                 'ACCOUNT_CHANGED': 'Job disimpan memakai konfigurasi sebelumnya. Periksa hasil pada akun lama.',
                 'JOB_BUDGET': 'Pemeriksaan email memerlukan waktu tambahan. Bot melanjutkan job ini sebentar lagi.',
                 'MAIL_WAIT_EXPIRED': 'Batas pemeriksaan inbox tercapai. Periksa email dan hasil provider secara manual.',
                 'INBOX_UNAVAILABLE': 'Inbox belum dapat dibaca. Bot akan mencoba membaca lagi tanpa mengulang pengiriman link.'}
        if job['code']:
            text += '\n' + notes.get(job['code'], 'Kode: ' + job['code'])
        cause = job.get('cause_code')
        if isinstance(cause, str) and cause in SAFE_CODES:
            text += '\nPenyebab: ' + cause
        if _status(job.get('http_status')):
            http_stage = job.get('http_stage')
            if http_stage not in {'send-link', 'verify-link'}:
                http_stage = 'verify-link' if job.get('verify_state') != 'NEW' else 'send-link'
            text += '\nHTTP ' + http_stage + ': ' + str(job['http_status'])
        if job['stage'] == 'WAITING_MAIL' and job['status'] not in TERMINAL:
            scans = {'EMPTY': 'Inbox berhasil diperiksa; belum ada email masuk.',
                     'NO_MATCH': 'Email masuk belum cocok dengan pengirim, penerima, atau waktu aktivasi.',
                     'NO_LINK': 'Email kandidat belum berisi satu Magic Link yang valid.',
                     'UNTRUSTED_LINK': 'Link email belum cocok dengan domain aktivasi Alight yang diizinkan.',
                     'DETAIL_MISMATCH': 'Identitas detail email tidak cocok; link tidak digunakan.',
                     'DETAIL_UNAVAILABLE': 'Detail email belum dapat dibaca; pemeriksaan akan diulang.',
                     'INBOX_MISMATCH': 'Identitas inbox tidak cocok; link tidak digunakan.',
                     'INBOX_INVALID': 'Format daftar email belum valid.',
                     'LINK_FOUND': 'Magic Link ditemukan; verifikasi menunggu giliran.'}
            scan_code = job.get('mail_scan_code', '')
            if scan_code in scans:
                text += '\n\n' + scans[scan_code]
            checked_at = job.get('mail_checked_at', '')
            try:
                checked = datetime.fromisoformat(checked_at.replace('Z', '+00:00'))
                if checked.tzinfo is not None:
                    text += '\nInbox terakhir diperiksa: ' + checked.astimezone(timezone.utc).strftime('%H:%M:%S UTC')
            except (ValueError, AttributeError):
                pass
            text += '\nBot memeriksa inbox otomatis; tidak perlu menekan Cek Job.'
            try:
                sent = datetime.fromisoformat(job['magic_sent_at'].replace('Z', '+00:00'))
                remaining = max(0, MAX_MAIL_WATCH_SECONDS - (datetime.now(timezone.utc) - sent).total_seconds())
                text += '\nBatas tunggu email: ' + str(max(1, int((remaining + 59) // 60))) + ' menit lagi.'
            except (KeyError, TypeError, ValueError):
                pass
            if job.get('send_state') == 'DONE':
                text += '\nHTTP send-link hanya membuktikan permintaan diterima API; bukan email sudah sampai.'
        controls = [[('🔄 Cek Job', 'amnew:resume:' + job['id'])], [('⬅️ AM Auto Create', 'amnew:menu')]]
        if mailbox is not None and mailbox.get('state') == 'ready':
            controls.insert(0, [('📬 Inbox Email', 'tm:inbox:' + str(mailbox['id']) + ':1')])
        return await self.host.safe_edit_or_answer(call, text, reply_markup=self._keyboard(controls), parse_mode='HTML')

    async def callback(self, call, state=None):
        if call.data == 'amnew:menu':
            return await self.menu(call, state)
        if not await self.host.temp_mail_require_owner(call):
            return
        if state is not None:
            await state.set_state(None)
        match = re.fullmatch(r'amnew:(new|view|resume):([0-9a-f]{16})', str(call.data or ''))
        if not match:
            return await self.host.safe_callback_notice(call, 'Tombol tidak valid.', show_alert=True)
        action, ident = match.groups()
        owner = int(call.from_user.id)
        try:
            job = self.job(owner, ident)
            if not job and action == 'new' and self.configured():
                job = self._new(owner, ident)
            if not job:
                return await self.host.safe_callback_notice(call, 'Job tidak ditemukan atau konfigurasi belum siap.', show_alert=True)
            self._views[(owner, ident)] = call
            if len(self._views) > 64:
                oldest = next(iter(self._views))
                self._views.pop(oldest, None)
                self._rendered.pop(oldest, None)
            await self.host.safe_callback_notice(call, 'Memeriksa aktivasi...')
            if action != 'view':
                try:
                    await self.render(call, job)
                except Exception:
                    pass
                await self.process(owner, ident, call)
            return await self.render(call, self.job(owner, ident))
        except asyncio.CancelledError:
            raise
        except Exception:
            return await self.host.safe_callback_notice(call, 'Job tetap disimpan. Buka kembali AM Auto Create untuk memeriksa.', show_alert=True)

    async def tick(self, bot=None):
        # Ordered next-attempt keys keep a leased/slow job from starving others.
        with self._connection() as conn:
            rows = conn.execute('SELECT key FROM settings WHERE key LIKE ? AND CAST(value AS REAL)<=? '
                                'ORDER BY CAST(value AS REAL),key LIMIT 5', (DUE_PREFIX + '%', time.time())).fetchall()
        for row in rows:
            ident = row['key'][len(DUE_PREFIX):]
            with self._connection() as conn:
                job = self._load(conn, ident)
            if not job or not self.host.is_owner(job['owner_id']):
                # A stale key or a revoked owner must not occupy the queue head.
                # Preserve the job itself for an authorized owner's later view.
                with self._connection(True) as conn:
                    conn.execute('DELETE FROM settings WHERE key=?', (row['key'],))
                continue
            owner = job['owner_id']
            call = self._views.get((owner, ident))
            await self.process(owner, ident, call)
            current = self.job(owner, ident)
            # Empty inbox scans still make progress. Refresh a visible waiting
            # view at most once per minute unless counts/reason/state changes.
            signature = (current['status'], current['stage'], current['code'], current['valid_until'],
                         current.get('mail_scan_code'), current.get('mail_count'),
                         current.get('mail_checked_at', '')[:16])
            if call is not None and self._rendered.get((owner, ident)) != signature:
                try:
                    await self.render(call, current)
                    self._rendered[(owner, ident)] = signature
                except Exception:
                    pass
            break  # At most one worker budget; stale metadata above is cheap.

    async def start(self, bot):
        if self._task is not None and not self._task.done():
            return []
        async def worker():
            while True:
                try:
                    await self.tick(bot)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
                await asyncio.sleep(POLL_SECONDS)
        self._task = asyncio.create_task(worker(), name='am_service_jobs')
        return [self._task]

    async def close(self):
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._views.clear()
        await self.client.close()


def register(router, gateway):
    router.callback_query.register(gateway.callback, F.data.startswith('amnew:'))

    async def command(message, state=None):
        async def answer(text='', **kwargs):
            if text:
                await message.answer(text)
        call = SimpleNamespace(from_user=message.from_user, message=message,
                               data='amnew:menu', id='', answer=answer)
        await gateway.menu(call, state)

    router.message.register(command, Command('amautocreate', 'amnew'))
    return gateway
