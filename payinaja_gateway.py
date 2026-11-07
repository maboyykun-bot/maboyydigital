"""Payinaja QRIS: authenticated polling, native accounting, no H2H operations."""
import asyncio
import binascii
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import base64
import warnings
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from io import BytesIO
from types import SimpleNamespace
from urllib.parse import urlsplit, parse_qs, urljoin, unquote

import aiohttp
import qrcode
from PIL import Image
from Crypto.Cipher import AES
from aiogram import F
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter
from aiogram.types import BufferedInputFile, InlineKeyboardButton, InlineKeyboardMarkup, InputMediaPhoto

from klikqris_gateway import GatewayError, environment_value, money, reference, encoded

BODY_LIMIT = 1024 * 1024
QR_LIMIT = 2 * 1024 * 1024
API_HOSTS = frozenset({'payinaja.com', 'www.payinaja.com'})
METHOD = 'PAYINAJA_AUTO'
PREFIX = 'payi:'
LABEL = '⚡ QRIS Otomatis'
FINAL = {'SETTLED', 'SETTLED_BALANCE', 'FAILED', 'CANCELLED'}
TX_PREFIX = 'payinaja.tx.'
ADAPTER_VERSION = '17.47'
QR_BLOCKING_ERRORS = frozenset({'SCHEMA', 'MISMATCH', 'AUTH', 'ACCOUNT_CHANGED', 'DUPLICATE_REFERENCE'})
DENIAL_LIMIT = 16384


async def denial_context(response):
    """Classify a rejection without retaining its body, identities or secrets."""
    result = dict(kind='credentials_rejected' if response.status == 401 else 'http_forbidden',
                  format='empty', source='http-status')
    if str(response.headers.get('cf-mitigated', '')).casefold() == 'challenge':
        return dict(kind='edge_challenge', format='unread', source='edge-header')
    async def read():
        raw = bytearray()
        async for chunk in response.content.iter_chunked(4096):
            raw.extend(chunk[:DENIAL_LIMIT + 1 - len(raw)])
            if len(raw) > DENIAL_LIMIT:
                break
        return bytes(raw)
    try:
        raw = await asyncio.wait_for(read(), timeout=3)
    except asyncio.CancelledError:
        raise
    except Exception:
        result['format'] = 'unreadable'
        return result
    if len(raw) > DENIAL_LIMIT:
        result['format'] = 'oversize'
        return result
    if not raw.strip():
        return result
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        lower = raw[:DENIAL_LIMIT].lower()
        result['format'] = 'html' if b'<html' in lower or b'<!doctype html' in lower else 'text'
        if result['format'] == 'html' and (b'challenge-platform' in lower or b'cf_chl_' in lower):
            result.update(kind='edge_challenge', source='html-challenge')
        return result
    result['format'] = 'json'
    if not isinstance(data, dict):
        return result
    nested = data.get('error') if isinstance(data.get('error'), dict) else {}
    codes = [data.get('code'), data.get('error_code'), nested.get('code')]
    mapping = {'IP_NOT_ALLOWED': 'ip_restricted', 'IP_NOT_WHITELISTED': 'ip_restricted',
               'IP_RESTRICTED': 'ip_restricted', 'INVALID_API_KEY': 'credentials_rejected',
               'API_KEY_INVALID': 'credentials_rejected', 'API_KEY_REVOKED': 'credentials_rejected',
               'MERCHANT_INACTIVE': 'merchant_restricted', 'MERCHANT_NOT_APPROVED': 'merchant_restricted',
               'ACCOUNT_SUSPENDED': 'merchant_restricted', 'PERMISSION_DENIED': 'api_permission'}
    for value in codes:
        if isinstance(value, str) and value.strip().upper() in mapping:
            result.update(kind=mapping[value.strip().upper()], source='json-code')
            return result
    messages = [data.get('message'), data.get('error'), nested.get('message')]
    for value in messages:
        if not isinstance(value, str):
            continue
        value = value[:DENIAL_LIMIT].casefold()
        kind = None
        if re.search(r'\bip\b', value) and any(term in value for term in ['not allowed', 'not whitelisted', 'tidak diizinkan',
                'belum terdaftar', 'tidak terdaftar', 'not in whitelist', 'belum diwhitelist', 'tidak masuk whitelist']):
            kind = 'ip_restricted'
        elif any(term in value for term in ['invalid api key', 'api key tidak valid', 'api key salah', 'api key revoked']):
            kind = 'credentials_rejected'
        elif any(term in value for term in ['merchant not approved', 'merchant inactive', 'account suspended', 'akun diblokir', 'akun belum disetujui']):
            kind = 'merchant_restricted'
        elif any(term in value for term in ['permission denied', 'insufficient permissions', 'tidak memiliki akses']):
            kind = 'api_permission'
        if kind:
            result.update(kind=kind, source='json-message')
            return result
    return result


def access_note(denial, status):
    notes = {'ip_restricted': 'Respons API menyebut pembatasan IP pembayaran.',
             'credentials_rejected': 'Respons API menolak kredensial pembayaran.',
             'merchant_restricted': 'Respons API menyebut pembatasan atau persetujuan akun merchant.',
             'api_permission': 'Respons API menyebut izin akses yang belum tersedia.',
             'edge_challenge': 'Respons meminta challenge dari perantara keamanan; request API belum diterima normal.'}
    kind = denial.get('kind') if isinstance(denial, dict) else None
    return notes.get(kind, 'HTTP 403 menolak akses; alasan spesifik belum diberikan oleh respons API.' if status == 403 else
                     'Pemeriksaan API belum berhasil. Tidak ada invoice uji dibuat.')


@dataclass(frozen=True)
class Config:
    key: str = field(default='', repr=False)
    base_url: str = 'https://payinaja.com/api/v1'
    timeout: int = 15
    server: int = 2
    enabled: bool = False

    @classmethod
    def environment(cls):
        key, _ = environment_value('PAYINAJA_API_KEY')
        base, _ = environment_value('PAYINAJA_API_BASE_URL', cls.base_url)
        server, _ = environment_value('PAYINAJA_QRIS_SERVER', '2')
        enabled, _ = environment_value('PAYINAJA_ENABLED', 'false')
        return cls(key=key, base_url=base.rstrip('/'),
                   server=int(server) if server in {'1', '2'} else 0,
                   enabled=enabled.lower() in {'true', '1'})

    def valid(self):
        try:
            u = urlsplit(self.base_url)
            return (isinstance(self.key, str) and 1 <= len(self.key) <= 4096
                    and all(33 <= ord(c) <= 126 for c in self.key)
                    and u.scheme == 'https' and u.hostname in API_HOSTS
                    and u.port in {None, 443} and not u.username and not u.password
                    and u.path == '/api/v1' and not u.query and not u.fragment
                    and type(self.server) is int and self.server in {1, 2}
                    and 3 <= self.timeout <= 60 and not isinstance(self.timeout, bool))
        except (ValueError, TypeError, AttributeError):
            return False


def qris_payload(value, total):
    """Validate the original dynamic IDR payload without altering its bytes."""
    if not isinstance(value, str):
        raise GatewayError('IMAGE')
    try:
        raw = value.encode()
    except UnicodeError:
        raise GatewayError('IMAGE') from None
    if not 24 <= len(raw) <= 4096:
        raise GatewayError('IMAGE')
    fields = {}
    pos = 0
    try:
        while pos < len(raw):
            tag, length = raw[pos:pos + 2], raw[pos + 2:pos + 4]
            if len(length) != 2 or not tag.isdigit() or not length.isdigit():
                raise ValueError
            end = pos + 4 + int(length)
            if end > len(raw) or tag in fields:
                raise ValueError
            fields[tag] = raw[pos + 4:end]
            if tag == b'63' and (end != len(raw) or length != b'04'):
                raise ValueError
            pos = end
        if (fields.get(b'00') != b'01' or fields.get(b'01') not in {b'11', b'12'}
                or fields.get(b'53') != b'360' or fields.get(b'58') != b'ID'
                or not any(26 <= int(t) <= 51 for t in fields)
                or not re.fullmatch(b'[0-9A-Fa-f]{4}', fields.get(b'63', b''))):
            raise ValueError
        if binascii.crc_hqx(raw[:-4], 0xFFFF) != int(fields[b'63'], 16):
            raise ValueError
        try:
            qr_amount = money(fields[b'54'].decode(), positive=True)
        except GatewayError:
            raise GatewayError('IMAGE') from None
        if qr_amount != money(total, positive=True):
            raise GatewayError('MISMATCH')
    except (ValueError, KeyError, UnicodeError):
        raise GatewayError('IMAGE') from None
    return value


def render_qris(payload, total):
    verified = qris_payload(payload, total)
    output = BytesIO()
    try:
        qrcode.make(verified, box_size=6).save(output, format='PNG')
    except (qrcode.exceptions.DataOverflowError, ValueError, OSError):
        raise GatewayError('IMAGE') from None
    return output.getvalue()


def qris_source(data, total):
    """Recover the provider's exact EMV text; never fetch an image or alter QR bytes."""
    raw = data.get('qris_string')
    blank = raw in (None, '') or (isinstance(raw, str) and not raw.strip())
    primary = None if blank else qris_payload(raw, total)
    url = data.get('qris_image_url')
    alternative = None
    try:
        if not isinstance(url, str) or not url or len(url) > 32768:
            raise GatewayError('QR_SOURCE_MISSING')
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or parsed.hostname != 'quickchart.io' or parsed.port not in {None, 443}
                or parsed.username or parsed.password or parsed.fragment or parsed.path not in {'/qr', '/qr/'}):
            raise GatewayError('QR_URL_UNSUPPORTED')
        query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=20, errors='strict')
        values = query.get('text', [])
        if len(values) != 1 or not values[0]:
            raise GatewayError('QR_URL_UNSUPPORTED')
        alternative = qris_payload(values[0], total)
    except (ValueError, UnicodeError):
        if primary is None:
            raise GatewayError('QR_URL_UNSUPPORTED') from None
    except GatewayError as exc:
        if primary is None or exc.code == 'MISMATCH':
            raise
    if primary is not None and alternative is not None and primary != alternative:
        raise GatewayError('MISMATCH')
    return primary or alternative


def qr_source_shape(data):
    """Fixed source categories only; never disclose QR text, URL or query values."""
    raw, image = data.get('qris_string'), data.get('qris_image_url')
    text = ('missing' if raw is None else 'invalid-type' if not isinstance(raw, str) else
            'blank' if not raw.strip() else 'present')
    kind = 'missing' if image is None else 'invalid-type' if not isinstance(image, str) else 'unsupported'
    if isinstance(image, str):
        if not image.strip():
            kind = 'blank'
        elif image.startswith('data:image/'):
            kind = 'inline'
        else:
            try:
                parsed = urlsplit(urljoin('https://payinaja.com/', image))
                if parsed.hostname == 'quickchart.io':
                    kind = 'quickchart'
                elif parsed.hostname in API_HOSTS:
                    kind = 'official-api' if parsed.path.startswith('/api/v1/') else 'official-image'
            except (ValueError, TypeError):
                pass
    return dict(qris_string=text, qris_image_url=kind)


def amounts(data, requested, expected_total=None, expected_fee=None):
    base = money(requested, positive=True)
    fee = money(data.get('fee'))
    total = money(data.get('total_amount'), positive=True)
    if (total not in {base, base + fee} or total <= fee
            or (expected_total is not None and total != expected_total)
            or (expected_fee is not None and fee != expected_fee)):
        raise GatewayError('MISMATCH')
    return base, fee, total


def response_shape(data):
    """Safe structure only: never retain raw response values, QR, identities or money."""
    def kind(value):
        return ('null' if value is None else 'bool' if isinstance(value, bool) else
                'string' if isinstance(value, str) else 'object' if isinstance(value, dict) else
                'array' if isinstance(value, list) else 'number' if isinstance(value, (int, Decimal)) else 'other')
    result = {'data': kind(data)}
    if isinstance(data, dict):
        for key in ['trx_id', 'merchant_ref', 'status', 'payment_method', 'net_amount', 'fee', 'total_amount', 'qris_string', 'qris_image_url']:
            result[key] = kind(data[key]) if key in data else 'missing'
        status = data.get('status')
        if isinstance(status, str) and status.strip().lower() in {'pending', 'success', 'failed', 'cancelled', 'canceled', 'expired', 'paid', 'waiting', 'unpaid', 'processing'}:
            result['status'] = status.strip().lower()
        method = data.get('payment_method')
        if isinstance(method, str):
            result['payment_method'] = 'qris' if method.strip().casefold() == 'qris' else 'other-string'
    return result


def lifecycle_status(data, *, bound=False):
    if not isinstance(data, dict):
        raise GatewayError('SCHEMA')
    raw = data.get('status')
    states = {'pending': 'PENDING', 'success': 'PAID', 'failed': 'FAILED'}
    if not isinstance(raw, str):
        raise GatewayError('SCHEMA')
    state = states.get(raw.strip().casefold())
    if state is None and bound and raw.strip().casefold() in {'cancelled', 'canceled', 'expired'}:
        state = 'FAILED'
    if state is None:
        raise GatewayError('SCHEMA')
    if bound and state == 'FAILED':
        return state  # Authenticated terminal failure cannot credit funds or deliver goods.
    method = data.get('payment_method')
    if (method is None or (isinstance(method, str) and not method.strip())) and bound and state != 'PAID':
        return state  # Existing authenticated QRIS create binds this invoice's method.
    if not isinstance(method, str) or method.strip().casefold() != 'qris':
        raise GatewayError('SCHEMA')
    return state


class Client:
    def __init__(self, config):
        self.config = config
        self.session = None
        self.cooldown_until = 0

    async def request(self, method, path, body=None):
        if not self.config.valid():
            raise GatewayError('CONFIG')
        allowed = ((method == 'GET' and re.fullmatch(
            r'/(?:profile|(?:transactions|showtrx)\?limit=[1-9][0-9]?(?:&offset=[0-9]{1,8})?|transaction/[A-Za-z0-9_-]{1,96})', path))
            or (method == 'POST' and (path in {'/qris/create', '/qris/create2'} or re.fullmatch(
                r'/transaction/[A-Za-z0-9_-]{1,96}/cancel', path))))
        if not allowed:
            raise GatewayError('CONFIG')
        label = re.sub(r'/transaction/[^/?]+', '/transaction/{trx_id}', path).split('?', 1)[0]
        endpoint = method + ' ' + label
        write = method == 'POST'

        def error(code, status=0, retry_after=0):
            exc = GatewayError(code, http_status=status, uncertain=write,
                               endpoint=endpoint, retry_after=retry_after)
            exc.provider = 'payinaja'
            exc.request_checked_at = time.time()
            return exc

        if self.cooldown_until > time.time():
            raise error('RATE_LIMIT', retry_after=int(self.cooldown_until - time.time()) + 1)
        try:
            if self.session is None or self.session.closed:
                self.session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout), trust_env=True)
            options = {'headers': {'x-api-key': self.config.key, 'Accept': 'application/json'},
                       'allow_redirects': False}
            if body is not None:
                options['json'] = body
            async with self.session.request(method, self.config.base_url + path, **options) as response:
                status = response.status
                if status == 429:
                    try:
                        delay = min(3600, max(1, int(response.headers.get('Retry-After', '60'))))
                    except (ValueError, TypeError):
                        delay = 60
                    self.cooldown_until = time.time() + delay
                    raise error('RATE_LIMIT', status, delay)
                if status >= 500:
                    raise error('UPSTREAM', status)
                if status in {401, 403}:
                    exc = error('AUTH', status)
                    exc.denial = await denial_context(response)
                    raise exc
                if status == 404:
                    code = ('NOT_FOUND' if path.startswith('/transaction/') else
                            'HISTORY_UNAVAILABLE' if path.startswith(('/transactions?', '/showtrx?')) else
                            'ENDPOINT_NOT_FOUND')
                    raise error(code, status)
                if status == 400:
                    raise error('REJECTED', status)
                if status != 200:
                    raise error('HTTP', status)
                raw = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    raw.extend(chunk)
                    if len(raw) > BODY_LIMIT:
                        raise error('SCHEMA', status)
                try:
                    value = json.loads(raw.decode(), parse_float=Decimal)
                except (ValueError, UnicodeError):
                    raise error('JSON_INVALID', status) from None
                if not isinstance(value, dict) or type(value.get('success')) is not bool:
                    exc = error('SCHEMA', status)
                    exc.schema_hint = dict(response_shape(value.get('data') if isinstance(value, dict) else None),
                        envelope=type(value).__name__,
                        success=type(value['success']).__name__ if isinstance(value, dict) and 'success' in value else 'missing')
                    raise exc
                if not value['success']:
                    raise error('REJECTED', status)
                return value.get('data')
        except aiohttp.ClientSSLError:
            raise error('TLS') from None
        except aiohttp.ClientConnectorDNSError:
            raise error('DNS') from None
        except aiohttp.ClientHttpProxyError as exc:
            raise error('PROXY', exc.status) from None
        except asyncio.TimeoutError:
            raise error('TIMEOUT') from None
        except aiohttp.ClientError:
            raise error('NETWORK') from None

    @staticmethod
    def validation_context(exc, endpoint, data=None):
        exc.http_status = 200
        exc.endpoint = endpoint
        exc.provider = 'payinaja'
        exc.request_checked_at = time.time()
        if exc.code == 'SCHEMA':
            exc.schema_hint = response_shape(data)
        return exc

    async def profile(self):
        data = await self.request('GET', '/profile')
        try:
            if not isinstance(data, dict) or not isinstance(data.get('status'), str):
                raise GatewayError('SCHEMA')
            if data['status'].casefold() != 'approved':
                raise GatewayError('MERCHANT_INACTIVE')
            email = data.get('email')
            if not isinstance(email, str) or not re.fullmatch(r'[^\s@]{1,200}@[^\s@]{1,200}', email):
                raise GatewayError('SCHEMA')
            try:
                binding = hashlib.sha256(email.casefold().encode()).hexdigest()
            except UnicodeError:
                raise GatewayError('SCHEMA') from None
            # Never persist/log the profile's name, email, phone or balance.
            return {'approved': True, 'account_binding': binding}
        except GatewayError as exc:
            raise self.validation_context(exc, 'GET /profile')

    async def create(self, ref, amount, server=None):
        ref, amount = reference(ref), money(amount, positive=True)
        if amount < 500:
            raise GatewayError('MIN_AMOUNT')
        server = self.config.server if server is None else server
        if type(server) is not int or server not in {1, 2}:
            raise GatewayError('CONFIG')
        path = '/qris/create2' if server == 2 else '/qris/create'
        data = await self.request('POST', path, {'reference_id': ref, 'amount': amount})
        try:
            if not isinstance(data, dict):
                raise GatewayError('SCHEMA')
            if data.get('merchant_ref') != ref:
                raise GatewayError('MISMATCH')
            if money(data.get('amount_requested'), positive=True) != amount:
                raise GatewayError('MISMATCH')
            base, fee, total = amounts(data, amount)
            ident = reference(data.get('payinaja_trx_id'))
            if not isinstance(data.get('status'), str) or data['status'].strip().casefold() != 'pending':
                raise GatewayError('SCHEMA')
            return {'provider_id': ident, 'reference': ref, 'amount': base, 'fee': fee,
                    'total_amount': total, 'status': 'PENDING', 'qris_string': data.get('qris_string'),
                    'qris_image_url': data.get('qris_image_url'),
                    'created_at': data.get('created_at')}
        except GatewayError as exc:
            exc.uncertain = True
            raise self.validation_context(exc, 'POST ' + path, data)

    async def status(self, ident, ref, amount, total=None, fee=None):
        ident, ref = reference(ident), reference(ref)
        data = await self.request('GET', '/transaction/' + ident)
        try:
            if not isinstance(data, dict):
                raise GatewayError('SCHEMA')
            if data.get('trx_id') != ident or data.get('merchant_ref') != ref:
                raise GatewayError('MISMATCH')
            state = lifecycle_status(data, bound=total is not None and fee is not None)
            if state == 'FAILED' and total is not None and fee is not None:
                # Preserve the known create quote; a failed invoice has no
                # settlement amount to authorize or overwrite that snapshot.
                base, checked_fee, checked_total = money(amount, positive=True), money(fee), money(total, positive=True)
            elif state == 'PAID' or total is None or fee is None:
                base, checked_fee, checked_total = amounts(data, amount, total, fee)
            else:
                # Pending/failed values are not settlement evidence. Keep the
                # authenticated create snapshot; reject contradictory positive values.
                base, checked_fee, checked_total = money(amount, positive=True), money(fee), money(total, positive=True)
                for field, expected in [('total_amount', checked_total), ('fee', checked_fee)]:
                    if data.get(field) is not None and money(data[field]) not in {0, expected}:
                        raise GatewayError('MISMATCH')
            if state == 'PAID' and money(data.get('net_amount')) != checked_total - checked_fee:
                raise GatewayError('MISMATCH')
            if state != 'FAILED' and data.get('amount_requested') is not None and money(data['amount_requested'], positive=True) != base:
                raise GatewayError('MISMATCH')
            return {'provider_id': ident, 'reference': ref, 'amount': base, 'fee': checked_fee,
                    'total_amount': checked_total, 'status': state,
                    'qris_string': data.get('qris_string'), 'qris_image_url': data.get('qris_image_url'),
                    'created_at': data.get('created_at')}
        except GatewayError as exc:
            raise self.validation_context(exc, 'GET /transaction/{trx_id}', data)

    async def history(self, limit=10, offset=0):
        if type(limit) is not int or not 1 <= limit <= 50 or type(offset) is not int or not 0 <= offset <= 10000000:
            raise GatewayError('INPUT')
        data = await self.request('GET', '/showtrx?limit=' + str(limit) + '&offset=' + str(offset))
        try:
            if not isinstance(data, list) or len(data) > limit:
                raise GatewayError('SCHEMA')
            for row in data:
                if not isinstance(row, dict):
                    raise GatewayError('SCHEMA')
                reference(row.get('trx_id'))
            return data
        except GatewayError as exc:
            raise self.validation_context(exc, 'GET /transactions')

    async def cancel(self, ident):
        await self.request('POST', '/transaction/' + reference(ident) + '/cancel')
        return dict(accepted=True, http_status=200, checked_at=time.time(),
                    correlation_id=secrets.token_hex(8), endpoint='POST /transaction/{trx_id}/cancel')

    async def cancel_status(self, ident, ref, *, bound=False):
        """Identity + lifecycle only; this response NEVER authorizes a payment."""
        ident, ref = reference(ident), reference(ref)
        data = await self.request('GET', '/transaction/' + ident)
        try:
            if not isinstance(data, dict):
                raise GatewayError('SCHEMA')
            if data.get('trx_id') != ident or data.get('merchant_ref') != ref:
                raise GatewayError('MISMATCH')
            return lifecycle_status(data, bound=bound)
        except GatewayError as exc:
            raise self.validation_context(exc, 'GET /transaction/{trx_id}', data)

    @staticmethod
    def image_valid(raw):
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= QR_LIMIT:
            raise GatewayError('IMAGE_SIZE')
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', Image.DecompressionBombWarning)
                with Image.open(BytesIO(raw)) as picture:
                    if (picture.format not in {'PNG', 'JPEG', 'WEBP'} or min(picture.size) < 32
                            or max(picture.size) > 4096 or getattr(picture, 'is_animated', False)):
                        raise ValueError
                    picture.verify()
        except Exception:
            raise GatewayError('IMAGE') from None
        return raw  # Original API-provided raster, never reconstructed/repriced.

    async def image(self, value, provider_id=None):
        """Fetch only the image URL returned by an authenticated, bound invoice."""
        endpoint = 'GET {qris_image}'
        if not self.config.valid() or not isinstance(value, str):
            raise GatewayError('CONFIG' if not self.config.valid() else 'IMAGE')
        if value.startswith(('data:image/png;base64,', 'data:image/jpeg;base64,', 'data:image/webp;base64,')):
            if len(value) > (QR_LIMIT * 4 // 3) + 128:
                raise GatewayError('IMAGE_SIZE')
            try:
                return self.image_valid(base64.b64decode(value.split(',', 1)[1], validate=True))
            except (ValueError, TypeError):
                raise GatewayError('IMAGE') from None
        try:
            if not value or len(value) > 32768 or any(ord(c) < 33 for c in value):
                raise ValueError
            origin = urlsplit(self.config.base_url)
            url = urljoin(origin.scheme + '://' + origin.netloc + '/', value)
            parsed = urlsplit(url)
            path = unquote(unquote(parsed.path))
            if (parsed.scheme != 'https' or parsed.port not in {None, 443} or parsed.username or parsed.password
                    or parsed.fragment or '\\' in path or '..' in path.split('/')):
                raise ValueError
            official = parsed.hostname in API_HOSTS
            public_image = official and re.fullmatch(r'/(?:storage|uploads|images)/.+\.(?:png|jpg|jpeg|webp)', path, re.I)
            api_image = official and (
                (re.fullmatch(r'/api/v1/qris/image/[A-Za-z0-9_-]{1,96}', path)
                 and (not provider_id or path == '/api/v1/qris/image/' + reference(provider_id)))
                or (provider_id and path == '/api/v1/transaction/' + reference(provider_id) + '/qris'))
            quickchart = parsed.hostname == 'quickchart.io' and re.fullmatch(r'/qr(?:/[A-Za-z0-9_-]{1,128})?/?', path)
            if not (public_image or api_image or quickchart):
                raise ValueError
            if not official and self.config.key in unquote(url):
                raise ValueError
            headers = {'Accept': 'image/png,image/jpeg,image/webp'}
            if api_image and parsed.hostname == origin.hostname:
                headers['x-api-key'] = self.config.key
        except (ValueError, TypeError):
            raise GatewayError('QR_URL_UNSUPPORTED', endpoint=endpoint) from None
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.config.timeout), trust_env=True)
        try:
            async with self.session.request('GET', url, headers=headers, allow_redirects=False) as response:
                if response.status != 200:
                    code = ('IMAGE_AUTH' if response.status in {401, 403} else 'IMAGE_NOT_FOUND' if response.status == 404 else
                            'IMAGE_RATE_LIMIT' if response.status == 429 else 'UPSTREAM' if response.status >= 500 else 'IMAGE_HTTP')
                    try:
                        delay = min(3600, max(1, int(response.headers.get('Retry-After', '30')))) if response.status == 429 else 5
                    except (TypeError, ValueError):
                        delay = 30
                    raise GatewayError(code, http_status=response.status, endpoint=endpoint, retry_after=delay)
                raw = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    raw.extend(chunk)
                    if len(raw) > QR_LIMIT:
                        raise GatewayError('IMAGE_SIZE', http_status=200, endpoint=endpoint)
                return self.image_valid(bytes(raw))
        except aiohttp.ClientSSLError:
            raise GatewayError('TLS', endpoint=endpoint) from None
        except aiohttp.ClientConnectorDNSError:
            raise GatewayError('DNS', endpoint=endpoint) from None
        except aiohttp.ClientHttpProxyError as exc:
            raise GatewayError('PROXY', http_status=exc.status, endpoint=endpoint) from None
        except asyncio.TimeoutError:
            raise GatewayError('TIMEOUT', endpoint=endpoint) from None
        except aiohttp.ClientError:
            raise GatewayError('NETWORK', endpoint=endpoint) from None

    async def close(self):
        if self.session is not None and not self.session.closed:
            await self.session.close()


class Gateway:
    """Provider metadata in the existing settings table; native money is unchanged."""
    def __init__(self, host, config=None):
        self.host = host
        self.config = config or Config.environment()
        self.api = Client(self.config)
        self.bot = None
        self.tasks = []
        self.delivery_locks = {}
        self.started_at = time.time()
        self.requested_qr_ids = set()

    @contextmanager
    def connection(self, write=False):
        conn = self.host.db()
        try:
            if write:
                self.host.begin_immediate_retry(conn)
            yield conn
            if write:
                conn.commit()
        except BaseException:
            if write:
                conn.rollback()
            raise
        finally:
            conn.close()

    def setting(self, key, default=None, conn=None):
        if conn is None:
            with self.connection() as db:
                return self.setting(key, default, db)
        found = conn.execute('SELECT value FROM settings WHERE key=?', ('payinaja.' + key,)).fetchone()
        if not found:
            return default
        try:
            return json.loads(found[0])
        except (ValueError, TypeError):
            raise GatewayError('STORAGE') from None

    def put(self, conn, key, value):
        conn.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',
                     ('payinaja.' + key, encoded(value)))

    @staticmethod
    def ident(purpose, entity):
        if purpose not in {'order', 'topup'} or type(entity) is not int or entity <= 0:
            raise GatewayError('INPUT')
        return ('o' if purpose == 'order' else 't') + str(entity)

    def transaction(self, ident, user=None, *, conn=None, admin=False):
        if not isinstance(ident, str) or not re.fullmatch(r'[ot][1-9][0-9]{0,17}', ident):
            raise GatewayError('INPUT')
        row = self.setting('tx.' + ident, None, conn)
        if not isinstance(row, dict):
            raise GatewayError('NOT_FOUND')
        if (row.get('version') != 1 or row.get('id') != ident
                or self.ident(row.get('purpose'), row.get('entity_id')) != ident
                or type(row.get('user_id')) is not int or row['user_id'] <= 0
                or row.get('state') not in FINAL | {'NEW', 'REQUESTING', 'CREATE_UNKNOWN', 'PENDING',
                                                   'PAID_VERIFIED', 'CANCELLED_LOCAL', 'REVIEW'}):
            raise GatewayError('STORAGE')
        reference(row.get('reference'))
        money(row.get('amount'), positive=True)
        if admin:
            self.require_owner(user)
        elif user is not None and row['user_id'] != user:
            raise GatewayError('FORBIDDEN')
        return row

    def save(self, conn, row):
        if row['state'] in FINAL | {'REVIEW', 'PAID_VERIFIED'}:
            row.pop('cancel_prompt', None)
        self.put(conn, 'tx.' + row['id'], row)
        active = 'payinaja.active.' + row['id']
        if row['state'] in FINAL or row['state'] == 'REVIEW':
            conn.execute('DELETE FROM settings WHERE key=?', (active,))
        else:
            conn.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',
                         (active, f"{row.get('next_poll_at', 0):020.3f}"))
        retention = 'payinaja.retention.' + row['id']
        if row['state'] in {'SETTLED', 'SETTLED_BALANCE'} and not row.get('retention_done'):
            conn.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',
                         (retention, f"{row.get('cleanup_at', 0):020.3f}"))
        else:
            conn.execute('DELETE FROM settings WHERE key=?', (retention,))
        messages = 'payinaja.messages.' + row['id']
        removable = [item for item in row['qr_messages'] if item['kind'] == 'QR']
        if removable and (row['state'] in FINAL | {'REVIEW', 'PAID_VERIFIED'} or row['cancel_requested']):
            conn.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',
                         (messages, f"{min(item['retry_at'] for item in removable):020.3f}"))
        else:
            conn.execute('DELETE FROM settings WHERE key=?', (messages,))
        review = 'payinaja.review.' + row['id']
        if row['state'] == 'REVIEW':
            conn.execute('INSERT OR REPLACE INTO settings VALUES(?,?)', (review, str(row['created_at'])))
        else:
            conn.execute('DELETE FROM settings WHERE key=?', (review,))

    def linked(self, purpose, entity, conn=None):
        ident = self.ident(purpose, int(entity))
        if self.setting('tx.' + ident, None, conn) is None:
            return None
        return self.transaction(ident, conn=conn)

    def require_owner(self, actor):
        if not self.host.is_owner(actor):
            raise GatewayError('FORBIDDEN')

    def fingerprint(self):
        return hashlib.sha256(encoded({'key': self.config.key, 'base': self.config.base_url}).encode()).hexdigest()

    def proof(self, conn=None):
        proof = self.setting('profile', {}, conn)
        return proof if isinstance(proof, dict) and proof.get('fingerprint') == self.fingerprint() else {}

    def enabled(self):
        value = self.setting('enabled', self.config.enabled)
        return value is True

    def ready(self):
        try:
            return self.config.valid() and self.enabled() and self.proof().get('approved') is True
        except (sqlite3.Error, GatewayError):
            return False

    def can_attempt(self):
        try:
            return self.config.valid() and self.enabled()
        except (sqlite3.Error, GatewayError):
            return False

    @staticmethod
    def has_qr(row):
        return bool(row.get('qris_cipher') or row.get('qr_image_cipher'))

    def diagnostic(self, exc, stage, *, conn=None):
        if not hasattr(exc, 'request_checked_at'):
            exc.request_checked_at = time.time()
        data = dict(stage=stage, code=getattr(exc, 'code', 'SQLITE' if isinstance(exc, sqlite3.Error) else 'INTERNAL'),
                    http_status=getattr(exc, 'http_status', 0), checked_at=time.time(),
                    correlation_id=getattr(exc, 'correlation_id', '') or secrets.token_hex(8),
                    endpoint=getattr(exc, 'endpoint', ''), fingerprint=self.fingerprint(),
                    request_checked_at=exc.request_checked_at)
        if getattr(exc, 'cached', False):
            data.update(cached=True, request_checked_at=getattr(exc, 'request_checked_at', data['checked_at']))
        if isinstance(getattr(exc, 'denial', None), dict):
            data['denial'] = exc.denial
        if isinstance(getattr(exc, 'schema_hint', None), dict):
            data['schema'] = exc.schema_hint
        logging.warning('Payinaja stage=%s code=%s correlation_id=%s', stage, data['code'], data['correlation_id'])
        try:
            if conn is None:
                with self.connection(True) as db:
                    self.put(db, 'diagnostic.' + stage, data)
                    if data['code'] in {'AUTH', 'MERCHANT_INACTIVE'} and not data.get('cached'):
                        proof = self.proof(db)
                        if proof:
                            proof.update(approved=False, checked_at=data['request_checked_at'], error=data['code'],
                                         http_status=data['http_status'], error_endpoint=data['endpoint'],
                                         error_correlation_id=data['correlation_id'], error_denial=data.get('denial', {}))
                            self.put(db, 'profile', proof)
            else:
                self.put(conn, 'diagnostic.' + stage, data)
                if data['code'] in {'AUTH', 'MERCHANT_INACTIVE'} and not data.get('cached'):
                    proof = self.proof(conn)
                    if proof:
                        proof.update(approved=False, checked_at=data['request_checked_at'], error=data['code'],
                                     http_status=data['http_status'], error_endpoint=data['endpoint'],
                                     error_correlation_id=data['correlation_id'], error_denial=data.get('denial', {}))
                        self.put(conn, 'profile', proof)
        except sqlite3.Error:
            pass
        return data

    async def ensure_profile(self, *, force=False):
        current = self.proof()
        if current.get('approved') and not force:
            return current
        if not force and current.get('error') and current.get('checked_at', 0) + 30 > time.time():
            exc = GatewayError(current['error'], http_status=current.get('http_status', 0),
                               endpoint=current.get('error_endpoint') or 'GET /profile')
            exc.cached = True
            exc.request_checked_at = current.get('checked_at', 0)
            if re.fullmatch('[0-9a-f]{16}', str(current.get('error_correlation_id', ''))):
                exc.correlation_id = current['error_correlation_id']
            exc.denial = current.get('error_denial', {})
            raise exc
        try:
            result = await self.api.profile()
        except GatewayError as exc:
            detail = self.diagnostic(exc, 'connection')
            with self.connection(True) as conn:
                self.put(conn, 'profile', dict(approved=False, fingerprint=self.fingerprint(),
                    checked_at=detail['request_checked_at'], error=exc.code, http_status=exc.http_status,
                    error_endpoint=detail['endpoint'], error_correlation_id=detail['correlation_id'],
                    error_denial=detail.get('denial', {})))
            raise
        result.update(fingerprint=self.fingerprint(), checked_at=time.time(), http_status=200)
        with self.connection(True) as conn:
            self.put(conn, 'profile', result)
            self.put(conn, 'diagnostic.connection', dict(stage='profile', code='OK', http_status=200,
                     correlation_id=secrets.token_hex(8), checked_at=time.time(), fingerprint=self.fingerprint()))
        return result

    async def check_connection(self, actor):
        self.require_owner(actor)
        return await self.ensure_profile(force=True)

    async def activate(self, actor):
        self.require_owner(actor)
        await self.ensure_profile(force=True)  # GET only, never a probe invoice.
        with self.connection(True) as conn:
            self.put(conn, 'enabled', True)

    def disable(self, actor):
        self.require_owner(actor)
        with self.connection(True) as conn:
            self.put(conn, 'enabled', False)

    def creation_health(self):
        proof = self.setting('create', {})
        if not isinstance(proof, dict) or proof.get('fingerprint') != self.fingerprint():
            profile = self.proof()
            if profile.get('error'):
                return False, ('Belum diuji: akses API/profil belum berhasil (HTTP ' +
                               str(profile.get('http_status') or '-') + '). Self-test tidak membuat invoice.')
            return False, 'Belum ada bukti create dengan key aktif. Self-test tidak membuat invoice.'
        if proof.get('error') and not proof.get('resolved_at'):
            return False, str(proof['error']) + ' • HTTP ' + str(proof.get('http_status') or '-')
        return bool(proof.get('success') or proof.get('resolved_at')), 'Metadata create terakhir tervalidasi / direkonsiliasi.'

    def _key(self):
        return hmac.new(str(self.host.BOT_TOKEN).encode(), b'maboyy-payinaja-data-v1', hashlib.sha256).digest()

    def crypt(self, value, ident, *, decrypt=False):
        try:
            if decrypt:
                raw = base64.b64decode(value, validate=True)
                cipher = AES.new(self._key(), AES.MODE_GCM, nonce=raw[:12])
                cipher.update(ident.encode())
                return cipher.decrypt_and_verify(raw[28:], raw[12:28]).decode()
            cipher = AES.new(self._key(), AES.MODE_GCM, nonce=secrets.token_bytes(12))
            cipher.update(ident.encode())
            data, tag = cipher.encrypt_and_digest(value.encode())
            return base64.b64encode(cipher.nonce + tag + data).decode()
        except (ValueError, TypeError, UnicodeError):
            raise GatewayError('STORAGE') from None

    def proof_mac(self, row):
        fields = ('id', 'purpose', 'entity_id', 'user_id', 'reference', 'provider_id', 'amount', 'fee',
                  'total_amount', 'account_binding', 'origin', 'verified_at', 'verified_total', 'verified_status')
        return hmac.new(self._key(), encoded({key: row.get(key) for key in fields}).encode(), hashlib.sha256).hexdigest()

    def paid_proof(self, row):
        return bool(row and row.get('verified_at', 0) > 0 and row.get('verified_status') == 'PAID'
                    and row.get('verified_total') == row.get('total_amount') and row.get('provider_id')
                    and isinstance(row.get('verification_mac'), str)
                    and hmac.compare_digest(row['verification_mac'], self.proof_mac(row)))

    def payment_authorized(self, conn, purpose, entity, *, settled=False):
        row = self.linked(purpose, entity, conn)
        if not row or not self.paid_proof(row) or row['state'] not in ({'PAID_VERIFIED', 'SETTLED'} if settled else {'PAID_VERIFIED'}):
            return False
        native = conn.execute('SELECT * FROM ' + ('orders' if purpose == 'order' else 'topups') + ' WHERE id=?', (entity,)).fetchone()
        base = (native['total'] - int(native['discount_amount'] or 0) if purpose == 'order' else native['amount']) if native else None
        return bool(native and native['payment_method'] == METHOD and native['user_id'] == row['user_id']
                    and native['provider_reference'] == row['provider_id'] and native['payment_total'] == row['total_amount']
                    and base == row['amount'])

    def reserve(self, conn, purpose, entity, user, amount):
        if not self.ready():
            raise GatewayError('NOT_READY')
        existing = self.linked(purpose, entity, conn)
        if existing:
            return existing
        amount = money(amount, positive=True)
        if amount < 500:
            raise GatewayError('MIN_AMOUNT')
        profile = self.proof(conn)
        row = dict(version=1, id=self.ident(purpose, entity), purpose=purpose, entity_id=entity, user_id=user,
                   reference='PA-' + purpose[0].upper() + '-' + str(entity) + '-' + secrets.token_hex(8),
                   origin=self.config.base_url, server=self.config.server, account_binding=profile['account_binding'],
                   amount=amount, fee=None, total_amount=None, provider_id=None, state='NEW',
                   created_at=time.time(), expires_at=time.time() + 900, next_poll_at=0, error='',
                   lease_owner=None, lease_until=0, cancel_requested=False, request_started_at=0,
                   verified_at=0, verified_total=None, verified_status='', verification_mac='',
                   qris_cipher=None, qr_image_cipher=None, qr_source_cipher=None, qr_messages=[], delivery_owner=None, delivery_until=0,
                   reconcile_offset=0, sandbox=0, cleanup_at=0, retention_done=False)
        self.save(conn, row)
        return row

    def resumable(self, purpose, user, *, variant=None, qty=None, amount=None, conn=None):
        if conn is None:
            with self.connection() as db:
                return self.resumable(purpose, user, variant=variant, qty=qty, amount=amount, conn=db)
        if purpose == 'order':
            sql = """SELECT n.id,s.value FROM orders n JOIN settings s ON s.key='payinaja.tx.o'||n.id
                WHERE n.user_id=? AND n.variant_id=? AND n.qty=? AND n.payment_method=? AND n.payment_status!='paid'
                ORDER BY n.id DESC LIMIT 20"""
            args = (user, variant, qty, METHOD)
        else:
            sql = """SELECT n.id,s.value FROM topups n JOIN settings s ON s.key='payinaja.tx.t'||n.id
                WHERE n.user_id=? AND n.amount=? AND n.payment_method=? AND n.status!='completed'
                ORDER BY n.id DESC LIMIT 20"""
            args = (user, amount, METHOD)
        for record in conn.execute(sql, args):
            try:
                row = self.transaction(self.ident(purpose, record[0]), user, conn=conn)
            except (ValueError, KeyError, TypeError):
                raise GatewayError('STORAGE') from None
            if row['state'] not in FINAL | {'REVIEW'}:
                return row
        return None

    def native_invoice(self, conn, row):
        table = 'orders' if row['purpose'] == 'order' else 'topups'
        if row['provider_id'] and row['total_amount'] is not None:
            if table == 'orders':
                conn.execute("""UPDATE orders SET provider_reference=?,payment_total=?,unique_code=0
                    WHERE id=? AND user_id=? AND payment_method=? AND payment_status!='paid'""",
                    (row['provider_id'], row['total_amount'], row['entity_id'], row['user_id'], METHOD))
            else:
                conn.execute("""UPDATE topups SET provider_reference=?,payment_total=?,unique_code=0
                    WHERE id=? AND user_id=? AND payment_method=? AND status!='completed'""",
                    (row['provider_id'], row['total_amount'], row['entity_id'], row['user_id'], METHOD))

    def retain_qr_source(self, row, data):
        # Called in the SAME transaction that saves the known invoice. No plaintext QR/URL in SQLite.
        if self.has_qr(row) or row.get('retention_done') or row['cancel_requested']:
            return
        # Invalid nonblank fields must stay invalid, rather than becoming a missing
        # primary field that could incorrectly enable the alternative source.
        values = {key: (data[key] if isinstance(data.get(key), str) and len(data[key]) <=
                        ((QR_LIMIT * 4 // 3) + 128 if key == 'qris_image_url' and data[key].startswith('data:image/') else 32768) else
                        None if data.get(key) is None else '!INVALID_QR_SOURCE')
                  for key in ('qris_string', 'qris_image_url')}
        if any(values.values()):
            raw = encoded(values)
            if row.get('qr_source_cipher'):
                try:
                    if self.crypt(row['qr_source_cipher'], row['id'], decrypt=True) == raw:
                        return
                except GatewayError:
                    pass  # A new authenticated status response may replace an unreadable old source.
            row['qr_source_cipher'] = self.crypt(raw, row['id'])

    def cache_qr(self, ident, payload=None):
        row = self.transaction(ident)
        if row['state'] != 'PENDING' or row['cancel_requested'] or row.get('retention_done') or self.has_qr(row):
            return
        data = {}
        try:
            if payload is None:
                source = row.get('qr_source_cipher')
                data = json.loads(self.crypt(source, ident, decrypt=True)) if source else {}
            else:
                data = payload if isinstance(payload, dict) else {'qris_string': payload}
            payload = qris_source(data, row['total_amount'])
            encrypted = self.crypt(payload, ident)
            with self.connection(True) as conn:
                row = self.transaction(ident, conn=conn)
                if (row['state'] == 'PENDING' and not row['cancel_requested'] and not row.get('retention_done')
                        and row['error'] not in QR_BLOCKING_ERRORS):
                    row['qris_cipher'], row['error'] = encrypted, ''
                    self.save(conn, row)
                    self.put(conn, 'diagnostic.image', dict(stage='image', code='OK', http_status=200,
                        checked_at=time.time(), correlation_id=secrets.token_hex(8), fingerprint=self.fingerprint()))
        except GatewayError as exc:
            if exc.code in {'IMAGE', 'MISMATCH', 'SCHEMA'} or exc.code.startswith('QR_'):
                exc.http_status = 200
            exc.schema_hint = qr_source_shape(data)
            with self.connection(True) as conn:
                row = self.transaction(ident, conn=conn)
                if row['state'] == 'PENDING' and row['error'] not in QR_BLOCKING_ERRORS and not self.has_qr(row) and not (row['error'] == 'IMAGE'
                        and row.get('diagnostic', {}).get('code') == exc.code
                        and row.get('diagnostic', {}).get('schema') == exc.schema_hint):
                    row['error'] = 'IMAGE'
                    row['diagnostic'] = self.diagnostic(exc, 'image', conn=conn)
                    self.save(conn, row)

    async def prepare_qr(self, ident):
        row = self.transaction(ident)
        if (row['state'] != 'PENDING' or row['cancel_requested'] or row.get('retention_done')
                or row['error'] in QR_BLOCKING_ERRORS
                or self.has_qr(row) or row['expires_at'] <= time.time()
                or row.get('image_retry_at', 0) > time.time()):
            return row
        profile = self.proof()
        if not profile.get('approved') or profile.get('account_binding') != row['account_binding'] or row['origin'] != self.config.base_url:
            raise GatewayError('ACCOUNT_CHANGED')
        self.cache_qr(ident)
        row = self.transaction(ident)
        if self.has_qr(row) or not row.get('qr_source_cipher'):
            return row
        source = row['qr_source_cipher']
        try:
            data = json.loads(self.crypt(source, ident, decrypt=True))
        except (GatewayError, ValueError, TypeError):
            self.diagnostic(GatewayError('STORAGE'), 'image')
            return row  # Do not prevent authenticated status/settlement reconciliation.
        raw_text = data.get('qris_string')
        if raw_text is not None and (not isinstance(raw_text, str) or raw_text.strip()):
            return row  # Invalid explicit EMV is never bypassed by an image.
        try:
            qris_source(data, row['total_amount'])
            return row  # Valid EMV preparation interrupted; retry locally, not via image.
        except GatewayError as exc:
            if exc.code not in {'QR_URL_UNSUPPORTED', 'QR_SOURCE_MISSING'} or not data.get('qris_image_url'):
                return row
        token = secrets.token_hex(12)
        with self.connection(True) as conn:
            current = self.transaction(ident, conn=conn)
            if (current['state'] != 'PENDING' or current['cancel_requested'] or self.has_qr(current)
                    or current['error'] in QR_BLOCKING_ERRORS
                    or current.get('image_lease_until', 0) > time.time() or current.get('image_retry_at', 0) > time.time()):
                return current
            current.update(image_lease_owner=token, image_lease_until=time.time() + self.config.timeout + 30)
            self.save(conn, current)
        try:
            raw = await self.api.image(data['qris_image_url'], row['provider_id'])
            encrypted = self.crypt(base64.b64encode(raw).decode('ascii'), ident)
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if (current['state'] == 'PENDING' and not current['cancel_requested'] and not current.get('retention_done')
                        and current['error'] not in QR_BLOCKING_ERRORS
                        and current['expires_at'] > time.time()
                        and self.proof(conn).get('approved') and self.proof(conn).get('account_binding') == current['account_binding']
                        and current.get('qr_source_cipher') == source and not self.has_qr(current)):
                    current.update(qr_image_cipher=encrypted, error='', image_retry_at=0)
                    if data['qris_image_url'].startswith('data:image/'):
                        current['qr_source_cipher'] = None  # No duplicate large inline copy.
                    self.save(conn, current)
                    self.put(conn, 'diagnostic.image', dict(stage='image', code='OK_ORIGINAL_IMAGE', http_status=200,
                        checked_at=time.time(), correlation_id=secrets.token_hex(8), fingerprint=self.fingerprint()))
        except GatewayError as exc:
            exc.schema_hint = qr_source_shape(data)
            detail = self.diagnostic(exc, 'image')
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['state'] == 'PENDING' and current['error'] not in QR_BLOCKING_ERRORS and not self.has_qr(current):
                    current.update(error='IMAGE', diagnostic=detail, image_retry_at=time.time() + max(5, exc.retry_after))
                    self.save(conn, current)
        finally:
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current.get('image_lease_owner') == token:
                    current.update(image_lease_owner=None, image_lease_until=0)
                    self.save(conn, current)
        return self.transaction(ident)

    async def issue(self, ident):
        row = self.transaction(ident)
        if row['state'] != 'NEW':
            return row
        if not self.ready():
            raise GatewayError('NOT_READY')
        profile = await self.ensure_profile()
        if profile['account_binding'] != row['account_binding'] or row['origin'] != self.config.base_url:
            raise GatewayError('ACCOUNT_CHANGED')
        token = secrets.token_hex(12)
        with self.connection(True) as conn:
            row = self.transaction(ident, conn=conn)
            if row['state'] != 'NEW':
                return row
            row.update(state='REQUESTING', lease_owner=token, lease_until=time.time() + self.config.timeout + 30,
                       request_started_at=time.time(), next_poll_at=time.time() + 15)
            self.save(conn, row)
        try:
            result = await self.api.create(row['reference'], row['amount'], row['server'])
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['lease_owner'] != token:
                    return current
                current.update(provider_id=result['provider_id'], fee=result['fee'], total_amount=result['total_amount'],
                               lease_owner=None, lease_until=0, error='',
                               state='CANCELLED_LOCAL' if current['cancel_requested'] else 'PENDING')
                self.retain_qr_source(current, result)
                self.native_invoice(conn, current)
                self.save(conn, current)
                self.put(conn, 'create', dict(success=True, error='', http_status=200, stage='create',
                    checked_at=time.time(), correlation_id=secrets.token_hex(8), transaction_id=ident,
                    fingerprint=self.fingerprint(), endpoint='POST /qris/create' + ('2' if row['server'] == 2 else '')))
            try:
                await self.prepare_qr(ident)
            except sqlite3.Error as exc:
                detail = self.diagnostic(exc, 'image')
                try:
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        if current['state'] == 'PENDING':
                            current.update(error='IMAGE', diagnostic=detail)
                            self.save(conn, current)
                except sqlite3.Error:
                    pass  # The durable invoice/source is retained even while storage is unavailable.
        except BaseException as exc:
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['lease_owner'] == token:
                    current.update(state='CANCELLED_LOCAL' if current['cancel_requested'] else 'CREATE_UNKNOWN',
                                   lease_owner=None, lease_until=0, error=getattr(exc, 'code', 'SQLITE' if isinstance(exc, sqlite3.Error) else 'INTERNAL'),
                                   next_poll_at=time.time() + max(15, getattr(exc, 'retry_after', 0)))
                    self.save(conn, current)
                    detail = self.diagnostic(exc, 'create', conn=conn)
                    detail.update(error=detail['code'], success=False, transaction_id=ident)
                    current['diagnostic'] = detail
                    self.save(conn, current)
                    self.put(conn, 'create', detail)
            if not isinstance(exc, Exception):
                raise
        return self.transaction(ident)

    async def reconcile_cancellation(self, ident, provider_id):
        """Submit a bound invoice cancellation once per lease, then read lifecycle."""
        token = secrets.token_hex(12)
        with self.connection(True) as conn:
            row = self.transaction(ident, conn=conn)
            if row['state'] in FINAL | {'REVIEW', 'PAID_VERIFIED'} or not row['cancel_requested']:
                return None
            if row.get('cancel_lease_until', 0) > time.time():
                return None
            row.update(cancel_lease_owner=token, cancel_lease_until=time.time() + self.config.timeout * 3 + 30)
            self.save(conn, row)
        try:
            if row['provider_id']:
                try:
                    lifecycle = await self.api.cancel_status(provider_id, row['reference'], bound=True)
                    if lifecycle in {'FAILED', 'PAID'}:
                        return lifecycle  # Already terminal: do not submit another cancel POST.
                except GatewayError:
                    pass  # Known create ID may still be cancelled if its status read is unavailable.
            # A recovered history ID must be confirmed against this reference
            # before it becomes a cancellation target. Known create IDs are bound already.
            if not row['provider_id']:
                lifecycle = await self.api.cancel_status(provider_id, row['reference'])
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    current['provider_id'] = provider_id
                    self.save(conn, current)
                if lifecycle != 'PENDING':
                    return lifecycle
            evidence = row.get('cancel_evidence', {})
            accepted = (evidence.get('accepted') is True and evidence.get('provider_id') == provider_id
                        and evidence.get('reference') == row['reference']
                        and evidence.get('account_binding') == row['account_binding'])
            if not accepted and row.get('cancel_retry_at', 0) <= time.time():
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    current.update(cancel_attempted_at=time.time(), cancel_retry_at=time.time() + 30)
                    self.save(conn, current)
                try:
                    result = await self.api.cancel(provider_id)
                    detail = dict(stage='cancel', code='ACCEPTED', http_status=200, checked_at=result['checked_at'],
                                  correlation_id=result['correlation_id'], endpoint=result['endpoint'], fingerprint=self.fingerprint())
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        current['cancel_evidence'] = dict(result, provider_id=provider_id, reference=row['reference'],
                                                          account_binding=row['account_binding'])
                        current['cancel_diagnostic'] = detail
                        self.put(conn, 'diagnostic.cancel', detail)
                        self.save(conn, current)
                except GatewayError as exc:
                    detail = self.diagnostic(exc, 'cancel')
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        current.update(cancel_diagnostic=detail,
                                       cancel_retry_at=time.time() + max(30, exc.retry_after))
                        self.save(conn, current)
            return await self.api.cancel_status(provider_id, row['reference'], bound=True)
        finally:
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current.get('cancel_lease_owner') == token:
                    current.update(cancel_lease_owner=None, cancel_lease_until=0, next_poll_at=time.time() + 15)
                    self.save(conn, current)

    async def refresh(self, ident, *, allow_cancel=True, prepare_image=True):
        row = self.transaction(ident)
        if row['state'] in FINAL | {'REVIEW'}:
            return row
        if row['state'] == 'PAID_VERIFIED':
            return await self.settle(ident)
        if row['state'] == 'REQUESTING':
            if row['lease_until'] > time.time():
                return row
            with self.connection(True) as conn:
                row = self.transaction(ident, conn=conn)
                if row['state'] == 'REQUESTING' and row['lease_until'] <= time.time():
                    row.update(state='CREATE_UNKNOWN', lease_owner=None, lease_until=0)
                    self.save(conn, row)
        try:
            profile = await self.ensure_profile()
            if profile['account_binding'] != row['account_binding'] or row['origin'] != self.config.base_url:
                raise GatewayError('ACCOUNT_CHANGED')
            if prepare_image and row['state'] == 'PENDING' and not self.has_qr(row) and row.get('qr_source_cipher'):
                await self.prepare_qr(ident)
            ident_provider = row['provider_id']
            if not ident_provider:
                history = await self.api.history(20, row.get('reconcile_offset', 0))
                found = [item for item in history if item.get('merchant_ref') == row['reference']]
                if len(found) > 1:
                    raise GatewayError('DUPLICATE_REFERENCE')
                if not found:
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        current['reconcile_offset'] = row.get('reconcile_offset', 0) + 20 if len(history) == 20 else 0
                        current['next_poll_at'] = time.time() + 15
                        self.save(conn, current)
                    return self.transaction(ident)  # No absence proof and no replacement POST.
                ident_provider = reference(found[0]['trx_id'])
            if row['cancel_requested']:
                if allow_cancel:
                    lifecycle = await self.reconcile_cancellation(ident, ident_provider)
                elif row['provider_id']:
                    lifecycle = await self.api.cancel_status(ident_provider, row['reference'], bound=True)
                else:
                    lifecycle = await self.api.cancel_status(ident_provider, row['reference'])
                if lifecycle == 'FAILED':
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        if current['state'] not in FINAL | {'REVIEW', 'PAID_VERIFIED'} and not self.paid_proof(current):
                            self.expire_native(conn, current)
                            current.update(state='CANCELLED', error='', cancel_confirmed_at=time.time(),
                                           qris_cipher=None, qr_image_cipher=None, qr_source_cipher=None)
                            current['cancel_confirmation'] = dict(status='FAILED', http_status=200, checked_at=time.time(),
                                correlation_id=secrets.token_hex(8), provider_id=ident_provider, reference=current['reference'])
                            self.put(conn, 'diagnostic.status', dict(stage='status', code='CONFIRMED_FAILED', http_status=200,
                                checked_at=time.time(), correlation_id=secrets.token_hex(8), fingerprint=self.fingerprint(), transaction_id=ident))
                            self.save(conn, current)
                    await self.retire_paid_messages(self.bot, ident)
                    return self.transaction(ident)
                if lifecycle != 'PAID':
                    return self.transaction(ident)  # Accepted/pending is NOT final cancellation.
            # PAID always follows the full amount/reference/account checks below.
            data = await self.api.status(ident_provider, row['reference'], row['amount'], row['total_amount'], row['fee'])
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['state'] in FINAL | {'REVIEW', 'PAID_VERIFIED'}:
                    return current
                current.update(provider_id=ident_provider, total_amount=data['total_amount'], fee=data['fee'],
                               next_poll_at=time.time() + 15,
                               error='IMAGE' if current['error'] == 'IMAGE' and not self.has_qr(current) else '')
                self.native_invoice(conn, current)
                if data['status'] == 'PAID':
                    table = 'orders' if current['purpose'] == 'order' else 'topups'
                    native = conn.execute('SELECT * FROM ' + table + ' WHERE id=?', (current['entity_id'],)).fetchone()
                    review = current['cancel_requested'] or not native or native['status'] in {'cancelled', 'rejected'}
                    current.update(state='REVIEW' if review else 'PAID_VERIFIED', verified_at=time.time(),
                                   verified_status='PAID', verified_total=data['total_amount'])
                    current['verification_mac'] = self.proof_mac(current)
                elif data['status'] == 'FAILED':
                    self.expire_native(conn, current)
                    current['state'] = 'CANCELLED' if current['cancel_requested'] else 'FAILED'
                    current.update(qris_cipher=None, qr_image_cipher=None, qr_source_cipher=None)
                    self.put(conn, 'diagnostic.status', dict(stage='status', code='CONFIRMED_FAILED', http_status=200,
                        checked_at=time.time(), correlation_id=secrets.token_hex(8), fingerprint=self.fingerprint(), transaction_id=ident))
                else:
                    current['state'] = 'CANCELLED_LOCAL' if current['cancel_requested'] else 'PENDING'
                    self.retain_qr_source(current, data)
                if data['status'] != 'PENDING':
                    current['error'] = ''
                self.save(conn, current)
                create = self.setting('create', {}, conn)
                if create.get('transaction_id') == ident and create.get('error') and not create.get('resolved_at'):
                    create.update(resolved_at=time.time(), resolution_http_status=200)
                    self.put(conn, 'create', create)
            if prepare_image and not self.has_qr(self.transaction(ident)):
                await self.prepare_qr(ident)
            if self.transaction(ident)['state'] == 'PAID_VERIFIED':
                return await self.settle(ident)
        except GatewayError as exc:
            detail = self.diagnostic(exc, 'status')
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['state'] not in FINAL:
                    current.update(error=exc.code, diagnostic=detail, next_poll_at=time.time() + max(15, exc.retry_after))
                    self.save(conn, current)
            raise
        return self.transaction(ident)

    def is_prior_session(self, row):
        return row['created_at'] < self.started_at

    async def prior_checkout(self, ident):
        """Reconcile a prior process invoice using GET only; never reset/erase it."""
        try:
            row = await self.refresh(ident, allow_cancel=False, prepare_image=False)
        except (GatewayError, sqlite3.Error):
            row = self.transaction(ident)
        return None if row['state'] in {'FAILED', 'CANCELLED'} else row

    async def show_prior_hold(self, call, ident):
        row = self.transaction(ident, call.from_user.id)
        if row['purpose'] == 'order':
            # Opening checkout is an explicit request for this invoice. A restart
            # alone still never resends an old QR to the buyer.
            self.requested_qr_ids.add(ident)
            if row['state'] == 'PENDING' and not row['cancel_requested'] and row['error'] in {'', 'IMAGE'}:
                return await self.show_payment(call, ident)
        text = ('<b>Pemeriksaan pembayaran sebelumnya</b>\n\n'
                'Belum ada invoice baru dibuat. ' +
                ('Pembayaran sebelumnya sudah berhasil diproses. Periksa riwayat pesanan.' if row['state'] in {'SETTLED', 'SETTLED_BALANCE'} else
                 'Hasil pembayaran sebelumnya masih perlu dipastikan agar tagihan tidak ganda.'))
        controls = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text='🔄 Periksa pembayaran sebelumnya', callback_data=PREFIX + 'u:check:' + ident)],
            [InlineKeyboardButton(text='🏠 Menu Awal', callback_data='home')]])
        if row['purpose'] == 'order':
            controls = self.user_keyboard(row)
            text += '\nBot melanjutkan pemeriksaan pembayaran secara otomatis.'
        return await self.host.safe_edit_or_answer(call, text, reply_markup=controls, parse_mode='HTML')

    def expire_native(self, conn, row):
        if row['purpose'] == 'topup':
            conn.execute("UPDATE topups SET status='expired',updated_at=? WHERE id=? AND payment_method=? AND status='pending'",
                         (datetime.now().isoformat(timespec='seconds'), row['entity_id'], METHOD))
        else:
            native = conn.execute('SELECT * FROM orders WHERE id=? AND payment_method=?', (row['entity_id'], METHOD)).fetchone()
            if native and native['payment_status'] != 'paid' and native['status'] not in {'cancelled', 'completed'}:
                self.host.release_order_reservation(conn, native)
                conn.execute("UPDATE orders SET status='expired',payment_status='expired',reserved_until='' WHERE id=?", (row['entity_id'],))

    async def settle(self, ident):
        token = secrets.token_hex(12)
        with self.connection(True) as conn:
            row = self.transaction(ident, conn=conn)
            if row['state'] != 'PAID_VERIFIED' or row['lease_until'] > time.time():
                return row
            if not self.payment_authorized(conn, row['purpose'], row['entity_id']):
                row.update(state='REVIEW', error='PAYMENT_PROOF_INVALID')
                self.save(conn, row)
                return row
            native = conn.execute('SELECT * FROM ' + ('orders' if row['purpose'] == 'order' else 'topups') + ' WHERE id=?',
                                  (row['entity_id'],)).fetchone()
            if native['status'] in {'cancelled', 'rejected'} or row['cancel_requested']:
                row.update(state='REVIEW', error='PAYMENT_AFTER_CANCEL')
                self.save(conn, row)
                return row
            row.update(lease_owner=token, lease_until=time.time() + 180)
            self.save(conn, row)
        try:
            if row['purpose'] == 'topup':
                result, reason = self.host.verify_topup_atomic(row['entity_id'], 0)
                success = result is not None and reason in {'completed', 'already_completed'}
            else:
                if self.bot is None:
                    raise GatewayError('NOT_READY')
                await self.host.mark_order_paid(row['entity_id'], self.bot, row['total_amount'])
                with self.connection() as conn:
                    native = conn.execute('SELECT payment_status FROM orders WHERE id=?', (row['entity_id'],)).fetchone()
                    success = bool(native and native['payment_status'] == 'paid')
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['lease_owner'] == token and success:
                    current.update(state='SETTLED', error='', lease_owner=None, lease_until=0)
                    self.save(conn, current)
            if success:
                self.host.payment_receipts.queue(self.host, row['purpose'], row['entity_id'])
                await self.retire_paid_messages(self.bot, ident)
        finally:
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['lease_owner'] == token:
                    current.update(lease_owner=None, lease_until=0)
                    self.save(conn, current)
        return self.transaction(ident)

    async def fulfill_once(self, order_id, bot, implementation):
        row = self.linked('order', order_id)
        if not row:
            return await implementation(order_id, bot)
        lock = self.delivery_locks.setdefault(order_id, asyncio.Lock())
        async with lock:
            token = secrets.token_hex(12)
            with self.connection(True) as conn:
                current = self.transaction(row['id'], conn=conn)
                if current['delivery_until'] > time.time():
                    return False
                current.update(delivery_owner=token, delivery_until=time.time() + 300)
                self.save(conn, current)
            try:
                return await implementation(order_id, bot)
            finally:
                with self.connection(True) as conn:
                    current = self.transaction(row['id'], conn=conn)
                    if current['delivery_owner'] == token:
                        current.update(delivery_owner=None, delivery_until=0)
                        self.save(conn, current)
                if not getattr(lock, '_waiters', None):
                    self.delivery_locks.pop(order_id, None)

    async def buyer_guard(self, call):
        if (not call.message or str(call.message.chat.type) != 'private'
                or call.message.chat.id != call.from_user.id or self.host.security_blocked(call.from_user.id)):
            raise GatewayError('FORBIDDEN')
        if not self.host.is_owner(call.from_user.id) and (self.host.safe_mode_enabled() or self.host.maintenance_enabled()):
            raise GatewayError('NOT_READY')
        if not await self.host.is_channel_member(call.bot, call.from_user.id):
            raise GatewayError('FORBIDDEN')
        if not self.can_attempt():
            raise GatewayError('NOT_READY')
        ok, _ = self.host.persistent_rate_limit(call.from_user.id, 'autoqris_create', limit=5, window_seconds=60)
        if not ok:
            raise GatewayError('RATE_LIMIT')
        self.bot = call.bot
        await self.host.safe_callback_notice(call)
        await self.ensure_profile()  # Automatic auth after acknowledging the click, before invoice creation.

    async def checkout(self, call, bot, state, variant_id, qty):
        await self.buyer_guard(call)
        qty = money(qty, positive=True)
        data = await state.get_data()
        note = self.host.get_checkout_note_from_state(data)
        prior = self.resumable('order', call.from_user.id, variant=variant_id, qty=qty)
        if prior and self.is_prior_session(prior):
            prior = await self.prior_checkout(prior['id'])
            if prior:
                return await self.show_prior_hold(call, prior['id'])
        with self.connection() as conn:
            product = conn.execute('SELECT p.* FROM products p JOIN product_variants v ON v.product_id=p.id WHERE v.id=?',
                                   (variant_id,)).fetchone()
        if self.host.product_is_famhead(product) and (
                int(data.get('checkout_variant_id', 0) or 0) != variant_id
                or not self.host.valid_family_gmail(data.get('family_gmail', ''))):
            return await self.host.require_family_checkout_gmail(call, state, product, variant_id, qty, data)
        async with self.host.purchase_lock(call.from_user.id):
            if not self.resumable('order', call.from_user.id, variant=variant_id, qty=qty):
                allowed, _ = self.host.anti_abuse_checkout(call.from_user.id, METHOD)
                if not allowed:
                    raise GatewayError('LIMIT')
            with self.connection(True) as conn:
                row = self.resumable('order', call.from_user.id, variant=variant_id, qty=qty, conn=conn)
                if row is None:
                    variant = conn.execute('SELECT * FROM product_variants WHERE id=?', (variant_id,)).fetchone()
                    product = conn.execute('SELECT * FROM products WHERE id=?', (variant['product_id'],)).fetchone() if variant else None
                    if (not variant or not product or not variant['active'] or not self.host.product_is_available(product)
                            or self.host.available_stock(variant) < qty):
                        raise GatewayError('STOCK')
                    if self.host.variant_is_sharing(variant) and qty != 1:
                        raise GatewayError('INPUT')
                    if self.host.product_is_famhead(product) and (
                            int(data.get('checkout_variant_id', 0) or 0) != variant_id
                            or not self.host.valid_family_gmail(data.get('family_gmail', ''))):
                        raise GatewayError('FAMILY_GMAIL')
                    unit = self.host.effective_unit_price(variant, qty)
                    subtotal = unit * qty
                    voucher, discount = self.host.checkout_discount_from_state(
                        data, call.from_user.id, product['id'], variant_id, subtotal, conn=conn)
                    if subtotal - discount <= 0:
                        raise self.host.VoucherCheckoutError('Voucher menutup seluruh tagihan. Selesaikan dengan saldo bot.', wallet_only=True)
                    amount = money(subtotal - discount, positive=True)
                    if amount < 500:
                        raise GatewayError('MIN_AMOUNT')
                    if not self.host.reserve_stock_for_order(conn, variant_id, qty):
                        raise GatewayError('STOCK')
                    entity = conn.execute("""INSERT INTO orders(user_id,username,product_id,variant_id,qty,unit_price,total,
                        status,payment_method,payment_status,note,unique_code,payment_total,stock_reserved,reserved_until,
                        created_at,voucher_code,discount_amount) VALUES(?,?,?,?,?,?,?,'pending',?,'unpaid',?,0,?,1,'',?,?,?)""",
                        (call.from_user.id, call.from_user.username or '', product['id'], variant_id, qty, unit, subtotal,
                         METHOD, note, amount, datetime.now().isoformat(timespec='seconds'), voucher, discount)).lastrowid
                    row = self.reserve(conn, 'order', entity, call.from_user.id, amount)
            if row['state'] == 'NEW':
                await self.host.safe_edit_or_answer(call, self.status_text(row),
                    reply_markup=self.user_keyboard(row), parse_mode='HTML')
                await self.issue(row['id'])
            elif row['cancel_requested']:
                await state.clear()
                return await self.show_existing_cancellation(call, row['id'])
            else:
                try:
                    await self.refresh(row['id'])
                except GatewayError:
                    pass
            await state.clear()
            await self.show_payment(call, row['id'])

    async def topup(self, call, amount, state=None):
        await self.buyer_guard(call)
        amount = money(amount, positive=True)
        if amount < max(500, self.host.get_min_topup()):
            raise GatewayError('MIN_AMOUNT')
        prior = self.resumable('topup', call.from_user.id, amount=amount)
        if prior and self.is_prior_session(prior):
            prior = await self.prior_checkout(prior['id'])
            if prior:
                return await self.show_prior_hold(call, prior['id'])
        async with self.host.purchase_lock(call.from_user.id):
            with self.connection(True) as conn:
                row = self.resumable('topup', call.from_user.id, amount=amount, conn=conn)
                if row is None:
                    stamp = datetime.now().isoformat(timespec='seconds')
                    entity = conn.execute("""INSERT INTO topups(user_id,username,amount,unique_code,payment_total,
                        payment_method,status,created_at,updated_at,expires_at) VALUES(?,?,?,0,?,?,'pending',?,?,'')""",
                        (call.from_user.id, call.from_user.username or '', amount, amount, METHOD, stamp, stamp)).lastrowid
                    row = self.reserve(conn, 'topup', entity, call.from_user.id, amount)
            if row['state'] == 'NEW':
                await self.issue(row['id'])
            elif row['cancel_requested']:
                if state is not None:
                    await state.clear()
                return await self.show_existing_cancellation(call, row['id'])
            else:
                try:
                    await self.refresh(row['id'])
                except GatewayError:
                    pass
            if state is not None:
                await state.clear()
            await self.show_payment(call, row['id'])

    def user_keyboard(self, row):
        rows = []
        if row['purpose'] != 'order':
            rows.append([InlineKeyboardButton(text='🔄 Periksa Pembatalan' if row['cancel_requested'] else '🔄 Cek Status',
                                             callback_data=PREFIX + 'u:check:' + row['id'])])
        if row['state'] not in FINAL | {'REVIEW', 'PAID_VERIFIED'} and not row['cancel_requested']:
            rows.append([InlineKeyboardButton(text='❌ Batalkan', callback_data=PREFIX + 'u:cancel:' + row['id'])])
        rows.append([InlineKeyboardButton(text='🏠 Menu Awal', callback_data='home')])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def status_text(self, row):
        invoice = self.host.invoice(row['entity_id']) if row['purpose'] == 'order' else self.host.topup_invoice(row['entity_id'])
        states = dict(NEW='Menyiapkan pembayaran', REQUESTING='Menyiapkan pembayaran', CREATE_UNKNOWN='Menunggu kepastian invoice',
                      PENDING='Menunggu pembayaran', PAID_VERIFIED='Pembayaran diterima; sedang diproses', SETTLED='Pembayaran berhasil',
                      SETTLED_BALANCE='Pembayaran masuk ke saldo', CANCELLED_LOCAL='Pembatalan diajukan; menunggu konfirmasi Payinaja',
                      CANCELLED='Dibatalkan', FAILED='Pembayaran gagal / kedaluwarsa', REVIEW='Perlu pemeriksaan owner')
        text = LABEL + '\n<b>MABOYY DIGITAL</b>\n\n🧾 ' + html.escape(invoice) + '\n'
        text += ('💰 Nominal saldo: ' if row['purpose'] == 'topup' else '💵 Harga pesanan: ') + self.host.rupiah(row['amount']) + '\n'
        if row['total_amount'] is not None:
            adjustment = row['total_amount'] - row['amount']
            if adjustment:
                text += 'Biaya/penyesuaian QRIS: ' + self.host.rupiah(adjustment) + '\n'
            text += '<b>Total pembayaran: ' + self.host.rupiah(row['total_amount']) + '</b>\n'
        text += '📌 Status: ' + states.get(row['state'], 'Sedang diperiksa') + '\n'
        if row['error'] == 'ACCOUNT_CHANGED':
            text += 'Akun provider berbeda dari akun invoice ini. Owner perlu memeriksa akun asal; jangan bayar QR lama.\n'
        elif row['state'] == 'PENDING' and row['expires_at'] <= time.time():
            text += 'Waktu QRIS telah lewat. Jangan bayar QRIS ini; status tetap diperiksa.\n'
        elif row['state'] in {'REQUESTING', 'CREATE_UNKNOWN', 'CANCELLED_LOCAL'}:
            text += 'Jangan membuat tagihan pengganti sebelum hasil invoice ini dipastikan.\n'
            audit = row.get('cancel_audit')
            if row['cancel_requested'] and audit:
                text += 'Permintaan pembatalan tercatat: ' + self.host.payment_receipts.format_wib(audit['created_at'], compact=True) + '\n'
        elif row['state'] == 'PENDING' and not self.has_qr(row):
            text += ('Invoice tersedia. Bot sedang menyiapkan dan mengirim gambar QR secara otomatis.\n' if row['purpose'] == 'order' else
                     'Invoice tersedia, tetapi gambar QR belum siap ditampilkan. Cek Status atau hubungi owner; jangan membuat tagihan pengganti.\n')
        return text

    def native_status(self, purpose, entity):
        row = self.linked(purpose, entity)
        if not row:
            raise GatewayError('NOT_FOUND')
        return self.status_text(row), self.user_keyboard(row)

    async def show_existing_cancellation(self, call, ident):
        row = self.transaction(ident, call.from_user.id)
        return await self.host.safe_edit_or_answer(call,
            '<b>Invoice sebelumnya masih menunggu penyelesaian pembatalan.</b>\n'
            'Checkout ini tidak membuat atau membatalkan invoice baru.\n\n' + self.status_text(row),
            reply_markup=self.user_keyboard(row), parse_mode='HTML')

    async def prompt_cancel(self, call, ident):
        if not call.message or str(call.message.chat.type) != 'private' or call.message.chat.id != call.from_user.id:
            raise GatewayError('FORBIDDEN')
        with self.connection(True) as conn:
            row = self.transaction(ident, call.from_user.id, conn=conn)
            if row['state'] not in FINAL | {'PAID_VERIFIED', 'REVIEW'} and not row['cancel_requested']:
                nonce = secrets.token_hex(8)
                row['cancel_prompt'] = dict(nonce=nonce, actor=call.from_user.id, expires_at=time.time() + 180)
                self.save(conn, row)
            else:
                nonce = None
        if nonce is None:
            # v17.41 used the cancel callback for "Periksa Pembatalan".
            # Preserve that read/reconcile action without creating a new intent.
            return await self.show_status(call, ident, refresh=bool(row['cancel_requested']))
        controls = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text='✅ Ya, ajukan pembatalan', callback_data=PREFIX + 'u:confirm:' + ident + '.' + nonce)],
            [InlineKeyboardButton(text='⬅️ Tetap lanjutkan pembayaran', callback_data=PREFIX + 'u:keep:' + ident)]])
        return await self.host.safe_edit_or_answer(call,
            self.status_text(row) + '\n<b>Ajukan pembatalan invoice ini?</b>\n'
            'Pembatalan belum diajukan. Pilih konfirmasi hanya jika ingin menutup pembayaran ini.',
            reply_markup=controls, parse_mode='HTML')

    async def keep_payment(self, call, ident):
        with self.connection(True) as conn:
            row = self.transaction(ident, call.from_user.id, conn=conn)
            row.pop('cancel_prompt', None)
            self.save(conn, row)
        return await self.show_payment(call, ident)

    def remember_payment_message(self, ident, user, message_id):
        if type(message_id) is not int or not 0 < message_id <= 9223372036854775807:
            raise GatewayError('INPUT')
        with self.connection(True) as conn:
            row = self.transaction(ident, user, conn=conn)
            if not any(item['id'] == message_id for item in row['qr_messages']):
                row['qr_messages'].append(dict(id=message_id, kind='QR', attempts=0, retry_at=0))
            if row['state'] in {'SETTLED', 'SETTLED_BALANCE'}:
                row.update(retention_done=False, cleanup_at=0)
            self.save(conn, row)

    async def show_payment(self, call, ident, *, automatic=False):
        row = self.transaction(ident, call.from_user.id)
        self.bot = call.bot
        if not automatic and row['purpose'] == 'order':
            self.requested_qr_ids.add(ident)
        if automatic and (not self.can_auto_deliver(row) or row['qr_messages'] or row.get('qr_send_retry_at', 0) > time.time()):
            return
        if row['state'] == 'PENDING' and not row['cancel_requested'] and not self.proof().get('approved'):
            try:
                await self.ensure_profile()
            except GatewayError:
                return None if automatic else await self.show_status(call, ident, refresh=False)
        if (row['state'] != 'PENDING' or row['cancel_requested']
                or row['error'] in QR_BLOCKING_ERRORS
                or row['origin'] != self.config.base_url
                or self.proof().get('account_binding') != row['account_binding'] or not self.proof().get('approved')
                or row['expires_at'] <= time.time()):
            return None if automatic else await self.show_status(call, ident, refresh=False)
        if not self.has_qr(row):
            if row['error'] == 'IMAGE' and row.get('diagnostic', {}).get('code') == 'SQLITE':
                return None if automatic else await self.show_status(call, ident, refresh=False)
            await self.prepare_qr(ident)
            row = self.transaction(ident, call.from_user.id)
            if (row['state'] != 'PENDING' or row['cancel_requested'] or not self.has_qr(row)
                    or row['error'] in QR_BLOCKING_ERRORS
                    or row['expires_at'] <= time.time() or not self.proof().get('approved')
                    or self.proof().get('account_binding') != row['account_binding']):
                return None if automatic else await self.show_status(call, ident, refresh=False)
        with self.connection() as conn:
            native = conn.execute('SELECT * FROM ' + ('orders' if row['purpose'] == 'order' else 'topups') + ' WHERE id=?',
                                  (row['entity_id'],)).fetchone()
        if not native or native['user_id'] != row['user_id'] or native['payment_method'] != METHOD:
            raise GatewayError('MISMATCH')
        paid = native['payment_status'] == 'paid' if row['purpose'] == 'order' else native['status'] in {'paid', 'completed'}
        if paid or native['status'] in {'cancelled', 'expired', 'completed', 'rejected'}:
            if automatic:
                return
            return await self.host.safe_edit_or_answer(call,
                self.status_text(row) + '\nPesanan sudah ditutup atau diproses di bot. QR tidak ditampilkan; status provider perlu diperiksa owner.',
                reply_markup=self.user_keyboard(row), parse_mode='HTML')
        try:
            raw = (render_qris(self.crypt(row['qris_cipher'], ident, decrypt=True), row['total_amount']) if row.get('qris_cipher') else
                   self.api.image_valid(base64.b64decode(self.crypt(row['qr_image_cipher'], ident, decrypt=True), validate=True)))
        except (GatewayError, ValueError, TypeError) as exc:
            self.diagnostic(exc if isinstance(exc, GatewayError) else GatewayError('IMAGE'), 'image')
            if automatic:
                return
            return await self.host.safe_edit_or_answer(call, self.status_text(row) + '\nGambar QR belum dapat dibuka; tidak ada invoice baru dibuat.',
                       reply_markup=self.user_keyboard(row), parse_mode='HTML')
        # Manual clicks and the recovery worker share one durable send lease.
        # This lease concerns Telegram only; it never authorizes a payment/create.
        token = secrets.token_hex(12)
        with self.connection(True) as conn:
            current = self.transaction(ident, row['user_id'], conn=conn)
            if (current['state'] != 'PENDING' or current['cancel_requested'] or current.get('retention_done')
                    or current['error'] in QR_BLOCKING_ERRORS or current['expires_at'] <= time.time()
                    or current['origin'] != self.config.base_url
                    or self.proof(conn).get('account_binding') != current['account_binding'] or not self.proof(conn).get('approved')
                    or current.get('qris_cipher') != row.get('qris_cipher')
                    or current.get('qr_image_cipher') != row.get('qr_image_cipher')
                    or current.get('qr_send_until', 0) > time.time()
                    or (automatic and (not self.can_auto_deliver(current) or current['qr_messages']
                                       or current.get('qr_send_retry_at', 0) > time.time()))):
                return
            native = conn.execute('SELECT * FROM ' + ('orders' if current['purpose'] == 'order' else 'topups') + ' WHERE id=?',
                                  (current['entity_id'],)).fetchone()
            if (not native or native['user_id'] != current['user_id'] or native['payment_method'] != METHOD
                    or native['status'] in {'cancelled', 'expired', 'completed', 'rejected'}
                    or (native['payment_status'] == 'paid' if current['purpose'] == 'order' else native['status'] == 'paid')):
                return
            current.update(qr_send_owner=token, qr_send_until=time.time() + self.config.timeout + 45)
            self.save(conn, current)
        try:
            try:
                message = await asyncio.wait_for(call.bot.send_photo(call.from_user.id, BufferedInputFile(raw, filename='qris.png'),
                    caption=self.status_text(row), reply_markup=self.user_keyboard(row), parse_mode='HTML'), timeout=self.config.timeout + 15)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                delay = max(30, min(3600, float(getattr(exc, 'retry_after', 0) or 0)))
                status = 429 if isinstance(exc, TelegramRetryAfter) else 403 if isinstance(exc, TelegramForbiddenError) else 400 if isinstance(exc, TelegramBadRequest) else 0
                self.diagnostic(GatewayError('TELEGRAM', http_status=status), 'telegram')
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    current['qr_send_retry_at'] = time.time() + delay
                    self.save(conn, current)
                if automatic:
                    return
                note = ('\nGambar belum terkirim; bot akan mencoba pengiriman kembali secara otomatis.' if row['purpose'] == 'order' else
                        '\nGambar belum terkirim; pengiriman akan dicoba kembali. Cek Status tidak membuat invoice baru.')
                return await self.host.safe_edit_or_answer(call, self.status_text(row) + note,
                           reply_markup=self.user_keyboard(row), parse_mode='HTML')
            self.remember_payment_message(ident, row['user_id'], message.message_id)
            if row['purpose'] == 'topup':
                self.host.save_topup_payment_message(row['entity_id'], row['user_id'], message.message_id)
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                current['qr_send_retry_at'] = 0
                self.save(conn, current)
                self.put(conn, 'diagnostic.telegram', dict(stage='telegram', code='OK', http_status=200,
                    checked_at=time.time(), correlation_id=secrets.token_hex(8), fingerprint=self.fingerprint()))
        finally:
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current.get('qr_send_owner') == token:
                    current.update(qr_send_owner=None, qr_send_until=0)
                    self.save(conn, current)
        await self.retire_paid_messages(call.bot, ident)
        if automatic:
            return
        try:
            await call.message.delete()
        except Exception:
            pass

    def can_auto_deliver(self, row):
        return not self.is_prior_session(row) or (row['purpose'] == 'order' and row['id'] in self.requested_qr_ids)

    async def deliver_pending_qr(self, ident):
        """Send a recovered current-process invoice; old invoices stay opt-in."""
        if self.bot is None:
            return
        row = self.transaction(ident)
        if (row['state'] != 'PENDING' or not self.can_auto_deliver(row) or row['qr_messages']
                or row['cancel_requested'] or not self.has_qr(row)):
            return
        call = SimpleNamespace(from_user=SimpleNamespace(id=row['user_id']), bot=self.bot)
        await self.show_payment(call, ident, automatic=True)

    async def show_status(self, call, ident, *, refresh=True, admin=False):
        row = self.transaction(ident, call.from_user.id, admin=admin)
        self.bot = call.bot
        if refresh:
            try:
                row = await self.refresh(ident)
            except GatewayError:
                row = self.transaction(ident, call.from_user.id, admin=admin)
        if admin:
            return await self.owner_detail(call, ident)
        if row['state'] == 'SETTLED':
            with self.connection() as conn:
                receipt = conn.execute('SELECT status FROM payment_receipts WHERE source=? AND entity_id=?',
                                      (row['purpose'], str(row['entity_id']))).fetchone()
            if receipt and receipt[0] in {'ARCHIVED', 'ARCHIVING'}:
                return await self.host.safe_edit_or_answer(call, self.status_text(row) + '\nInvoice sudah melewati masa simpan 1 jam; riwayat pembayaran tetap tersedia.',
                    reply_markup=self.user_keyboard(row), parse_mode='HTML')
            await self.host.payment_receipts.notify(self.host, call.bot, row['purpose'], row['entity_id'])
            await self.retire_paid_messages(call.bot, ident)
            return
        if refresh and row['state'] == 'PENDING' and self.has_qr(row) and row['expires_at'] > time.time():
            return await self.show_payment(call, ident)
        await self.host.safe_edit_or_answer(call, self.status_text(row), reply_markup=self.user_keyboard(row), parse_mode='HTML')

    async def cancel(self, call, ident, *, admin=False, nonce=None):
        if not call.message or str(call.message.chat.type) != 'private' or call.message.chat.id != call.from_user.id:
            raise GatewayError('FORBIDDEN')
        with self.connection(True) as conn:
            row = self.transaction(ident, call.from_user.id, conn=conn, admin=admin)
            if nonce is not None:
                prompt = row.get('cancel_prompt', {})
                if (not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{16}', nonce) or prompt.get('actor') != call.from_user.id
                        or prompt.get('expires_at', 0) < time.time()
                        or not hmac.compare_digest(str(prompt.get('nonce', '')), nonce)):
                    raise GatewayError('CONFIRM_EXPIRED')
            if row['state'] not in FINAL | {'PAID_VERIFIED', 'REVIEW'} and not self.paid_proof(row):
                table = 'orders' if row['purpose'] == 'order' else 'topups'
                native = conn.execute('SELECT * FROM ' + table + ' WHERE id=?', (row['entity_id'],)).fetchone()
                if not native or native['user_id'] != row['user_id'] or native['payment_method'] != METHOD:
                    raise GatewayError('MISMATCH')
                paid = native['payment_status'] == 'paid' if row['purpose'] == 'order' else native['status'] in {'paid', 'completed'}
                if paid:
                    raise GatewayError('BUSY')
                if row['purpose'] == 'order':
                    if native['status'] == 'completed':
                        raise GatewayError('BUSY')
                    self.host.release_order_reservation(conn, native)
                    conn.execute("UPDATE orders SET status='cancelled',payment_status='cancelled',reserved_until='' WHERE id=?", (row['entity_id'],))
                else:
                    conn.execute("UPDATE topups SET status='cancelled',updated_at=? WHERE id=?",
                                 (datetime.now().isoformat(timespec='seconds'), row['entity_id']))
                if not row['cancel_requested']:
                    row['cancel_audit'] = dict(actor=call.from_user.id, created_at=time.time(),
                        source='owner_confirmed' if admin else 'buyer_confirmed' if nonce is not None else 'internal_confirmed')
                row.pop('cancel_prompt', None)
                row.update(cancel_requested=True,
                           state='CANCELLED' if not row['request_started_at'] and not row['provider_id'] else 'CANCELLED_LOCAL',
                           next_poll_at=0)
                self.save(conn, row)
        if row['state'] == 'CANCELLED_LOCAL':
            try:
                await self.refresh(ident)
            except GatewayError:
                pass
        current = self.transaction(ident)
        if admin:
            await self.retire_paid_messages(call.bot, ident)
            return await self.owner_detail(call, ident)
        if current['state'] in {'SETTLED', 'PAID_VERIFIED', 'REVIEW'}:
            return await self.show_status(call, ident, refresh=False)
        await self.host.render_cancelled_payment_message(call, self.status_text(current), self.user_keyboard(current))
        await self.retire_paid_messages(call.bot, ident)

    def receipt_transaction(self, source, entity):
        return self.linked(source, int(entity)) if source in {'order', 'topup'} else None

    def receipt_payment_confirmed(self, row):
        with self.connection() as conn:
            if not self.payment_authorized(conn, row['purpose'], row['entity_id'], settled=True):
                return False
            native = conn.execute('SELECT * FROM ' + ('orders' if row['purpose'] == 'order' else 'topups') + ' WHERE id=?',
                                  (row['entity_id'],)).fetchone()
            return native['payment_status'] == 'paid' if row['purpose'] == 'order' else native['status'] == 'completed'

    def protected_receipt_message(self, user, message_id):
        with self.connection() as conn:
            found = conn.execute("""SELECT source,entity_id FROM payment_receipts WHERE user_id=? AND message_id=?
                AND (status='SENT' OR error_code='QRIS_EDIT')""", (user, message_id)).fetchall()
            return any(self.linked(item['source'], int(item['entity_id']), conn)
                       for item in found if item['source'] in {'order', 'topup'})

    async def deliver_receipt_photo(self, bot, receipt, photo, caption):
        row = self.receipt_transaction(receipt['source'], receipt['entity_id'])
        if not row or not self.receipt_payment_confirmed(row):
            raise GatewayError('NOT_READY')
        anchor = receipt['message_id'] if receipt['error_code'] == 'QRIS_EDIT' else None
        if not anchor:
            messages = [item for item in row['qr_messages'] if item['kind'] == 'QR']
            anchor = messages[-1]['id'] if messages else None
        if anchor:
            with self.connection(True) as conn:
                conn.execute("""UPDATE payment_receipts SET message_id=?,error_code='QRIS_EDIT'
                    WHERE source=? AND entity_id=? AND lease_token=?""",
                    (anchor, receipt['source'], receipt['entity_id'], receipt['lease_token']))
            try:
                await bot.edit_message_media(chat_id=row['user_id'], message_id=anchor,
                    media=InputMediaPhoto(media=photo, caption=caption, parse_mode='HTML'),
                    reply_markup=InlineKeyboardMarkup(inline_keyboard=[]))
            except TelegramBadRequest as exc:
                text = str(exc).lower()
                if 'message is not modified' in text:
                    pass
                elif 'message to edit not found' in text or "message can't be edited" in text:
                    with self.connection(True) as conn:
                        current = self.transaction(row['id'], conn=conn)
                        for item in current['qr_messages']:
                            if item['id'] == anchor:
                                item['kind'] = 'REMOVED'
                        self.save(conn, current)
                    anchor = None
                else:
                    raise
            if anchor:
                with self.connection(True) as conn:
                    current = self.transaction(row['id'], conn=conn)
                    for item in current['qr_messages']:
                        if item['id'] == anchor:
                            item['kind'] = 'INVOICE'
                    self.save(conn, current)
                return SimpleNamespace(message_id=anchor)
        with self.connection(True) as conn:
            changed = conn.execute("""UPDATE payment_receipts SET status='UNKNOWN',message_id=NULL,error_code='QRIS_SEND_STARTED'
                WHERE source=? AND entity_id=? AND lease_token=?""",
                (receipt['source'], receipt['entity_id'], receipt['lease_token'])).rowcount
            if changed != 1:
                raise GatewayError('STORAGE')
        try:
            return await bot.send_photo(row['user_id'], photo, caption=caption, parse_mode='HTML')
        except (TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter):
            with self.connection(True) as conn:
                conn.execute("UPDATE payment_receipts SET status='SENDING' WHERE source=? AND entity_id=? AND lease_token=?",
                             (receipt['source'], receipt['entity_id'], receipt['lease_token']))
            raise

    async def retire_paid_messages(self, bot, ident):
        if bot is None or self.setting('telegram_delete_retry', 0) > time.time():
            return
        row = self.transaction(ident)
        if row['state'] not in FINAL | {'REVIEW', 'PAID_VERIFIED'} and not row['cancel_requested']:
            return
        with self.connection() as conn:
            receipt = conn.execute('SELECT * FROM payment_receipts WHERE source=? AND entity_id=?',
                                  (row['purpose'], str(row['entity_id']))).fetchone()
        if (self.paid_proof(row) and not row['cancel_requested'] and row['state'] != 'REVIEW'
                and (not receipt or receipt['status'] not in {'SENT', 'UNKNOWN', 'ARCHIVING', 'ARCHIVED', 'LEGACY'})):
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                for item in current['qr_messages']:
                    if item['kind'] == 'QR':
                        item['retry_at'] = max(item['retry_at'], time.time() + 30)
                self.save(conn, current)
            return
        due = [item for item in row['qr_messages'] if item['kind'] == 'QR' and item['retry_at'] <= time.time()]
        for message in due[:20]:
            if message['kind'] != 'QR' or message['retry_at'] > time.time():
                continue
            if receipt and receipt['message_id'] == message['id']:
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    for item in current['qr_messages']:
                        if item['id'] == message['id']:
                            item['kind'] = 'INVOICE'
                    self.save(conn, current)
                continue
            deleted = False
            delay = 30
            throttled = False
            try:
                await asyncio.wait_for(bot.delete_message(chat_id=row['user_id'], message_id=message['id']), timeout=10)
                deleted = True
            except TelegramBadRequest as exc:
                deleted = 'message to delete not found' in str(exc).lower()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                delay = max(30, float(getattr(exc, 'retry_after', 0) or 0))
                throttled = isinstance(exc, TelegramRetryAfter)
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                for item in current['qr_messages']:
                    if item['id'] == message['id']:
                        item.update(kind='REMOVED' if deleted else 'QR', retry_at=time.time() + delay,
                                    attempts=item['attempts'] + 1)
                    elif throttled and item['kind'] == 'QR':
                        item['retry_at'] = max(item['retry_at'], time.time() + delay)
                if throttled:
                    self.put(conn, 'telegram_delete_retry', time.time() + delay)
                self.save(conn, current)
            if throttled:
                break  # Respect Telegram's retry delay instead of issuing more deletes.

    def due_ids(self, prefix, *, now=None, limit=10):
        now = time.time() if now is None else now
        with self.connection() as conn:
            return [item[0].rsplit('.', 1)[1] for item in conn.execute(
                "SELECT key FROM settings WHERE key GLOB ? AND value<=? ORDER BY value LIMIT ?",
                ('payinaja.' + prefix + '.*', f'{now:020.3f}', limit))]

    async def cleanup_success_receipts(self, bot, *, now=None):
        if bot is None:
            return
        now = time.time() if now is None else now
        if self.setting('telegram_delete_retry', 0) > now:
            return
        for ident in self.due_ids('messages', now=now):
            await self.retire_paid_messages(bot, ident)
        for ident in self.due_ids('retention', now=now):
            if self.setting('telegram_delete_retry', 0) > now:
                break
            row = self.transaction(ident)
            if not self.paid_proof(row):
                continue
            if row['state'] == 'SETTLED_BALANCE':
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    if now >= current.get('credited_at', now) + 3600:
                        current.update(qris_cipher=None, qr_image_cipher=None, qr_source_cipher=None, retention_done=True)
                    else:
                        current['cleanup_at'] = current['credited_at'] + 3600
                    self.save(conn, current)
                continue
            if not self.receipt_payment_confirmed(row):
                continue
            token = secrets.token_hex(12)
            with self.connection(True) as conn:
                receipt = conn.execute('SELECT * FROM payment_receipts WHERE source=? AND entity_id=?',
                                      (row['purpose'], str(row['entity_id']))).fetchone()
                current = self.transaction(ident, conn=conn)
                if (not receipt or receipt['status'] not in {'SENT', 'ARCHIVING', 'ARCHIVED'}
                        or not receipt['sent_at'] or receipt['sent_at'] > now - 3600
                        or receipt['lease_until'] > now or receipt['next_retry_at'] > now):
                    due = (receipt['sent_at'] or now) + 3600 if receipt else 0
                    current['cleanup_at'] = due if due > now else now + 30
                    if receipt:
                        current['cleanup_at'] = max(current['cleanup_at'], receipt['lease_until'], receipt['next_retry_at'])
                    if receipt and receipt['status'] == 'UNKNOWN' and now >= current['verified_at'] + 3600:
                        current.update(qris_cipher=None, qr_image_cipher=None, qr_source_cipher=None, retention_done=True)
                    self.save(conn, current)
                    continue
                changed = conn.execute("""UPDATE payment_receipts SET status='ARCHIVING',lease_token=?,lease_until=?,
                    snapshot_json='{}',caption_hash='',error_code='QRIS_RETENTION'
                    WHERE source=? AND entity_id=? AND lease_until<=? AND status IN ('SENT','ARCHIVING','ARCHIVED')""",
                    (token, now + 120, row['purpose'], str(row['entity_id']), now)).rowcount
                if changed != 1:
                    continue
                current['qris_cipher'] = None
                current['qr_image_cipher'] = None
                current['qr_source_cipher'] = None
                if receipt['message_id'] and not any(item['id'] == receipt['message_id'] for item in current['qr_messages']):
                    current['qr_messages'].append(dict(id=receipt['message_id'], kind='INVOICE', attempts=0, retry_at=0))
                self.save(conn, current)
                messages = [dict(item) for item in current['qr_messages'] if item['kind'] in {'QR', 'INVOICE'}]
            try:
                for item in messages[:20]:
                    if item['retry_at'] > now:
                        continue
                    deleted, delay = False, 30
                    throttled = False
                    try:
                        await asyncio.wait_for(bot.delete_message(chat_id=row['user_id'], message_id=item['id']), timeout=10)
                        deleted = True
                    except TelegramBadRequest as exc:
                        deleted = 'message to delete not found' in str(exc).lower()
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        delay = max(30, float(getattr(exc, 'retry_after', 0) or 0))
                        throttled = isinstance(exc, TelegramRetryAfter)
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        for message in current['qr_messages']:
                            if message['id'] == item['id']:
                                message.update(kind='REMOVED' if deleted else message['kind'], attempts=message['attempts'] + 1,
                                               retry_at=0 if deleted else now + delay)
                            elif throttled and message['kind'] in {'QR', 'INVOICE'}:
                                message['retry_at'] = max(message['retry_at'], now + delay)
                        if throttled:
                            self.put(conn, 'telegram_delete_retry', now + delay)
                        self.save(conn, current)
                    if throttled:
                        break
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    pending = [item for item in current['qr_messages'] if item['kind'] in {'QR', 'INVOICE'}]
                    if not pending:
                        current.update(retention_done=True, qr_messages=[], qris_cipher=None, qr_image_cipher=None, qr_source_cipher=None)
                        conn.execute("""UPDATE payment_receipts SET status='ARCHIVED',message_id=NULL,
                            lease_token=NULL,lease_until=0,next_retry_at=0 WHERE source=? AND entity_id=? AND lease_token=?""",
                            (row['purpose'], str(row['entity_id']), token))
                    else:
                        current['cleanup_at'] = min(item['retry_at'] for item in pending)
                        conn.execute("""UPDATE payment_receipts SET lease_token=NULL,lease_until=0,next_retry_at=?
                            WHERE source=? AND entity_id=? AND lease_token=?""",
                            (current['cleanup_at'], row['purpose'], str(row['entity_id']), token))
                    self.save(conn, current)
            except BaseException:
                with self.connection(True) as conn:
                    conn.execute("""UPDATE payment_receipts SET lease_token=NULL,lease_until=0,next_retry_at=?
                        WHERE source=? AND entity_id=? AND lease_token=?""",
                        (now + 30, row['purpose'], str(row['entity_id']), token))
                raise

    async def credit_review(self, actor, ident):
        self.require_owner(actor)
        if not self.paid_proof(self.transaction(ident)):
            await self.refresh(ident)
        with self.connection(True) as conn:
            row = self.transaction(ident, conn=conn)
            if row['state'] == 'SETTLED_BALANCE':
                return row
            if row['state'] != 'REVIEW' or not self.paid_proof(row):
                raise GatewayError('NOT_READY')
            ref = 'PA-REVIEW-' + ident
            existing = conn.execute("SELECT id FROM wallet_ledger WHERE type='TOPUP' AND user_id=? AND reference=?",
                                    (row['user_id'], ref)).fetchone()
            if not existing:
                wallet = conn.execute('SELECT balance FROM wallets WHERE user_id=?', (row['user_id'],)).fetchone()
                balance = (wallet[0] if wallet else 0) + row['amount']
                if not 0 <= balance <= 9223372036854775807:
                    raise GatewayError('STORAGE')
                stamp = datetime.now().isoformat(timespec='seconds')
                conn.execute("""INSERT INTO wallets(user_id,balance,updated_at) VALUES(?,?,?)
                    ON CONFLICT(user_id) DO UPDATE SET balance=excluded.balance,updated_at=excluded.updated_at""",
                    (row['user_id'], balance, stamp))
                conn.execute("""INSERT INTO wallet_ledger(user_id,type,amount,balance_after,reference,note,created_at)
                    VALUES(?,'TOPUP',?,?,?,'Payinaja payment reviewed',?)""",
                    (row['user_id'], row['amount'], balance, ref, stamp))
            row.update(state='SETTLED_BALANCE', credited_at=time.time(), error='')
            self.save(conn, row)
        return self.transaction(ident)

    async def poll_once(self):
        for ident in self.due_ids('active'):
            try:
                row = self.transaction(ident)
                if row['state'] == 'NEW':
                    if self.ready():
                        await self.issue(ident)
                    else:
                        with self.connection(True) as conn:
                            current = self.transaction(ident, conn=conn)
                            current['next_poll_at'] = time.time() + 30
                            self.save(conn, current)
                else:
                    await self.refresh(ident)
                await self.deliver_pending_qr(ident)
            except GatewayError as exc:
                if exc.code == 'RATE_LIMIT':
                    break
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.diagnostic(exc, 'poll')

    async def start(self, bot):
        self.bot = bot
        if self.tasks:
            return []
        async def payments():
            while True:
                try:
                    await self.poll_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.diagnostic(exc, 'poll')
                await asyncio.sleep(15)
        async def cleanup():
            while True:
                try:
                    await self.cleanup_success_receipts(bot)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.diagnostic(exc, 'cleanup')
                await asyncio.sleep(30)
        self.tasks = [asyncio.create_task(payments(), name='payinaja_payments'),
                      asyncio.create_task(cleanup(), name='payinaja_invoice_cleanup')]
        return list(self.tasks)

    async def close(self):
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks = []
        await self.api.close()

    @staticmethod
    def owner_keyboard(rows):
        return InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=label, callback_data=PREFIX + 'a:' + action + (':' + str(value) if value is not None else ''))
             for label, action, value in line] for line in rows])

    async def owner_panel(self, call, *, note=''):
        self.require_owner(call.from_user.id)
        proof = self.proof()
        _, health = self.creation_health()
        last = self.setting('create', {})
        last_row = (self.transaction(last['transaction_id']) if last.get('transaction_id')
                    and last.get('fingerprint') == self.fingerprint() else None)
        if last.get('checked_at', 0) < self.started_at:
            health = 'Belum ada create pada proses ini; riwayat tetap tersimpan.'
        if last_row and self.is_prior_session(last_row):
            last_row = None
        qr_state = ('Belum ada invoice baru pada proses ini' if last_row is None else
                    'Menunggu kepastian invoice' if last_row['state'] in {'NEW', 'REQUESTING', 'CREATE_UNKNOWN'} else
                    'QR tidak ditampilkan untuk status ' + last_row['state'] if last_row['state'] != 'PENDING' else
                    'QR tersedia; pengiriman Telegram terpisah' if self.has_qr(last_row) else
                    'Belum tersedia; periksa diagnosis image dan detail invoice')
        text = ('👑 <b>PENGATURAN QRIS OTOMATIS</b>\n\nProvider: Payinaja\n'
                f'Versi bot: {html.escape(self.host.BOT_VERSION)} • Gateway: {ADAPTER_VERSION}\n'
                f'Server create: {self.config.server}\n'
                f'Izin membuat invoice: {"AKTIF" if self.enabled() else "NONAKTIF"}\n'
                f'Konfigurasi: {"Tersedia" if self.config.valid() else "Periksa PAYINAJA_API_KEY / konfigurasi API"}\n'
                f'Autentikasi: {"Terverifikasi; merchant approved" if proof.get("approved") else "Belum terverifikasi"}\n'
                'Status pembuatan invoice: ' + html.escape(health) + '\n'
                'Sumber QR invoice terakhir: ' + qr_state + '\n'
                'Profil dan invoice diperiksa otomatis saat checkout. '
                'Pembayaran diverifikasi lewat API status; callback H2H tidak dipakai.\n'
                'Kredensial tidak ditampilkan. Key KlikQRIS tidak dipakai untuk Payinaja.\n')
        if proof.get('error') and not proof.get('approved'):
            text += ('\nPembayaran belum siap: ' + access_note(proof.get('error_denial'), proof.get('http_status')) +
                     '\nAktivasi hanya berhasil setelah akses API diterima; tidak ada invoice uji dibuat.\n')
        for kind in ['connection', 'checkout', 'create', 'status', 'image', 'telegram', 'cancel', 'poll', 'cleanup']:
            detail = self.setting('diagnostic.' + kind, {})
            if not isinstance(detail, dict) or detail.get('fingerprint') != self.fingerprint():
                continue
            if detail.get('checked_at', 0) < self.started_at:
                continue  # Old diagnostics remain in storage/detail history, not the fresh process panel.
            text += ('\nTahap: ' + html.escape(str(detail['stage'])) + ' • Kode: ' + html.escape(str(detail['code'])) +
                     ' • HTTP: ' + str(detail.get('http_status') or '-') +
                     '\nWaktu: ' + self.host.payment_receipts.format_wib(detail['checked_at'], compact=True) +
                     ' • ID: ' + html.escape(detail['correlation_id']) + '\n')
            if detail.get('endpoint'):
                text += 'Request: ' + html.escape(str(detail['endpoint'])) + '\n'
            if detail.get('cached'):
                text += ('Sumber: cache penolakan sebelumnya; tidak ada request API baru pada pemeriksaan ini.\n'
                         'Waktu request API: ' + self.host.payment_receipts.format_wib(detail['request_checked_at'], compact=True) + '\n')
            if detail.get('denial'):
                text += access_note(detail['denial'], detail.get('http_status')) + '\n'
            if detail.get('schema'):
                text += 'Bentuk respons (tanpa nilai privat): ' + html.escape(encoded(detail['schema'])) + '\n'
        if note:
            text += '\n' + html.escape(note)
        await self.host.safe_edit_or_answer(call, text, parse_mode='HTML', reply_markup=self.owner_keyboard([
            [('🔴 Nonaktifkan' if self.enabled() else '🟢 Aktifkan Payinaja', 'toggle', 'off' if self.enabled() else 'on')],
            [('📊 Riwayat', 'history', '0'), ('⏳ Pending', 'pending', '0')],
            [('🔄 Rekonsiliasi', 'reconcile', None)],
            [('⚙️ Pilih Provider', 'providers', None)], [('⬅️ Pengaturan Pembayaran', 'back', None)]]))

    async def owner_list(self, call, *, pending=False, page=0):
        self.require_owner(call.from_user.id)
        with self.connection() as conn:
            if pending:
                keys = [item[0].replace('payinaja.active.', '') for item in conn.execute(
                    "SELECT key FROM settings WHERE key GLOB 'payinaja.active.*' ORDER BY key DESC")]
                keys += [item[0].replace('payinaja.review.', '') for item in conn.execute(
                    "SELECT key FROM settings WHERE key GLOB 'payinaja.review.*'")]
            else:
                keys = [item[0].replace(TX_PREFIX, '') for item in conn.execute(
                    "SELECT key FROM settings WHERE key GLOB 'payinaja.tx.*' ORDER BY key DESC")]
        page = max(0, min(int(page), max(0, (len(keys) - 1) // 6)))
        text, controls = '📊 <b>TRANSAKSI QRIS OTOMATIS</b>\nProvider: Payinaja\n\n', []
        for ident in keys[page * 6:page * 6 + 6]:
            row = self.transaction(ident)
            text += html.escape(row['reference']) + ' • ' + self.host.rupiah(row['total_amount'] or row['amount']) + ' • ' + row['state'] + '\n'
            controls.append([('🔎 ' + row['reference'], 'detail', ident)])
        if not keys:
            text += 'Belum ada transaksi.\n'
        nav = []
        action = 'pending' if pending else 'history'
        if page:
            nav.append(('⬅️ Sebelumnya', action, str(page - 1)))
        if (page + 1) * 6 < len(keys):
            nav.append(('Berikutnya ➡️', action, str(page + 1)))
        if nav:
            controls.append(nav)
        controls.append([('⬅️ Kembali', 'menu', None)])
        await self.host.safe_edit_or_answer(call, text, parse_mode='HTML', reply_markup=self.owner_keyboard(controls))

    async def owner_detail(self, call, ident, *, confirm=False):
        row = self.transaction(ident, call.from_user.id, admin=True)
        text = self.status_text(row) + '\nProvider: Payinaja\nRef: ' + html.escape(row['reference'])
        text += '\nID provider: ' + html.escape(row['provider_id'] or '-') + '\nKode: ' + html.escape(row['error'] or '-')
        detail = row.get('diagnostic')
        if detail and row['error']:
            text += ('\nTahap: ' + html.escape(detail['stage']) + ' • HTTP: ' + str(detail.get('http_status') or '-') +
                     '\nWaktu: ' + self.host.payment_receipts.format_wib(detail['checked_at'], compact=True) +
                     ' • ID: ' + html.escape(detail['correlation_id']))
            if detail.get('schema'):
                text += '\nBentuk respons (tanpa nilai privat): ' + html.escape(encoded(detail['schema']))
        if row['cancel_requested']:
            audit = row.get('cancel_audit')
            if audit:
                text += ('\nAsal pembatalan: ' + html.escape(audit['source']) + '\nWaktu permintaan: ' +
                         self.host.payment_receipts.format_wib(audit['created_at'], compact=True))
            else:
                text += '\nAsal pembatalan: metadata versi lama; aktor/waktu belum tercatat.'
        cancel_detail = row.get('cancel_diagnostic')
        if cancel_detail:
            text += ('\nPengajuan pembatalan terakhir: ' + html.escape(cancel_detail['code']) + ' • HTTP: ' + str(cancel_detail.get('http_status') or '-') +
                     '\nWaktu: ' + self.host.payment_receipts.format_wib(cancel_detail['checked_at'], compact=True) +
                     ' • ID: ' + html.escape(cancel_detail['correlation_id']))
        confirmation = row.get('cancel_confirmation')
        if confirmation:
            text += ('\nKonfirmasi API: FAILED • HTTP: 200\nWaktu: ' +
                     self.host.payment_receipts.format_wib(confirmation['checked_at'], compact=True) +
                     ' • ID: ' + html.escape(confirmation['correlation_id']))
        controls = [[('🔄 Rekonsiliasi Status', 'check', ident)]]
        if row['state'] == 'REVIEW' and self.paid_proof(row):
            text += '\nPembayaran sah perlu penanganan owner; tidak ada saldo atau produk diproses otomatis.'
            if confirm:
                text += '\nKonfirmasi: kreditkan nominal pesanan ke saldo? Biaya provider tidak dikreditkan dan produk tidak dikirim.'
                controls.append([('✅ Konfirmasi Kredit Saldo', 'credit', ident)])
            else:
                controls.append([('💰 Pindahkan ke Saldo', 'credit_confirm', ident)])
        controls.append([('⬅️ Kembali', 'pending', '0'), ('🏠 QRIS Otomatis', 'menu', None)])
        await self.host.safe_edit_or_answer(call, text, parse_mode='HTML', reply_markup=self.owner_keyboard(controls))


def register(router, gateway):
    host = gateway.host

    @router.callback_query(F.data.startswith(PREFIX))
    async def payinaja_callback(call, state):
        owner = False
        try:
            if not call.message or str(call.message.chat.type) != 'private' or call.message.chat.id != call.from_user.id:
                raise GatewayError('FORBIDDEN')
            parts = str(call.data or '').split(':')
            if len(parts) not in {3, 4}:
                raise GatewayError('INPUT')
            scope, action = parts[1:3]
            value = parts[3] if len(parts) == 4 else None
            owner = scope == 'a'
            if owner:
                gateway.require_owner(call.from_user.id)
                await state.clear()
            elif scope != 'u':
                raise GatewayError('INPUT')
            ok, _ = host.persistent_rate_limit(call.from_user.id, 'autoqris_callback', limit=20, window_seconds=60)
            if not ok:
                raise GatewayError('RATE_LIMIT')
            await host.safe_callback_notice(call)
            gateway.bot = call.bot
            if not owner:
                if action == 'check':
                    await gateway.show_status(call, value)
                elif action == 'cancel':
                    await gateway.prompt_cancel(call, value)
                elif action == 'confirm':
                    bits = (value or '').split('.')
                    if len(bits) != 2:
                        raise GatewayError('INPUT')
                    await gateway.cancel(call, bits[0], nonce=bits[1])
                elif action == 'keep':
                    await gateway.keep_payment(call, value)
                else:
                    raise GatewayError('INPUT')
                return
            if action == 'menu':
                await gateway.owner_panel(call)
            elif action == 'connect':
                await gateway.check_connection(call.from_user.id)
                await gateway.owner_panel(call, note='Profil diperiksa; tidak ada invoice dibuat.')
            elif action == 'toggle':
                if value == 'on':
                    await gateway.activate(call.from_user.id)
                elif value == 'off':
                    gateway.disable(call.from_user.id)
                else:
                    raise GatewayError('INPUT')
                await gateway.owner_panel(call)
            elif action in {'history', 'pending'}:
                if not value or not re.fullmatch('[0-9]{1,6}', value):
                    raise GatewayError('INPUT')
                await gateway.owner_list(call, pending=action == 'pending', page=int(value))
            elif action == 'reconcile':
                await gateway.poll_once()
                await gateway.owner_list(call, pending=True)
            elif action == 'detail':
                await gateway.owner_detail(call, value)
            elif action == 'check':
                await gateway.show_status(call, value, admin=True)
            elif action == 'credit_confirm':
                await gateway.owner_detail(call, value, confirm=True)
            elif action == 'credit':
                await gateway.credit_review(call.from_user.id, value)
                await gateway.owner_detail(call, value)
            elif action == 'providers':
                await host.automatic_qris.owner_provider_menu(host, call)
            elif action == 'back':
                await host.safe_edit_or_answer(call, '💳 Pengaturan Pembayaran', reply_markup=host.qris_settings_menu())
            else:
                raise GatewayError('INPUT')
        except (GatewayError, sqlite3.Error) as exc:
            if getattr(exc, 'code', '') == 'FORBIDDEN':
                return await host.safe_callback_notice(call, 'Akses ditolak.', show_alert=True)
            detail = gateway.diagnostic(exc, 'owner' if owner else 'checkout')
            text = 'Payinaja belum dapat diproses. Periksa status invoice; tagihan pengganti tidak dibuat.'
            if getattr(exc, 'code', '') == 'MIN_AMOUNT':
                text = 'Minimum pembayaran QRIS Payinaja Rp500. Pilih metode lain untuk nominal lebih kecil.'
            elif getattr(exc, 'code', '') == 'CONFIRM_EXPIRED':
                text = 'Konfirmasi sudah dipakai atau kedaluwarsa. Buka kembali invoice; tidak ada pembatalan baru diajukan.'
            elif owner and getattr(exc, 'code', '') == 'AUTH':
                text = access_note(getattr(exc, 'denial', None), getattr(exc, 'http_status', 0))
            if owner and host.is_owner(call.from_user.id):
                try:
                    await gateway.owner_panel(call, note='Kode: ' + detail['code'] + ' • ID: ' + detail['correlation_id'])
                except (GatewayError, sqlite3.Error):
                    pass
            await host.safe_callback_notice(call, text, show_alert=True)
    return gateway


async def read_only_access_probe(config=None):
    """Hosting diagnostic: exactly GET profile, no DB, activation or invoice."""
    api = Client(config or Config.environment())
    try:
        await api.profile()
        return dict(code='OK', http_status=200, endpoint='GET /profile', approved=True,
                    correlation_id=secrets.token_hex(8), read_only=True, invoice_created=False)
    except GatewayError as exc:
        result = dict(code=exc.code, http_status=exc.http_status, endpoint=exc.endpoint,
                      approved=False, correlation_id=exc.correlation_id, read_only=True, invoice_created=False)
        if isinstance(getattr(exc, 'denial', None), dict):
            result['denial'] = exc.denial
        return result
    finally:
        await api.close()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Pemeriksaan akses Payinaja tanpa membuat invoice atau mengubah database.')
    parser.add_argument('--check-access', action='store_true', help='GET profil memakai secret hosting; output hanya diagnosis aman.')
    args = parser.parse_args()
    if not args.check_access:
        parser.error('Gunakan --check-access untuk pemeriksaan read-only.')
    result = asyncio.run(read_only_access_probe())
    print(encoded(result))
    raise SystemExit(0 if result['code'] == 'OK' else 1)
