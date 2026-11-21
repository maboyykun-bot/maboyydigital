"""Payinaja QRIS: authenticated polling, native accounting, no H2H operations."""
import asyncio
import binascii
import hashlib
import hmac
import html
import ipaddress
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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from io import BytesIO
from types import SimpleNamespace
from urllib.parse import urlsplit, parse_qs, urljoin, unquote

import aiohttp
import qrcode
import zxingcpp
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
ADAPTER_VERSION = '17.71'
QR_BLOCKING_ERRORS = frozenset({'SCHEMA', 'MISMATCH', 'AUTH', 'ACCOUNT_CHANGED', 'DUPLICATE_REFERENCE'})
DENIAL_LIMIT = 16384
UPSTREAM_LIMIT = 16384


async def upstream_context(response):
    """Keep response-reported hints only, never the 5xx body or its values."""
    result = dict(kind='unspecified', format='empty', source='http-status',
                  origin_evidence='unproven', error_code='', shape={})
    if str(response.headers.get('cf-mitigated', '')).casefold() == 'challenge':
        result.update(kind='edge_challenge', format='unread', source='edge-header')
        return result

    async def read():
        raw = bytearray()
        async for chunk in response.content.iter_chunked(4096):
            raw.extend(chunk[:UPSTREAM_LIMIT + 1 - len(raw)])
            if len(raw) > UPSTREAM_LIMIT:
                break
        return bytes(raw)

    try:
        raw = await asyncio.wait_for(read(), timeout=3)
    except asyncio.CancelledError:
        raise
    except Exception:
        result['format'] = 'unreadable'
        return result
    if len(raw) > UPSTREAM_LIMIT:
        result['format'] = 'oversize'
        return result
    if not raw.strip():
        return result
    try:
        data = json.loads(raw)
    except RecursionError:
        result['format'] = 'unreadable'
        return result
    except (ValueError, UnicodeError):
        lower = raw.lower()
        result['format'] = 'html' if b'<html' in lower or b'<!doctype html' in lower else 'text'
        if result['format'] == 'html' and (b'challenge-platform' in lower or b'cf_chl_' in lower):
            result.update(kind='edge_challenge', source='html-challenge')
        return result
    result['format'] = 'json'
    if not isinstance(data, dict):
        return result

    def kind(value):
        return ('null' if value is None else 'bool' if isinstance(value, bool) else
                'string' if isinstance(value, str) else 'object' if isinstance(value, dict) else
                'array' if isinstance(value, list) else 'number' if isinstance(value, (int, float)) else 'other')

    result['shape'] = {name: kind(data[name]) for name in ('success', 'message', 'error', 'code', 'error_code', 'data') if name in data}
    nested = data.get('error') if isinstance(data.get('error'), dict) else {}
    for name in ('code', 'message'):
        if name in nested:
            result['shape']['error.' + name] = kind(nested[name])
    mapping = {
        'INVALID_API_KEY': 'credentials_rejected', 'API_KEY_INVALID': 'credentials_rejected',
        'API_KEY_REVOKED': 'credentials_rejected', 'IP_NOT_ALLOWED': 'ip_restricted',
        'IP_NOT_WHITELISTED': 'ip_restricted', 'IP_RESTRICTED': 'ip_restricted',
        'MERCHANT_INACTIVE': 'merchant_restricted', 'MERCHANT_NOT_APPROVED': 'merchant_restricted',
        'ACCOUNT_SUSPENDED': 'merchant_restricted', 'PERMISSION_DENIED': 'api_permission',
        'PROVIDER_UNAVAILABLE': 'service_unavailable', 'SERVICE_UNAVAILABLE': 'service_unavailable',
        'MAINTENANCE': 'service_unavailable', 'QRIS_GENERATION_FAILED': 'qr_generation_failed',
        'QR_GENERATION_FAILED': 'qr_generation_failed', 'VALIDATION_ERROR': 'parameter_error',
        'INVALID_AMOUNT': 'parameter_error', 'AMOUNT_TOO_LOW': 'parameter_error',
        'INSUFFICIENT_BALANCE': 'balance_error', 'INSUFFICIENT_FUNDS': 'balance_error',
        'DUPLICATE_REFERENCE': 'reference_conflict', 'REFERENCE_ALREADY_EXISTS': 'reference_conflict',
    }
    for value in (data.get('code'), data.get('error_code'), nested.get('code')):
        if isinstance(value, str) and value.strip().upper() in mapping:
            code = value.strip().upper()
            result.update(kind=mapping[code], source='json-code', error_code=code)
            return result
    # A fixed phrase is a reported hint, never a conclusion about our key or
    # the originating service. Unrecognized text is not persisted or displayed.
    phrases = {
        'qr_generation_failed': ('failed to generate qris', 'gagal membuat qris', 'qris generation failed'),
        'service_unavailable': ('service unavailable', 'provider unavailable', 'under maintenance', 'sedang pemeliharaan'),
        'credentials_rejected': ('invalid api key', 'api key tidak valid', 'api key revoked'),
        'parameter_error': ('invalid parameter', 'parameter tidak valid', 'validation failed'),
    }
    for value in (data.get('message'), data.get('error'), nested.get('message')):
        if isinstance(value, str):
            text = value.casefold()
            for category, values in phrases.items():
                if any(phrase in text for phrase in values):
                    result.update(kind=category, source='json-message')
                    return result
    return result


def upstream_note(context):
    notes = {
        'credentials_rejected': 'Respons 5xx menyebut kesalahan kredensial; belum membuktikan API key bot salah.',
        'ip_restricted': 'Respons 5xx menyebut pembatasan IP pada layanan pembayaran.',
        'merchant_restricted': 'Respons 5xx menyebut pembatasan akun merchant.',
        'api_permission': 'Respons 5xx menyebut izin akses pada layanan pembayaran.',
        'service_unavailable': 'Respons 5xx menyebut layanan atau provider belum tersedia.',
        'qr_generation_failed': 'Respons 5xx menyebut kegagalan pembuatan QRIS.',
        'parameter_error': 'Respons 5xx menyebut parameter request tidak valid.',
        'balance_error': 'Respons 5xx menyebut kendala saldo pada layanan pembayaran.',
        'reference_conflict': 'Respons 5xx menyebut referensi sudah digunakan; hasilnya tetap direkonsiliasi.',
        'edge_challenge': 'Respons memuat challenge; request belum diterima sebagai respons API normal.',
    }
    category = context.get('kind') if isinstance(context, dict) else None
    return notes.get(category if isinstance(category, str) else None,
                     'Respons 5xx tidak memberi alasan yang dapat diklasifikasikan dengan aman.')


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
    except (ValueError, UnicodeError, RecursionError):
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


async def hosting_ipv4():
    """Observe this service's IPv4 toward ipify; never send payment credentials."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5), trust_env=True,
                                         cookie_jar=aiohttp.DummyCookieJar()) as session:
            async with session.get('https://api.ipify.org?format=json', headers={'Accept': 'application/json'},
                                   allow_redirects=False) as response:
                if response.status != 200:
                    raise GatewayError('IP_LOOKUP_HTTP', http_status=response.status)
                raw = bytearray()
                async for chunk in response.content.iter_chunked(256):
                    raw.extend(chunk[:1025 - len(raw)])
                    if len(raw) > 1024:
                        raise GatewayError('IP_LOOKUP_SIZE')
                try:
                    data = json.loads(raw)
                    value = data.get('ip') if isinstance(data, dict) else None
                    if not isinstance(value, str) or len(value) > 45:
                        raise ValueError
                    address = ipaddress.ip_address(value)
                    if (address.version != 4 or not address.is_global or address.is_multicast
                            or address.is_reserved or address.is_unspecified):
                        raise ValueError
                    return str(address)
                except (ValueError, TypeError, UnicodeError):
                    raise GatewayError('IP_LOOKUP_SCHEMA') from None
    except (aiohttp.ClientError, asyncio.TimeoutError):
        raise GatewayError('IP_LOOKUP_UNAVAILABLE') from None


@dataclass(frozen=True)
class Config:
    key: str = field(default='', repr=False)
    base_url: str = 'https://payinaja.com/api/v1'
    timeout: int = 15
    server: int = 2
    enabled: bool = False
    create_timeout: int = 45

    @classmethod
    def environment(cls):
        key, _ = environment_value('PAYINAJA_API_KEY')
        base, _ = environment_value('PAYINAJA_API_BASE_URL', cls.base_url)
        server, _ = environment_value('PAYINAJA_QRIS_SERVER', '2')
        enabled, _ = environment_value('PAYINAJA_ENABLED', 'false')
        create_timeout, _ = environment_value('PAYINAJA_CREATE_TIMEOUT_SECONDS', '45')
        return cls(key=key, base_url=base.rstrip('/'),
                   server=int(server) if server in {'1', '2'} else 0,
                   enabled=enabled.lower() in {'true', '1'},
                   create_timeout=int(create_timeout) if re.fullmatch('[0-9]{1,2}', create_timeout) else 0)

    def valid(self):
        try:
            u = urlsplit(self.base_url)
            return (isinstance(self.key, str) and 1 <= len(self.key) <= 4096
                    and all(33 <= ord(c) <= 126 for c in self.key)
                    and u.scheme == 'https' and u.hostname in API_HOSTS
                    and u.port in {None, 443} and not u.username and not u.password
                    and u.path == '/api/v1' and not u.query and not u.fragment
                    and type(self.server) is int and self.server in {1, 2}
                    and type(self.create_timeout) is int and 15 <= self.create_timeout <= 60
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


def lifecycle_status(data, *, bound=False, qris_bound=False):
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
    # Server 2 may report a settlement-channel label instead of literal "qris".
    # Only an authenticated QRIS create plus validated original QR may establish
    # this alternative binding. A history hit or a paid flag alone cannot.
    if (not isinstance(method, str) or len(method) > 128
            or (method.strip().casefold() != 'qris' and not qris_bound)):
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
            if method == 'POST' and path in {'/qris/create', '/qris/create2'}:
                options['timeout'] = aiohttp.ClientTimeout(total=self.config.create_timeout, connect=self.config.timeout)
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
                    exc = error('UPSTREAM', status)
                    exc.upstream = await upstream_context(response)
                    raise exc
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
                except (ValueError, UnicodeError, RecursionError):
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
        data = await self.request('POST', path, {'reference_id': ref, 'amount': amount,
                                               'customer_name': 'Pelanggan'})
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

    async def status(self, ident, ref, amount, total=None, fee=None, *, recovered=False, qris_bound=False):
        ident, ref = reference(ident), reference(ref)
        data = await self.request('GET', '/transaction/' + ident)
        try:
            if not isinstance(data, dict):
                raise GatewayError('SCHEMA')
            if data.get('trx_id') != ident or data.get('merchant_ref') != ref:
                raise GatewayError('MISMATCH')
            recovered_failed = (recovered and total is None and fee is None
                                and isinstance(data.get('status'), str)
                                and data['status'].strip().casefold() == 'failed')
            # Recovery may recognize FAILED with another method, but never relaxes
            # pending/paid. An unknown quote still goes through amounts() below.
            state = lifecycle_status(data, bound=recovered_failed or (total is not None and fee is not None),
                                     qris_bound=qris_bound is True and total is not None and fee is not None)
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
            if (state != 'FAILED' or recovered_failed) and data.get('amount_requested') is not None and money(data['amount_requested'], positive=True) != base:
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
            raise self.validation_context(exc, 'GET /showtrx')

    async def cancel(self, ident):
        await self.request('POST', '/transaction/' + reference(ident) + '/cancel')
        return dict(accepted=True, http_status=200, checked_at=time.time(),
                    correlation_id=secrets.token_hex(8), endpoint='POST /transaction/{trx_id}/cancel')

    async def cancel_status(self, ident, ref, *, bound=False, qris_bound=False):
        """Identity + lifecycle only; this response NEVER authorizes a payment."""
        ident, ref = reference(ident), reference(ref)
        data = await self.request('GET', '/transaction/' + ident)
        try:
            if not isinstance(data, dict):
                raise GatewayError('SCHEMA')
            if data.get('trx_id') != ident or data.get('merchant_ref') != ref:
                raise GatewayError('MISMATCH')
            return lifecycle_status(data, bound=bound, qris_bound=qris_bound is True and bound)
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

    @staticmethod
    def image_qris(raw, total):
        """Verify the actual raster's QR payload, retaining the original bytes."""
        Client.image_valid(raw)
        try:
            with Image.open(BytesIO(raw)) as picture:
                codes = zxingcpp.read_barcodes(picture.convert('RGB'), formats=zxingcpp.BarcodeFormat.QRCode)
            if len(codes) != 1 or not codes[0].valid:
                raise ValueError
            payload = codes[0].text
        except Exception:
            raise GatewayError('QR_IMAGE_UNREADABLE') from None
        qris_payload(payload, total)  # Same EMV, CRC, currency and amount guard as text QRIS.
        return raw

    async def image(self, value, provider_id=None):
        """Fetch only the image URL returned by an authenticated, bound invoice."""
        endpoint = 'GET {qris_image}'
        if not self.config.valid() or not isinstance(value, str):
            raise GatewayError('CONFIG' if not self.config.valid() else 'IMAGE')
        if value.startswith(('data:image/png;base64,', 'data:image/jpeg;base64,', 'data:image/webp;base64,')):
            if len(value) > (QR_LIMIT * 4 // 3) + 128:
                raise GatewayError('IMAGE_SIZE', endpoint='LOCAL {qris_image}')
            try:
                return self.image_valid(base64.b64decode(value.split(',', 1)[1], validate=True))
            except (ValueError, TypeError):
                raise GatewayError('IMAGE', endpoint='LOCAL {qris_image}') from None
            except GatewayError as exc:
                exc.endpoint = 'LOCAL {qris_image}'
                raise
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
                try:
                    return self.image_valid(bytes(raw))
                except GatewayError as exc:
                    exc.http_status, exc.endpoint = 200, endpoint
                    raise
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
        self._poll_lock = asyncio.Lock()
        self._media_jobs = {}
        self._media_closing = False
        self.delivery_locks = {}
        self.started_at = time.time()
        self.requested_qr_ids = set()
        self.terminal_notices = {}

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

    def selected_server(self, conn=None):
        # An explicit owner choice overrides the hosting default for NEW invoices.
        value = self.setting('server', None, conn)
        value = self.config.server if value is None else value
        if type(value) is not int or value not in {1, 2}:
            raise GatewayError('CONFIG')
        return value

    def set_server(self, actor, server):
        self.require_owner(actor)
        if server is not None and (type(server) is not int or server not in {1, 2}):
            raise GatewayError('INPUT')
        with self.connection(True) as conn:
            self.put(conn, 'server', server)

    def ready(self):
        try:
            return self.config.valid() and bool(self.selected_server()) and self.enabled() and self.proof().get('approved') is True
        except (sqlite3.Error, GatewayError):
            return False

    def can_attempt(self):
        try:
            return self.config.valid() and bool(self.selected_server()) and self.enabled()
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
        if isinstance(getattr(exc, 'upstream', None), dict):
            data['upstream'] = exc.upstream
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
        fingerprint = self.fingerprint()
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
            if self.fingerprint() != fingerprint:
                raise GatewayError('CONFIG') from None
            detail = self.diagnostic(exc, 'connection')
            with self.connection(True) as conn:
                self.put(conn, 'profile', dict(approved=False, fingerprint=self.fingerprint(),
                    checked_at=detail['request_checked_at'], error=exc.code, http_status=exc.http_status,
                    error_endpoint=detail['endpoint'], error_correlation_id=detail['correlation_id'],
                    error_denial=detail.get('denial', {})))
            raise
        if self.fingerprint() != fingerprint:
            raise GatewayError('CONFIG')
        result.update(fingerprint=fingerprint, checked_at=time.time(), http_status=200)
        with self.connection(True) as conn:
            self.put(conn, 'profile', result)
            self.put(conn, 'diagnostic.connection', dict(stage='profile', code='OK', http_status=200,
                     correlation_id=secrets.token_hex(8), checked_at=time.time(), fingerprint=self.fingerprint()))
        return result

    async def check_connection(self, actor):
        self.require_owner(actor)
        return await self.ensure_profile(force=True)

    async def activate(self, actor, *, progress=None):
        self.require_owner(actor)
        if not self.config.valid():
            raise GatewayError('CONFIG')
        token, fingerprint = secrets.token_hex(12), self.fingerprint()
        with self.connection(True) as conn:
            current = self.setting('activation', {}, conn)
            if (current.get('state') == 'checking' and current.get('lease_until', 0) > time.time()
                    and current.get('fingerprint') == fingerprint):
                raise GatewayError('BUSY')
            self.put(conn, 'activation', dict(token=token, state='checking', fingerprint=fingerprint,
                     lease_until=time.time() + self.config.timeout + 45))
        try:
            if progress is not None:
                try:
                    await asyncio.wait_for(progress(), timeout=10)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    raise GatewayError('TELEGRAM') from None
            current = self.setting('activation', {})
            if current.get('token') != token or self.fingerprint() != fingerprint:
                raise GatewayError('ACTIVATION_CANCELLED')
            try:
                await self.ensure_profile(force=True)  # GET only, never a probe invoice.
            except GatewayError:
                if self.fingerprint() != fingerprint:
                    raise GatewayError('ACTIVATION_CANCELLED') from None
                raise
            with self.connection(True) as conn:
                current = self.setting('activation', {}, conn)
                if current.get('token') != token or self.fingerprint() != fingerprint:
                    raise GatewayError('ACTIVATION_CANCELLED')
                self.put(conn, 'enabled', True)
                current.update(state='enabled', token=None, lease_until=0)
                self.put(conn, 'activation', current)
                source = self.setting('diagnostic.connection', {}, conn)
                self.put(conn, 'diagnostic.activation', dict(stage='activation', code='OK', http_status=200,
                    checked_at=time.time(), request_checked_at=self.proof(conn).get('checked_at', time.time()),
                    correlation_id=source.get('correlation_id') or secrets.token_hex(8),
                    endpoint='GET /profile', fingerprint=fingerprint))
        except BaseException as exc:
            with self.connection(True) as conn:
                current = self.setting('activation', {}, conn)
                if current.get('token') == token:
                    current.update(state='cancelled' if isinstance(exc, asyncio.CancelledError) else 'denied',
                                   token=None, lease_until=0)
                    self.put(conn, 'activation', current)
                    self.diagnostic(GatewayError('ACTIVATION_CANCELLED') if isinstance(exc, asyncio.CancelledError) else exc,
                                    'activation', conn=conn)
            raise

    def disable(self, actor):
        self.require_owner(actor)
        with self.connection(True) as conn:
            self.put(conn, 'enabled', False)
            self.put(conn, 'activation', dict(token=secrets.token_hex(12), state='disabled', lease_until=0,
                     fingerprint=self.fingerprint()))

    def create_proof(self, server=None, conn=None):
        server = self.selected_server(conn) if server is None else server
        if type(server) is not int or server not in {1, 2}:
            raise GatewayError('CONFIG')
        proof = self.setting('create.server.' + str(server), None, conn)
        if proof is None:
            proof = self.setting('create', {}, conn)
        if not isinstance(proof, dict) or proof.get('fingerprint') != self.fingerprint():
            return {}
        source = proof.get('server')
        if source is None and proof.get('transaction_id'):
            try:
                source = self.transaction(proof['transaction_id'], conn=conn).get('server')
            except GatewayError:
                return {}  # Unbound legacy metadata is never authentication evidence.
        if source is None:
            source = {'POST /qris/create': 1, 'POST /qris/create2': 2}.get(proof.get('endpoint'))
        if type(source) is not int or source != server:
            return {}
        return dict(proof, server=source, code=proof.get('code') or ('OK' if proof.get('success') else proof.get('error') or 'UNKNOWN'))

    def record_create_proof(self, conn, proof, server):
        proof = dict(proof, server=server, code=proof.get('code') or ('OK' if proof.get('success') else proof.get('error') or 'UNKNOWN'))
        self.put(conn, 'create', proof)  # Compatibility alias: most recently completed request.
        self.put(conn, 'create.server.' + str(server), proof)

    def resolve_create_proof(self, conn, row, status):
        for key in ('create', 'create.server.' + str(row['server'])):
            proof = self.setting(key, {}, conn)
            if (isinstance(proof, dict) and proof.get('transaction_id') == row['id']
                    and proof.get('error') and not proof.get('resolved_at')):
                proof.update(resolved_at=time.time(), resolution_http_status=200, resolution_status=status)
                self.put(conn, key, proof)

    def creation_health(self):
        # None means no create was observed with this configuration. It is not
        # success, and it must not be reported as a failed production request.
        proof = self.create_proof()
        if not proof:
            profile = self.proof()
            if profile.get('error'):
                return None, ('Belum diuji: akses API/profil belum berhasil (HTTP ' +
                               str(profile.get('http_status') or '-') + '). Self-test tidak membuat invoice.')
            return None, 'Belum diuji: belum ada bukti create untuk server terpilih dengan key aktif. Self-test tidak membuat invoice.'
        if proof.get('error') and not proof.get('resolved_at'):
            return False, str(proof['error']) + ' • HTTP ' + str(proof.get('http_status') or '-')
        if proof.get('resolution_status') == 'FAILED':
            return False, 'Provider mengonfirmasi invoice gagal; QR tidak tersedia untuk tagihan tersebut.'
        if proof.get('resolution_status') == 'CANCELLED':
            return False, 'Invoice dibatalkan; belum ada bukti create berhasil untuk tagihan tersebut.'
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
                   origin=self.config.base_url, server=self.selected_server(conn), account_binding=profile['account_binding'],
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
                    detail = dict(stage='image', code='OK', http_status=200,
                        checked_at=time.time(), correlation_id=secrets.token_hex(8), fingerprint=self.fingerprint())
                    row['qris_cipher'], row['error'] = encrypted, ''
                    row['qr_diagnostic'] = detail
                    self.save(conn, row)
                    self.put(conn, 'diagnostic.image', detail)
        except GatewayError as exc:
            if exc.code in {'IMAGE', 'MISMATCH', 'SCHEMA'} or exc.code.startswith('QR_'):
                exc.http_status = 200
                exc.endpoint = 'LOCAL qris_source'
            exc.schema_hint = qr_source_shape(data)
            with self.connection(True) as conn:
                row = self.transaction(ident, conn=conn)
                if (exc.code in {'QR_URL_UNSUPPORTED', 'QR_SOURCE_MISSING'}
                        and row.get('image_retry_at', 0) > time.time()):
                    return  # Keep the actual image HTTP failure during its retry delay.
                if row['state'] == 'PENDING' and row['error'] not in QR_BLOCKING_ERRORS and not self.has_qr(row) and not (row['error'] == 'IMAGE'
                        and row.get('diagnostic', {}).get('code') == exc.code
                        and row.get('diagnostic', {}).get('schema') == exc.schema_hint):
                    row['error'] = 'IMAGE'
                    row['diagnostic'] = self.diagnostic(exc, 'image', conn=conn)
                    row['qr_diagnostic'] = row['diagnostic']
                    self.save(conn, row)

    async def prepare_qr(self, ident):
        row = self.transaction(ident)
        if (row['state'] != 'PENDING' or row['cancel_requested'] or row.get('retention_done')
                or row['error'] in QR_BLOCKING_ERRORS
                or self.has_qr(row) or row['expires_at'] <= time.time()):
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
        inline_image = data['qris_image_url'].startswith('data:image/')
        token = secrets.token_hex(12)
        with self.connection(True) as conn:
            current = self.transaction(ident, conn=conn)
            if (current['state'] != 'PENDING' or current['cancel_requested'] or self.has_qr(current)
                    or current['error'] in QR_BLOCKING_ERRORS
                    or current.get('image_lease_until', 0) > time.time()
                    or (not inline_image and current.get('image_retry_at', 0) > time.time())):
                return current
            current.update(image_lease_owner=token, image_lease_until=time.time() + self.config.timeout + 30)
            self.save(conn, current)
        try:
            raw = await self.api.image(data['qris_image_url'], row['provider_id'])
            await self.validate_qr_image(raw, row['total_amount'])
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
                    detail = dict(stage='image', code='OK_ORIGINAL_IMAGE', http_status=200,
                        checked_at=time.time(), correlation_id=secrets.token_hex(8), fingerprint=self.fingerprint())
                    current['qr_diagnostic'] = detail
                    self.save(conn, current)
                    self.put(conn, 'diagnostic.image', detail)
        except GatewayError as exc:
            exc.schema_hint = qr_source_shape(data)
            detail = self.diagnostic(exc, 'image')
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['state'] == 'PENDING' and current['error'] not in QR_BLOCKING_ERRORS and not self.has_qr(current):
                    current.update(error='IMAGE', diagnostic=detail, qr_diagnostic=detail,
                                   image_retry_at=time.time() + max(5, exc.retry_after))
                    self.save(conn, current)
        finally:
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current.get('image_lease_owner') == token:
                    current.update(image_lease_owner=None, image_lease_until=0)
                    self.save(conn, current)
        return self.transaction(ident)

    async def validate_qr_image(self, raw, total):
        """Bound CPU decoding separately from payment status polling."""
        guard = getattr(self, '_qr_decode_guard', None)
        if guard is None:
            guard = self._qr_decode_guard = asyncio.Semaphore(3)
        async with guard:
            pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='payinaja-qr')
            try:
                job = pool.submit(self.api.image_qris, raw, total)
                while not job.done():
                    await asyncio.sleep(.01)
                return job.result()
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

    async def status_binding(self, row):
        """Identify the invoice kind from its authenticated create and original QR.

        Some settlement responses use a different payment_method label. Do not
        guess aliases: a successfully created, correctly bound QRIS invoice and
        its unchanged validated QR are stronger evidence of the invoice kind.
        Recovered IDs/history without that evidence still require literal qris.
        This grants no payment proof; status/ID/ref/amount/fee/net must all pass.
        """
        detail = row.get('create_diagnostic', {})
        endpoint = {1: 'POST /qris/create', 2: 'POST /qris/create2'}.get(row.get('server'))
        profile = self.proof()
        if (not row.get('provider_id') or row.get('total_amount') is None or row.get('fee') is None
                or row.get('origin') != self.config.base_url or not profile.get('approved')
                or row.get('account_binding') != profile.get('account_binding')
                or not isinstance(detail, dict) or detail.get('success') is not True
                or detail.get('http_status') != 200 or detail.get('endpoint') != endpoint
                or detail.get('transaction_id') != row['id'] or not row.get('request_started_at')):
            return {}
        with self.connection() as conn:
            native = conn.execute('SELECT * FROM ' + ('orders' if row['purpose'] == 'order' else 'topups')
                + ' WHERE id=? AND user_id=?', (row['entity_id'], row['user_id'])).fetchone()
        base = ((native['total'] - int(native['discount_amount'] or 0)) if row['purpose'] == 'order'
                else native['amount']) if native else None
        if (not native or native['payment_method'] != METHOD or native['provider_reference'] != row['provider_id']
                or native['payment_total'] != row['total_amount'] or base != row['amount']):
            return {}
        context = {field: row.get(field) for field in ('id', 'purpose', 'entity_id', 'user_id', 'reference',
            'provider_id', 'amount', 'total_amount', 'fee', 'origin', 'server', 'account_binding',
            'request_started_at', 'qris_cipher', 'qr_image_cipher')}
        digest = hashlib.sha256(encoded(context).encode()).hexdigest()
        cached = getattr(self, '_status_binding_cache', None)
        if cached is None:
            cached = self._status_binding_cache = set()
        if digest in cached:
            return {'qris_bound': True}
        try:
            if row.get('qris_cipher'):
                qris_payload(self.crypt(row['qris_cipher'], row['id'], decrypt=True), row['total_amount'])
            elif row.get('qr_image_cipher'):
                raw = base64.b64decode(self.crypt(row['qr_image_cipher'], row['id'], decrypt=True), validate=True)
                await self.validate_qr_image(raw, row['total_amount'])
            else:
                return {}
        except (GatewayError, ValueError, TypeError):
            return {}
        if len(cached) >= 256:
            cached.clear()
        cached.add(digest)
        return {'qris_bound': True}

    async def issue(self, ident):
        row = self.transaction(ident)
        if row['state'] != 'NEW':
            return row
        # An expired, unsubmitted draft needs no provider call to close it.
        if row['expires_at'] > time.time():
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
            if row['request_started_at']:
                row.update(state='CREATE_UNKNOWN', next_poll_at=time.time() + 15)
                self.save(conn, row)
                return row
            if row['expires_at'] <= time.time():
                self.expire_native(conn, row)
                row.update(state='FAILED', error='EXPIRED', lease_owner=None, lease_until=0)
                self.save(conn, row)
                return row
            row.update(state='REQUESTING', lease_owner=token, lease_until=time.time() + self.config.create_timeout + 30,
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
                detail = dict(success=True, error='', code='OK', http_status=200, stage='create',
                    checked_at=time.time(), correlation_id=secrets.token_hex(8), transaction_id=ident,
                    fingerprint=self.fingerprint(), server=row['server'],
                    endpoint='POST /qris/create' + ('2' if row['server'] == 2 else ''))
                current['create_diagnostic'] = detail
                self.save(conn, current)
                self.record_create_proof(conn, detail, row['server'])
            try:
                await self.prepare_qr(ident)
            except sqlite3.Error as exc:
                detail = self.diagnostic(exc, 'image')
                try:
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        if current['state'] == 'PENDING':
                            current.update(error='IMAGE', diagnostic=detail, qr_diagnostic=detail)
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
                    detail.update(error=detail['code'], success=False, transaction_id=ident, server=row['server'])
                    current['diagnostic'] = detail
                    current['create_diagnostic'] = detail
                    self.save(conn, current)
                    self.record_create_proof(conn, detail, row['server'])
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
            binding = await self.status_binding(row)
            if row['provider_id'] and row['total_amount'] is not None and row['fee'] is not None:
                try:
                    lifecycle = await self.api.cancel_status(provider_id, row['reference'], bound=True, **binding)
                    if lifecycle in {'FAILED', 'PAID'}:
                        return lifecycle  # Already terminal: do not submit another cancel POST.
                except GatewayError:
                    pass  # Known create ID may still be cancelled if its status read is unavailable.
            # A recovered history ID must be confirmed against this reference
            # before it becomes a cancellation target. Known create IDs are bound already.
            if not row['provider_id'] or row['total_amount'] is None or row['fee'] is None:
                data = await self.api.status(provider_id, row['reference'], row['amount'],
                                             row['total_amount'], row['fee'], recovered=True)
                lifecycle = data['status']
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    if current['state'] in FINAL | {'REVIEW', 'PAID_VERIFIED'}:
                        return None
                    current.update(provider_id=provider_id, total_amount=data['total_amount'], fee=data['fee'])
                    self.native_invoice(conn, current)
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
            return await self.api.cancel_status(provider_id, row['reference'], bound=True, **binding)
        finally:
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current.get('cancel_lease_owner') == token:
                    current.update(cancel_lease_owner=None, cancel_lease_until=0, next_poll_at=time.time() + 15)
                    self.save(conn, current)

    async def refresh(self, ident, *, allow_cancel=True, prepare_image=True, settle_payment=True):
        row = self.transaction(ident)
        if row['state'] in FINAL | {'REVIEW'}:
            return row
        if row['state'] == 'PAID_VERIFIED':
            return await self.settle(ident) if settle_payment else row
        if row['state'] == 'REQUESTING':
            with self.connection(True) as conn:
                row = self.transaction(ident, conn=conn)
                if row['state'] == 'REQUESTING':
                    if row['lease_until'] > time.time():
                        row['next_poll_at'] = max(row['next_poll_at'], row['lease_until'])
                        self.save(conn, row)
                        return row
                    row.update(state='CREATE_UNKNOWN', lease_owner=None, lease_until=0)
                    self.save(conn, row)
        try:
            profile = await self.ensure_profile()
            if profile['account_binding'] != row['account_binding'] or row['origin'] != self.config.base_url:
                raise GatewayError('ACCOUNT_CHANGED')
            binding = await self.status_binding(row)
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
                elif row['provider_id'] and row['total_amount'] is not None and row['fee'] is not None:
                    lifecycle = await self.api.cancel_status(ident_provider, row['reference'], bound=True, **binding)
                else:
                    data = await self.api.status(ident_provider, row['reference'], row['amount'],
                                                 row['total_amount'], row['fee'], recovered=True)
                    lifecycle = data['status']
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        if current['state'] not in FINAL | {'REVIEW', 'PAID_VERIFIED'}:
                            current.update(provider_id=ident_provider, total_amount=data['total_amount'], fee=data['fee'])
                            self.native_invoice(conn, current)
                            self.save(conn, current)
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
                            self.resolve_create_proof(conn, current, 'CANCELLED')
                    await self.retire_paid_messages(self.bot, ident)
                    return self.transaction(ident)
                if lifecycle != 'PAID':
                    return self.transaction(ident)  # Accepted/pending is NOT final cancellation.
                row = self.transaction(ident)  # Use the recovered quote for full PAID validation.
            # PAID always follows the full amount/reference/account checks below.
            if row['total_amount'] is None and row['fee'] is None:
                data = await self.api.status(ident_provider, row['reference'], row['amount'], recovered=True)
            else:
                data = await self.api.status(ident_provider, row['reference'], row['amount'], row['total_amount'], row['fee'], **binding)
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['state'] in FINAL | {'REVIEW', 'PAID_VERIFIED'}:
                    return current
                current.update(provider_id=ident_provider, total_amount=data['total_amount'], fee=data['fee'],
                               next_poll_at=time.time() + (5 if data['status'] == 'PENDING' and not current['cancel_requested'] else 15),
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
                detail = dict(stage='status', code='CONFIRMED_FAILED' if data['status'] == 'FAILED' else current['state'], http_status=200,
                    checked_at=time.time(), correlation_id=secrets.token_hex(8),
                    endpoint='GET /transaction/{trx_id}', fingerprint=self.fingerprint(),
                    transaction_id=ident)
                current['status_diagnostic'] = detail
                self.put(conn, 'diagnostic.status', detail)
                if data['status'] != 'PENDING':
                    current['error'] = ''
                self.save(conn, current)
                self.resolve_create_proof(conn, current, data['status'])
            # Financial status takes precedence over a slow/unavailable QR image.
            # A confirmed payment must never wait for media it no longer needs.
            current = self.transaction(ident)
            if prepare_image and current['state'] == 'PENDING' and not self.has_qr(current):
                await self.prepare_qr(ident)
            if self.transaction(ident)['state'] == 'PAID_VERIFIED':
                return await self.settle(ident) if settle_payment else self.transaction(ident)
        except GatewayError as exc:
            detail = self.diagnostic(exc, 'status')
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['state'] not in FINAL:
                    current.update(error=exc.code, diagnostic=detail, status_diagnostic=detail,
                                   next_poll_at=time.time() + max(15, exc.retry_after))
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
            [InlineKeyboardButton(text='🏠 Menu Utama', callback_data='home')]])
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
        correlation_id = secrets.token_hex(8)

        def record(conn, current, code, exception_type=''):
            detail = dict(stage='settlement', code=code, http_status=0,
                          checked_at=time.time(), correlation_id=correlation_id,
                          fingerprint=self.fingerprint(), transaction_id=ident)
            if exception_type:
                detail['exception_type'] = exception_type
            current['settlement_diagnostic'] = detail
            self.put(conn, 'diagnostic.settlement', detail)

        with self.connection(True) as conn:
            row = self.transaction(ident, conn=conn)
            if row['state'] != 'PAID_VERIFIED':
                return row
            if row['lease_until'] > time.time():
                row['next_poll_at'] = max(row['next_poll_at'], row['lease_until'])
                self.save(conn, row)
                return row
            if not self.payment_authorized(conn, row['purpose'], row['entity_id']):
                row.update(state='REVIEW', error='PAYMENT_PROOF_INVALID')
                record(conn, row, 'PAYMENT_PROOF_INVALID')
                self.save(conn, row)
                return row
            native = conn.execute('SELECT * FROM ' + ('orders' if row['purpose'] == 'order' else 'topups') + ' WHERE id=?',
                                  (row['entity_id'],)).fetchone()
            if native['status'] in {'cancelled', 'rejected'} or row['cancel_requested']:
                row.update(state='REVIEW', error='PAYMENT_AFTER_CANCEL')
                record(conn, row, 'PAYMENT_AFTER_CANCEL')
                self.save(conn, row)
                return row
            row.update(lease_owner=token, lease_until=time.time() + 180,
                       next_poll_at=time.time() + 180)
            self.save(conn, row)
        settlement_code, exception_type = 'SETTLEMENT_RETRY', ''
        try:
            if row['purpose'] == 'topup':
                result, reason = self.host.verify_topup_atomic(row['entity_id'], 0)
                settlement_code = {
                    'storage_error': 'TOPUP_STORAGE_ERROR',
                    'race_lost': 'TOPUP_RACE_LOST',
                    'provider_unverified': 'TOPUP_PROVIDER_UNVERIFIED',
                }.get(reason, 'TOPUP_INVALID_STATUS' if isinstance(reason, str)
                      and reason.startswith('invalid_status:') else 'SETTLEMENT_RETRY')
                with self.connection() as conn:
                    native = conn.execute('SELECT status FROM topups WHERE id=?', (row['entity_id'],)).fetchone()
                    success = bool(result is not None and reason in {'completed', 'already_completed'}
                                   and native and native['status'] == 'completed'
                                   and self.payment_authorized(conn, 'topup', row['entity_id']))
            else:
                if self.bot is None:
                    raise GatewayError('NOT_READY')
                await self.host.mark_order_paid(row['entity_id'], self.bot, row['total_amount'])
                with self.connection() as conn:
                    native = conn.execute('SELECT payment_status FROM orders WHERE id=?', (row['entity_id'],)).fetchone()
                    # Financial settlement and account delivery are separate.
                    # mark_order_paid resumes an already-paid undelivered order;
                    # its return value is not proof that either action finished.
                    success = bool(native and native['payment_status'] == 'paid'
                                   and self.payment_authorized(conn, 'order', row['entity_id']))
                settlement_code = 'ORDER_LOCAL_PAYMENT_UNCOMMITTED'
            if success:
                settlement_code = 'LOCAL_PAYMENT_COMMITTED'
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['lease_owner'] == token and success:
                    current.update(state='SETTLED', error='', lease_owner=None, lease_until=0)
                    record(conn, current, settlement_code)
                    self.save(conn, current)
            if success:
                self.host.payment_receipts.queue(self.host, row['purpose'], row['entity_id'])
                await self.retire_paid_messages(self.bot, ident)
        except asyncio.CancelledError:
            settlement_code, exception_type = 'SETTLEMENT_CANCELLED', 'CancelledError'
            raise
        except Exception as exc:
            if isinstance(exc, sqlite3.Error):
                settlement_code, exception_type = ('TOPUP_STORAGE_ERROR' if row['purpose'] == 'topup'
                                                   else 'ORDER_STORAGE_ERROR'), 'SQLiteError'
            else:
                settlement_code = 'TOPUP_SETTLEMENT_ERROR' if row['purpose'] == 'topup' else 'ORDER_SETTLEMENT_ERROR'
                name = type(exc).__name__
                exception_type = name if name in {
                    'GatewayError', 'RuntimeError', 'ValueError', 'TypeError',
                    'TimeoutError', 'OSError', 'ConnectionError', 'KeyError',
                } else 'Exception'
            raise
        finally:
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current['lease_owner'] == token:
                    current.update(lease_owner=None, lease_until=0, next_poll_at=time.time() + 30)
                    record(conn, current, settlement_code, exception_type)
                    self.save(conn, current)
        return self.transaction(ident)

    async def fulfill_once(self, order_id, bot, implementation):
        row = self.linked('order', order_id)
        if not row:
            with self.connection() as conn:
                native = conn.execute('SELECT payment_method FROM orders WHERE id=?', (order_id,)).fetchone()
            if native and native['payment_method'] == METHOD:
                return False  # A local paid flag cannot replace missing provider evidence.
            return await implementation(order_id, bot)
        lock = self.delivery_locks.setdefault(order_id, asyncio.Lock())
        async with lock:
            token = secrets.token_hex(12)
            leased = False
            try:
                with self.connection(True) as conn:
                    current = self.transaction(row['id'], conn=conn)
                    native = conn.execute('SELECT payment_status,status FROM orders WHERE id=?', (order_id,)).fetchone()
                    if (not native or native['payment_status'] != 'paid'
                            or native['status'] in {'cancelled', 'rejected'}
                            or not self.payment_authorized(conn, 'order', order_id, settled=True)):
                        return False
                    if current['delivery_until'] > time.time():
                        return False
                    current.update(delivery_owner=token, delivery_until=time.time() + 300)
                    self.save(conn, current)
                leased = True
                return await implementation(order_id, bot)
            finally:
                if leased:
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
        await self.render_checkout_start(call)
        await self.ensure_profile()  # Automatic auth after acknowledging the click, before invoice creation.

    async def render_checkout_start(self, call):
        source = self.editable_payment_message(call)
        if source is None or self.setting('qr_view.' + str(call.from_user.id) + '.' + str(source), None) is not None:
            return
        try:
            await asyncio.wait_for(call.bot.edit_message_text(chat_id=call.from_user.id, message_id=source,
                text='⏳ <b>Menyiapkan QRIS Otomatis</b>\nMohon tunggu sebentar.', parse_mode='HTML',
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text='🏠 Menu Utama', callback_data='home')]])), timeout=2)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass  # Only edit the known card; an uncertain edit never triggers a send.

    @staticmethod
    def editable_payment_message(call):
        """Only a known bot message in the buyer's private chat can anchor a QR."""
        message = getattr(call, 'message', None)
        chat = getattr(message, 'chat', None)
        actor = getattr(message, 'from_user', None)
        message_id = getattr(message, 'message_id', None)
        return (message_id if type(message_id) is int and message_id > 0
                and str(getattr(chat, 'type', '')) == 'private'
                and getattr(chat, 'id', None) == call.from_user.id
                and getattr(actor, 'is_bot', False) is True else None)

    def bind_payment_view(self, ident, user, message_id):
        if type(message_id) is not int or message_id <= 0:
            return False
        with self.connection(True) as conn:
            row = self.transaction(ident, user, conn=conn)
            key = 'qr_view.' + str(user) + '.' + str(message_id)
            owner = self.setting(key, None, conn)
            if owner not in (None, ident):
                return False
            if row.get('qr_view_message_id') not in (None, message_id):
                return False
            self.put(conn, key, ident)
            row['qr_view_message_id'] = message_id
            self.save(conn, row)
        return True

    def payment_view_message(self, row, conn=None):
        message_id = row.get('qr_view_message_id')
        if (type(message_id) is int and message_id > 0
                and self.setting('qr_view.' + str(row['user_id']) + '.' + str(message_id), None, conn) == row['id']):
            return message_id
        return None

    @staticmethod
    def uneditable_payment_message(exc):
        text = str(exc).lower()
        return isinstance(exc, TelegramBadRequest) and any(note in text for note in (
            'message to edit not found', "message can't be edited", 'message can not be edited'))

    async def render_payment_progress(self, call, ident):
        """Remember the exact progress card before create or its recovery can run."""
        source = self.editable_payment_message(call)
        if source is None:
            row = self.transaction(ident, call.from_user.id)
            return await self.host.safe_edit_or_answer(call, self.status_text(row),
                reply_markup=self.user_keyboard(row), parse_mode='HTML')
        row = self.transaction(ident, call.from_user.id)
        anchor = self.payment_view_message(row)
        if anchor is None and self.bind_payment_view(ident, row['user_id'], source):
            anchor = source
        async with self.host.automatic_qris.payment_view_guard(self, ident):
            row = self.transaction(ident, call.from_user.id)
            if row['state'] not in {'NEW', 'REQUESTING', 'CREATE_UNKNOWN'} or row['qr_messages']:
                return
            # An ID already owned by another invoice must never be repurposed.
            # send_message is attempted only once; an uncertain result is not replayed.
            if anchor is None:
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    if current.get('qr_view_progress_started'):
                        return
                    current['qr_view_progress_started'] = True
                    self.save(conn, current)
                try:
                    message = await asyncio.wait_for(call.bot.send_message(row['user_id'], self.status_text(row),
                        reply_markup=self.user_keyboard(row), parse_mode='HTML'), timeout=self.config.timeout + 15)
                    self.bind_payment_view(ident, row['user_id'], message.message_id)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        current['qr_view_progress_unknown'] = True
                        self.save(conn, current)
                return
            try:
                await asyncio.wait_for(call.bot.edit_message_text(chat_id=row['user_id'], message_id=anchor,
                    text=self.status_text(row), reply_markup=self.user_keyboard(row), parse_mode='HTML'),
                    timeout=self.config.timeout + 15)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Keep the known ID: a timeout may already have changed it.
                # The QR worker retries media replacement against this same ID.
                pass

    async def render_payment_status(self, call, ident, *, note=''):
        """Update the invoice's own card without guessing a new message on failure."""
        row = self.transaction(ident, call.from_user.id)
        anchor = self.payment_view_message(row)
        if anchor is None:
            if row.get('qr_view_fallback_started') or row.get('qr_view_progress_unknown'):
                return  # An uncertain send must not be replaced with another card.
            source = self.editable_payment_message(call)
            if source and self.setting('qr_view.' + str(row['user_id']) + '.' + str(source), None) not in (None, ident):
                return
            return await self.host.safe_edit_or_answer(call, self.status_text(row) + note,
                reply_markup=self.user_keyboard(row), parse_mode='HTML')
        async with self.host.automatic_qris.payment_view_guard(self, ident):
            row = self.transaction(ident, call.from_user.id)
            if (row['state'] in {'PAID_VERIFIED', 'SETTLED'} or self.payment_view_message(row) != anchor
                    or self.protected_receipt_message(row['user_id'], anchor)):
                return
            options = dict(chat_id=row['user_id'], message_id=anchor,
                           reply_markup=self.user_keyboard(row), parse_mode='HTML')
            is_photo = any(item['id'] == anchor and item['kind'] == 'QR' for item in row['qr_messages'])
            try:
                if is_photo:
                    await asyncio.wait_for(call.bot.edit_message_caption(caption=self.status_text(row) + note, **options),
                                           timeout=self.config.timeout + 15)
                else:
                    try:
                        await asyncio.wait_for(call.bot.edit_message_text(text=self.status_text(row) + note, **options),
                                               timeout=self.config.timeout + 15)
                    except TelegramBadRequest as exc:
                        if not any(message in str(exc).lower() for message in (
                                'there is no text in the message', 'message has no text')):
                            raise
                        # A previous media edit may have applied despite its lost response.
                        await asyncio.wait_for(call.bot.edit_message_caption(caption=self.status_text(row) + note, **options),
                                               timeout=self.config.timeout + 15)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # No answer()/send_message fallback for a known invoice card.

    async def checkout(self, call, bot, state, variant_id, qty, *, request_id=None):
        await self.buyer_guard(call)
        qty = money(qty, positive=True)
        data = await state.get_data()
        note = self.host.get_checkout_note_from_state(data)
        def request_row(conn=None):
            if request_id is not None:
                return self.host.automatic_qris.checkout_request_row(self.host, 'payinaja', call.from_user.id,
                    variant_id, qty, request_id, conn=conn)
            return self.resumable('order', call.from_user.id, variant=variant_id, qty=qty, conn=conn)
        prior = request_row() if request_id is None else None
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
            if not request_row():
                allowed, _ = self.host.anti_abuse_checkout(call.from_user.id, METHOD)
                if not allowed:
                    raise GatewayError('LIMIT')
            with self.connection(True) as conn:
                row = request_row(conn)
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
                    self.host.automatic_qris.save_checkout_request(self.host, 'payinaja', conn, call.from_user.id,
                        variant_id, qty, request_id, row['id'])
            if row['state'] == 'NEW':
                await self.render_payment_progress(call, row['id'])
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
                await self.render_payment_progress(call, row['id'])
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
        rows.append([InlineKeyboardButton(text='🏠 Menu Utama', callback_data='home')])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def status_text(self, row):
        invoice = self.host.invoice(row['entity_id']) if row['purpose'] == 'order' else self.host.topup_invoice(row['entity_id'])
        states = dict(NEW='Menyiapkan pembayaran', REQUESTING='Menyiapkan pembayaran', CREATE_UNKNOWN='Menunggu kepastian invoice',
                      PENDING='Menunggu pembayaran', PAID_VERIFIED='Pembayaran diterima; sedang diproses', SETTLED='Pembayaran berhasil',
                      SETTLED_BALANCE='Pembayaran masuk ke saldo', CANCELLED_LOCAL='Pembatalan diajukan; menunggu konfirmasi Payinaja',
                      CANCELLED='Dibatalkan', FAILED='Pembayaran gagal / kedaluwarsa', REVIEW='Perlu pemeriksaan owner')
        text = LABEL + ' • <b>MABOYY DIGITAL</b>\n🧾 ' + html.escape(invoice) + '\n'
        text += ('💰 Nominal saldo: ' if row['purpose'] == 'topup' else '💵 Harga pesanan: ') + self.host.rupiah(row['amount']) + '\n'
        if row['total_amount'] is not None:
            adjustment = row['total_amount'] - row['amount']
            if adjustment:
                text += 'Biaya QRIS: ' + self.host.rupiah(adjustment) + '\n'
            text += '<b>Total pembayaran: ' + self.host.rupiah(row['total_amount']) + '</b>\n'
        text += '📌 Status: ' + states.get(row['state'], 'Sedang diperiksa') + '\n'
        if row['state'] == 'PENDING' and row['error'] not in {'', 'IMAGE'}:
            text += 'Verifikasi sedang dicoba ulang. Jika sudah membayar, jangan bayar lagi.\n'
        if row['error'] == 'ACCOUNT_CHANGED':
            text += 'Akun provider berbeda dari akun invoice ini. Owner perlu memeriksa akun asal; jangan bayar QR lama.\n'
        elif row['state'] == 'PENDING' and row['expires_at'] <= time.time():
            text += 'Waktu QRIS telah lewat. Jangan bayar QRIS ini; status tetap diperiksa.\n'
        elif row['state'] in {'REQUESTING', 'CREATE_UNKNOWN', 'CANCELLED_LOCAL'}:
            if row['state'] == 'CREATE_UNKNOWN' and row['error'] == 'TIMEOUT':
                text += 'Permintaan pembuatan QR melewati batas waktu. Bot sedang memeriksa hasil permintaan ini secara otomatis.\n'
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
                prompt = row.get('cancel_prompt', {})
                if (prompt.get('actor') == call.from_user.id and prompt.get('expires_at', 0) > time.time()
                        and isinstance(prompt.get('nonce'), str) and re.fullmatch('[0-9a-f]{16}', prompt['nonce'])):
                    nonce = prompt['nonce']
                else:
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

    async def replace_payment_view(self, call, row, raw):
        """Replace a known card; never turn an uncertain edit into a second send."""
        rendered_source = (row.get('qris_cipher'), row.get('qr_image_cipher'))
        anchor = self.payment_view_message(row)
        if anchor:
            try:
                await asyncio.wait_for(call.bot.edit_message_media(chat_id=row['user_id'], message_id=anchor,
                    media=InputMediaPhoto(media=BufferedInputFile(raw, filename='qris.png'),
                                         caption=self.status_text(row), parse_mode='HTML'),
                    reply_markup=self.user_keyboard(row)), timeout=self.config.timeout + 15)
                return SimpleNamespace(message_id=anchor)
            except TelegramBadRequest as exc:
                if 'message is not modified' in str(exc).lower():
                    return SimpleNamespace(message_id=anchor)
                if not self.uneditable_payment_message(exc):
                    raise
                with self.connection(True) as conn:
                    current = self.transaction(row['id'], conn=conn)
                    if self.payment_view_message(current, conn) == anchor:
                        current.pop('qr_view_message_id', None)
                        current['qr_view_fallback_from'] = anchor
                        self.save(conn, current)
                row = self.transaction(row['id'])
                with self.connection() as conn:
                    native = conn.execute('SELECT * FROM ' + ('orders' if row['purpose'] == 'order' else 'topups')
                        + ' WHERE id=?', (row['entity_id'],)).fetchone()
                if (row['state'] != 'PENDING' or row['cancel_requested'] or row.get('retention_done')
                        or row['error'] in QR_BLOCKING_ERRORS or row['expires_at'] <= time.time()
                        or row['origin'] != self.config.base_url or not self.proof().get('approved')
                        or self.proof().get('account_binding') != row['account_binding']
                        or (row.get('qris_cipher'), row.get('qr_image_cipher')) != rendered_source
                        or not native or native['user_id'] != row['user_id'] or native['payment_method'] != METHOD
                        or native['status'] in {'cancelled', 'expired', 'completed', 'rejected'}
                        or (native['payment_status'] == 'paid' if row['purpose'] == 'order' else native['status'] == 'paid')):
                    return None
        fallback = row.get('qr_view_fallback_from')
        if not anchor and not fallback and row.get('qr_view_progress_unknown'):
            return None
        if fallback:
            with self.connection(True) as conn:
                current = self.transaction(row['id'], conn=conn)
                if current.get('qr_view_fallback_started'):
                    return None  # A lost send response cannot safely be replayed.
                current['qr_view_fallback_started'] = True
                self.save(conn, current)
        try:
            message = await asyncio.wait_for(call.bot.send_photo(row['user_id'], BufferedInputFile(raw, filename='qris.png'),
                caption=self.status_text(row), reply_markup=self.user_keyboard(row), parse_mode='HTML'),
                timeout=self.config.timeout + 15)
        except (TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter):
            if fallback:
                with self.connection(True) as conn:
                    current = self.transaction(row['id'], conn=conn)
                    current.pop('qr_view_fallback_started', None)
                    self.save(conn, current)
            raise
        if fallback:
            self.bind_payment_view(row['id'], row['user_id'], message.message_id)
        return message

    async def show_payment(self, call, ident, *, automatic=False):
        row = self.transaction(ident, call.from_user.id)
        self.bot = call.bot
        if not self.payment_view_message(row):
            # v17.66 rows already know the QR they sent. Adopt it instead of
            # turning a later menu callback into a second invoice card.
            known = next((item['id'] for item in reversed(row['qr_messages'])
                          if item['kind'] == 'QR' and type(item['id']) is int and item['id'] > 0), None)
            if known:
                self.bind_payment_view(ident, row['user_id'], known)
            elif not automatic and not row.get('qr_view_fallback_started'):
                self.bind_payment_view(ident, row['user_id'], self.editable_payment_message(call))
            row = self.transaction(ident, call.from_user.id)
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
            return await self.render_payment_status(call, ident,
                note='\nPesanan sudah ditutup atau diproses di bot. QR tidak ditampilkan; status provider perlu diperiksa owner.')
        try:
            raw = (render_qris(self.crypt(row['qris_cipher'], ident, decrypt=True), row['total_amount']) if row.get('qris_cipher') else
                   self.api.image_valid(base64.b64decode(self.crypt(row['qr_image_cipher'], ident, decrypt=True), validate=True)))
            if not row.get('qris_cipher'):
                await self.validate_qr_image(raw, row['total_amount'])
        except (GatewayError, ValueError, TypeError) as exc:
            detail = self.diagnostic(exc if isinstance(exc, GatewayError) else GatewayError('IMAGE'), 'image')
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                current['qr_diagnostic'] = detail
                # An unreadable cached image must not permanently block recovery
                # from the retained, authenticated source of this SAME invoice.
                # Keep ciphertext on key/decryption or amount failures.
                invalid_raster = (not current.get('qris_cipher') and current.get('qr_image_cipher')
                                  and detail['code'] in {'IMAGE', 'QR_IMAGE_UNREADABLE', 'MISMATCH'})
                if ((invalid_raster or (detail['code'] == 'IMAGE' and current.get('qr_source_cipher')))
                        and current['state'] == 'PENDING'
                        and not current['cancel_requested'] and current['error'] not in QR_BLOCKING_ERRORS
                        and current.get('qris_cipher') == row.get('qris_cipher')
                        and current.get('qr_image_cipher') == row.get('qr_image_cipher')):
                    current.update(qris_cipher=None, qr_image_cipher=None, error='IMAGE', image_retry_at=0)
                self.save(conn, current)
            if automatic:
                return
            return await self.render_payment_status(call, ident, note='\nGambar QR belum dapat dibuka; tidak ada invoice baru dibuat.')
        # Manual clicks and the recovery worker share one durable send lease.
        # This lease concerns Telegram only; it never authorizes a payment/create.
        rendered_source = (row.get('qris_cipher'), row.get('qr_image_cipher'))
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
            async with self.host.automatic_qris.payment_view_guard(self, ident):
                row = self.transaction(ident, call.from_user.id)
                with self.connection() as conn:
                    native = conn.execute('SELECT * FROM ' + ('orders' if row['purpose'] == 'order' else 'topups')
                        + ' WHERE id=?', (row['entity_id'],)).fetchone()
                if (row['state'] != 'PENDING' or row['cancel_requested'] or row.get('retention_done')
                        or row['error'] in QR_BLOCKING_ERRORS or row['expires_at'] <= time.time()
                        or row['origin'] != self.config.base_url or not self.proof().get('approved')
                        or self.proof().get('account_binding') != row['account_binding']
                        or (row.get('qris_cipher'), row.get('qr_image_cipher')) != rendered_source
                        or row.get('qr_send_owner') != token
                        or not native or native['user_id'] != row['user_id'] or native['payment_method'] != METHOD
                        or native['status'] in {'cancelled', 'expired', 'completed', 'rejected'}
                        or (native['payment_status'] == 'paid' if row['purpose'] == 'order' else native['status'] == 'paid')):
                    return
                try:
                    message = await self.replace_payment_view(call, row, raw)
                    if message is None:
                        return
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    delay = max(30, min(3600, float(getattr(exc, 'retry_after', 0) or 0)))
                    status = 429 if isinstance(exc, TelegramRetryAfter) else 403 if isinstance(exc, TelegramForbiddenError) else 400 if isinstance(exc, TelegramBadRequest) else 0
                    detail = self.diagnostic(GatewayError('TELEGRAM', http_status=status), 'telegram')
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        current['qr_send_retry_at'] = time.time() + delay
                        current['qr_diagnostic'] = detail
                        self.save(conn, current)
                    if automatic or self.payment_view_message(current) or current.get('qr_view_fallback_from'):
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
                    if (current.get('qr_view_fallback_started')
                            and self.payment_view_message(current, conn) == message.message_id):
                        # Both the replacement ID and its QR registration are
                        # confirmed. A later definitive deletion may recover it;
                        # uncertain send results never reach this block.
                        current.pop('qr_view_fallback_started', None)
                    detail = dict(stage='telegram', code='OK', http_status=200,
                        checked_at=time.time(), correlation_id=secrets.token_hex(8), fingerprint=self.fingerprint())
                    current['qr_diagnostic'] = detail
                    self.save(conn, current)
                    self.put(conn, 'diagnostic.telegram', detail)
        finally:
            with self.connection(True) as conn:
                current = self.transaction(ident, conn=conn)
                if current.get('qr_send_owner') == token:
                    current.update(qr_send_owner=None, qr_send_until=0)
                    self.save(conn, current)
        await self.retire_paid_messages(call.bot, ident)
        previous = self.transaction(ident).get('qr_view_fallback_from')
        if previous and previous != message.message_id:
            try:
                await asyncio.wait_for(call.bot.delete_message(chat_id=row['user_id'], message_id=previous), timeout=10)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
        if automatic or self.payment_view_message(self.transaction(ident)):
            return
        try:
            await call.message.delete()
        except Exception:
            pass

    def order_message_text(self, row, native, stage):
        """Payment and fulfillment are reported independently from native facts."""
        reference = html.escape(self.host.invoice(row['entity_id']))
        amount = html.escape(self.host.rupiah(row['total_amount']))
        if stage == 'completed':
            return ('✅ <b>PEMBAYARAN BERHASIL</b>\n📦 <b>PRODUK BERHASIL DIKIRIM</b>\n\n'
                    '🧾 Invoice: <b>' + reference + '</b>\n💰 Pembayaran: <b>LUNAS</b>\n'
                    '💵 Total pembayaran: <b>' + amount + '</b>\n📦 <b>COMPLETED</b>\n'
                    'Terima kasih telah berbelanja di Maboyy Digital.')
        status, note = {
            'confirmed': ('Sedang menyiapkan produk', 'Data akun dikirim otomatis. Mohon tunggu.'),
            'pending_stock': ('Menunggu stok', 'Owner diberi tahu. Tidak perlu membayar ulang.'),
            'send_failed': ('Pengiriman sedang ditangani', 'Data akun tetap disimpan. Tidak perlu membayar ulang.'),
        }[stage]
        return ('✅ <b>PEMBAYARAN TERKONFIRMASI</b>\n⚡ <b>QRIS OTOMATIS MABOYY DIGITAL</b>\n'
                '🧾 Invoice: <b>' + reference + '</b>\n💰 Status: <b>LUNAS</b>\n'
                '💵 Total pembayaran: <b>' + amount + '</b>\n📦 Status pesanan: <b>' + status + '</b>\n\n' + note)

    def _order_notice_snapshot(self, ident, stage, conn):
        row = self.transaction(ident, conn=conn)
        if (row['purpose'] != 'order' or row['state'] not in {'PAID_VERIFIED', 'SETTLED'}
                or row['cancel_requested']
                or not self.payment_authorized(conn, 'order', row['entity_id'], settled=True)):
            return None
        native = conn.execute('SELECT * FROM orders WHERE id=? AND user_id=?',
                              (row['entity_id'], row['user_id'])).fetchone()
        if not native or native['payment_status'] != 'paid' or native['status'] in {'cancelled', 'rejected'}:
            return None
        receipt = conn.execute('SELECT status FROM payment_receipts WHERE source=\'order\' AND entity_id=?',
                               (str(row['entity_id']),)).fetchone()
        retired = row.get('retention_done') or bool(receipt and receipt['status'] in {'ARCHIVING', 'ARCHIVED'})
        completed = (native['status'] == 'completed' and native['fulfillment_status'] == 'delivered'
                     and native['account_sent'] == 1)
        if completed:
            stage = 'completed'
        elif stage == 'completed':
            return None
        notice = row.get('order_notice', {})
        if retired and ((not notice and stage != 'completed') or notice.get('stage') == 'completed'):
            return None  # No old-history replay; an unfinished persisted watch may still complete.
        if notice.get('stage') == 'completed' and not completed:
            return None  # Never downgrade a confirmed final result after inconsistent edits.
        ranks = {'confirmed': 0, 'pending_stock': 1, 'send_failed': 2, 'completed': 3}
        requested = notice.get('requested_stage')
        if not completed and requested in ranks and requested != 'completed' and ranks[requested] > ranks[stage]:
            stage = requested
        return row, native, stage

    async def _edit_order_notice(self, bot, user, message_id, kind, text):
        controls = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text='🏠 Menu Utama', callback_data='home')]])
        for _ in range(2):
            try:
                if kind == 'photo':
                    await asyncio.wait_for(bot.edit_message_caption(chat_id=user, message_id=message_id,
                        caption=text, parse_mode='HTML', reply_markup=controls), timeout=2)
                else:
                    await asyncio.wait_for(bot.edit_message_text(chat_id=user, message_id=message_id,
                        text=text, parse_mode='HTML', reply_markup=controls), timeout=2)
                return kind
            except TelegramBadRequest as exc:
                message = str(exc).lower()
                if 'message is not modified' in message:
                    return kind
                switch = (kind == 'photo' and any(value in message for value in (
                    'there is no caption', 'message has no caption', 'message is not a media message')))
                switch = switch or (kind == 'text' and any(value in message for value in (
                    'there is no text', 'message has no text')))
                if not switch:
                    raise
                kind = 'text' if kind == 'photo' else 'photo'
        raise GatewayError('TELEGRAM')

    async def update_order_message(self, bot, ident, *, stage='confirmed'):
        """Edit one bound order card, with a durable, deduplicated fallback."""
        if bot is None or stage not in {'confirmed', 'pending_stock', 'send_failed', 'completed'}:
            return False
        key = 'payinaja.notices.' + ident
        with self.connection(True) as conn:
            snapshot = self._order_notice_snapshot(ident, stage, conn)
            if snapshot is None:
                conn.execute('DELETE FROM settings WHERE key=?', (key,))
                return False
            row, native, stage = snapshot
            notice = row.setdefault('order_notice', {})
            notice.update(version=1, chat_id=row['user_id'], requested_stage=stage)
            retry_at = notice.get('retry_at', 0)
            conn.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',
                         (key, f'{max(time.time(), retry_at):020.3f}'))
            self.save(conn, row)
            if retry_at > time.time():
                return False
        locks = getattr(self, '_payment_view_locks', None)
        existing = locks.get(ident) if locks is not None else None
        if existing is not None and existing.locked():
            return False  # Fulfillment must not wait for a slow Telegram edit.
        token = secrets.token_hex(12)
        async with self.host.automatic_qris.payment_view_guard(self, ident):
            with self.connection(True) as conn:
                snapshot = self._order_notice_snapshot(ident, stage, conn)
                if snapshot is None:
                    conn.execute('DELETE FROM settings WHERE key=?', (key,))
                    return False
                row, native, stage = snapshot
                notice = row.setdefault('order_notice', {})
                if notice.get('lease_until', 0) > time.time():
                    return False
                notice.update(lease_owner=token, lease_until=time.time()+10)
                self.save(conn, row)
            try:
                for _ in range(2):  # Catch completion while an earlier caption was in flight.
                    with self.connection() as conn:
                        snapshot = self._order_notice_snapshot(ident, stage, conn)
                    if snapshot is None:
                        return False
                    row, native, stage = snapshot
                    notice = row['order_notice']
                    text = self.order_message_text(row, native, stage)
                    digest = hashlib.sha256(text.encode()).hexdigest()
                    target, kind = notice.get('message_id'), notice.get('kind', 'text')
                    if notice.get('chat_id') != row['user_id'] or type(target) is not int or target <= 0:
                        target = None
                    if target is None:
                        photos = [item['id'] for item in row['qr_messages'] if item['kind'] in {'QR', 'INVOICE'}
                                  and type(item['id']) is int and 0 < item['id'] <= 9223372036854775807]
                        if photos:
                            target, kind = photos[-1], 'photo'
                        else:
                            target = self.payment_view_message(row)
                            kind = 'text'
                    if target and self.setting('qr_view.'+str(row['user_id'])+'.'+str(target), None) not in (None, ident):
                        target = None
                    if target and notice.get('stage') == stage and notice.get('digest') == digest:
                        with self.connection(True) as conn:
                            self._schedule_order_notice(conn, ident, stage)
                        return True
                    if target:
                        try:
                            kind = await self._edit_order_notice(bot, row['user_id'], target, kind, text)
                        except TelegramBadRequest as exc:
                            if not self.uneditable_payment_message(exc):
                                raise
                            target = None
                    if target is None:
                        # Recheck proof/native state after an edit proved impossible.
                        with self.connection(True) as conn:
                            snapshot = self._order_notice_snapshot(ident, stage, conn)
                            if snapshot is None:
                                return False
                            row, native, stage = snapshot
                            text = self.order_message_text(row, native, stage)
                            digest = hashlib.sha256(text.encode()).hexdigest()
                            notice = row['order_notice']
                            attempts = notice.setdefault('fallbacks', {})
                            if attempts.get(stage) in {'REQUESTING', 'UNKNOWN'}:
                                self._schedule_order_notice(conn, ident, stage, unknown=True)
                                return False
                            attempts[stage] = 'REQUESTING'
                            notice.update(message_id=None, kind='text', requested_stage=stage)
                            self.save(conn, row)
                        try:
                            sent = await asyncio.wait_for(bot.send_message(row['user_id'], text, parse_mode='HTML',
                                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                                    [InlineKeyboardButton(text='🏠 Menu Utama', callback_data='home')]])), timeout=2)
                            target = getattr(sent, 'message_id', None)
                            if type(target) is not int or target <= 0:
                                raise GatewayError('TELEGRAM')
                            kind = 'text'
                        except BaseException as exc:
                            with self.connection(True) as conn:
                                current = self.transaction(ident, conn=conn)
                                state = current['order_notice']
                                if isinstance(exc, (TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter)):
                                    state.setdefault('fallbacks', {}).pop(stage, None)
                                else:
                                    state.setdefault('fallbacks', {})[stage] = 'UNKNOWN'
                                self.save(conn, current)
                            raise
                    with self.connection(True) as conn:
                        current = self.transaction(ident, conn=conn)
                        state = current['order_notice']
                        state.update(chat_id=row['user_id'], message_id=target, kind=kind, stage=stage,
                                     digest=digest, retry_at=0)
                        if state.get('fallbacks', {}).get(stage) == 'REQUESTING':
                            state['fallbacks'][stage] = 'SENT'
                        self.save(conn, current)
                        latest = self._order_notice_snapshot(ident, stage, conn)
                        if latest and latest[2] != stage:
                            stage = latest[2]
                            state['requested_stage'] = stage
                            self.save(conn, current)
                            continue
                        self._schedule_order_notice(conn, ident, stage)
                    return True
                return False
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    notice = current['order_notice']
                    notice['retry_at'] = time.time()+max(5, min(3600, float(getattr(exc, 'retry_after', 0) or 0)))
                    self.save(conn, current)
                    conn.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',
                                 (key, f"{notice['retry_at']:020.3f}"))
                logging.warning('Payinaja order notice deferred invoice=%s type=%s',ident,type(exc).__name__)
                return False
            finally:
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    notice = current.get('order_notice', {})
                    if notice.get('lease_owner') == token:
                        notice.update(lease_owner=None, lease_until=0)
                        self.save(conn, current)

    @staticmethod
    def _schedule_order_notice(conn, ident, stage, *, unknown=False):
        key = 'payinaja.notices.' + ident
        if stage == 'completed' and not unknown:
            conn.execute('DELETE FROM settings WHERE key=?', (key,))
        else:
            conn.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',
                         (key, f'{time.time()+30:020.3f}'))

    def remember_order_message(self, ident, user, message_id, kind, stage):
        """Record the caption actually acknowledged, then watch for a newer state."""
        if (type(message_id) is not int or message_id <= 0 or kind not in {'photo', 'text'}
                or stage not in {'confirmed', 'pending_stock', 'send_failed', 'completed'}):
            raise GatewayError('INPUT')
        rendered_stage = stage
        with self.connection(True) as conn:
            snapshot = self._order_notice_snapshot(ident, stage, conn)
            if snapshot is None or snapshot[0]['user_id'] != user:
                return False
            row, native, requested_stage = snapshot
            notice = row.setdefault('order_notice', {})
            text = self.order_message_text(row, native, rendered_stage)
            notice.update(version=1, chat_id=user, message_id=message_id, kind=kind, stage=rendered_stage,
                          requested_stage=requested_stage, digest=hashlib.sha256(text.encode()).hexdigest(), retry_at=0)
            self.save(conn, row)
            if requested_stage != rendered_stage:
                conn.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',
                             ('payinaja.notices.' + ident, f'{time.time():020.3f}'))
            else:
                self._schedule_order_notice(conn, ident, rendered_stage)
        return True

    async def retry_order_messages(self, bot):
        for ident in self.due_ids('notices'):
            try:
                row = self.transaction(ident)
                await self.update_order_message(bot, ident, stage=row.get('order_notice', {}).get('requested_stage', 'confirmed'))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logging.warning('Payinaja notice retry deferred invoice=%s type=%s', ident, type(exc).__name__)
                try:
                    with self.connection(True) as conn:
                        conn.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',
                                     ('payinaja.notices.'+ident, f'{time.time()+30:020.3f}'))
                except sqlite3.Error:
                    pass  # Preserve payment data even when diagnostics storage is unavailable.

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
        await self.render_payment_status(call, ident)

    async def cancel(self, call, ident, *, admin=False, nonce=None):
        if not call.message or str(call.message.chat.type) != 'private' or call.message.chat.id != call.from_user.id:
            raise GatewayError('FORBIDDEN')
        with self.connection(True) as conn:
            row = self.transaction(ident, call.from_user.id, conn=conn, admin=admin)
            already_handled = nonce is not None and (row['cancel_requested'] or row['state'] in FINAL | {'PAID_VERIFIED', 'REVIEW'})
            if nonce is not None and not already_handled:
                prompt = row.get('cancel_prompt', {})
                if (not isinstance(nonce, str) or not re.fullmatch(r'[0-9a-f]{16}', nonce) or prompt.get('actor') != call.from_user.id
                        or prompt.get('expires_at', 0) < time.time()
                        or not hmac.compare_digest(str(prompt.get('nonce', '')), nonce)):
                    raise GatewayError('CONFIRM_EXPIRED')
            if not already_handled and row['state'] not in FINAL | {'PAID_VERIFIED', 'REVIEW'} and not self.paid_proof(row):
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
        if already_handled:
            return await self.owner_detail(call, ident) if admin else await self.show_status(call, ident, refresh=False)
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
            if row['purpose'] == 'order':
                return native['payment_status'] == 'paid'
            if native['status'] != 'completed':
                return False
            wallet = conn.execute('SELECT balance FROM wallets WHERE user_id=?', (row['user_id'],)).fetchone()
            credits = conn.execute("SELECT amount FROM wallet_ledger WHERE user_id=? AND type='TOPUP' AND reference=?",
                (row['user_id'], self.host.topup_invoice(row['entity_id']))).fetchall()
            # A completed flag is not evidence that wallet credit committed.
            # Current balance may be lower after a legitimate later purchase.
            return bool(wallet and type(wallet['balance']) is int and wallet['balance'] >= 0
                        and len(credits) == 1 and type(credits[0]['amount']) is int
                        and credits[0]['amount'] == row['amount'])

    def protected_receipt_message(self, user, message_id):
        with self.connection() as conn:
            found = conn.execute("""SELECT source,entity_id FROM payment_receipts WHERE user_id=? AND message_id=?
                AND (status='SENT' OR error_code='QRIS_EDIT')""", (user, message_id)).fetchall()
            return any(self.linked(item['source'], int(item['entity_id']), conn)
                       for item in found if item['source'] in {'order', 'topup'})

    async def deliver_receipt_photo(self, bot, receipt, photo, caption):
        row = self.receipt_transaction(receipt['source'], receipt['entity_id'])
        if not row:
            raise GatewayError('NOT_READY')
        async with self.host.automatic_qris.payment_view_guard(self, row['id']):
            message = await self._deliver_receipt_photo(bot, receipt, photo, caption)
        if row['purpose'] == 'order':
            await self.update_order_message(bot, row['id'])
        return message

    async def _deliver_receipt_photo(self, bot, receipt, photo, caption):
        row = self.receipt_transaction(receipt['source'], receipt['entity_id'])
        if not row or not self.receipt_payment_confirmed(row):
            raise GatewayError('NOT_READY')
        order_stage = None
        if row['purpose'] == 'order':
            with self.connection() as conn:
                snapshot = self._order_notice_snapshot(row['id'], 'confirmed', conn)
            if snapshot is None:
                raise GatewayError('NOT_READY')
            row, native, order_stage = snapshot
            caption = self.order_message_text(row, native, order_stage)
        anchor = receipt['message_id'] if receipt['error_code'] == 'QRIS_EDIT' else None
        notice = row.get('order_notice', {})
        if (not anchor and row['purpose'] == 'order' and notice.get('chat_id') == row['user_id']
                and type(notice.get('message_id')) is int and notice['message_id'] > 0):
            anchor = notice['message_id']
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
                if order_stage is not None:
                    self.remember_order_message(row['id'], row['user_id'], anchor, 'photo', order_stage)
                return SimpleNamespace(message_id=anchor)
        with self.connection(True) as conn:
            changed = conn.execute("""UPDATE payment_receipts SET status='UNKNOWN',message_id=NULL,error_code='QRIS_SEND_STARTED'
                WHERE source=? AND entity_id=? AND lease_token=?""",
                (receipt['source'], receipt['entity_id'], receipt['lease_token'])).rowcount
            if changed != 1:
                raise GatewayError('STORAGE')
        try:
            message = await bot.send_photo(row['user_id'], photo, caption=caption, parse_mode='HTML')
            if order_stage is not None:
                self.remember_order_message(row['id'], row['user_id'], message.message_id, 'photo', order_stage)
            return message
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
            await self.host.automatic_qris.payment_verified_progress(self.host, self, ident, bot)
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

    def start_pending_media(self, ident):
        """Supervise at most three QR views without holding financial polling."""
        if self._media_closing:
            return None
        existing = self._media_jobs.get(ident)
        if existing is not None and not existing.done():
            return existing
        row = self.transaction(ident)
        if (len(self._media_jobs) >= 3 or row['state'] != 'PENDING' or row.get('qr_messages')
                or row.get('cancel_requested') or row.get('qr_send_retry_at', 0) > time.time()):
            return None

        async def run():
            try:
                await self.prepare_qr(ident)
                await self.deliver_pending_qr(ident)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.diagnostic(exc, 'image')
            finally:
                if self._media_jobs.get(ident) is asyncio.current_task():
                    self._media_jobs.pop(ident, None)

        task = asyncio.create_task(run(), name='payinaja_pending_media')
        self._media_jobs[ident] = task
        return task

    async def close_pending_media(self):
        self._media_closing = True
        jobs = list(self._media_jobs.values())
        for task in jobs:
            task.cancel()
        if jobs:
            await asyncio.gather(*jobs, return_exceptions=True)
        self._media_jobs.clear()

    async def poll_once(self):
        if self._poll_lock.locked():
            return
        async with self._poll_lock:
            async def check(ident):
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
                        await self.refresh(ident, prepare_image=False, settle_payment=False)
                    current = self.transaction(ident)
                    if current['state'] == 'PAID_VERIFIED':
                        self.host.automatic_qris.start_settlement(self, ident)
                    if (current['purpose'] == 'order' and current['state'] in {'FAILED', 'CANCELLED'}
                            and self.can_auto_deliver(current) and not current.get('terminal_notice_sent')):
                        self.terminal_notices.setdefault(ident, dict(queued_at=time.time(), retry_at=0))
                    if current['state'] == 'PENDING':
                        self.start_pending_media(ident)
                except GatewayError as exc:
                    if exc.code == 'RATE_LIMIT':
                        return False
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.diagnostic(exc, 'poll')
                return True

            await self.host.automatic_qris.poll_batch(self.due_ids('active'), check)
            await self.deliver_terminal_notices()

    async def deliver_terminal_notices(self):
        # Only views from this process are queued. Redeploy never replays old
        # failed invoices. Telegram delivery never changes financial state.
        if self.bot is None:
            return
        attempted = 0
        for ident, pending in list(self.terminal_notices.items()):
            if pending['queued_at'] + 3600 < time.time():
                self.terminal_notices.pop(ident, None)
                continue
            if pending['retry_at'] > time.time():
                continue
            if attempted >= 20:
                break
            attempted += 1
            token = secrets.token_hex(12)
            with self.connection(True) as conn:
                row = self.transaction(ident, conn=conn)
                if row['state'] not in {'FAILED', 'CANCELLED'} or row.get('terminal_notice_sent'):
                    self.terminal_notices.pop(ident, None)
                    continue
                if row.get('terminal_notice_until', 0) > time.time():
                    continue
                row.update(terminal_notice_owner=token, terminal_notice_until=time.time() + 30)
                self.save(conn, row)
            try:
                await asyncio.wait_for(self.bot.send_message(row['user_id'], self.status_text(row) +
                    '\nTagihan ini sudah ditutup oleh penyedia. Buka Belanja untuk membuat pembayaran baru.',
                    reply_markup=self.user_keyboard(row), parse_mode='HTML'), timeout=10)
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    if current.get('terminal_notice_owner') == token:
                        current['terminal_notice_sent'] = True
                        self.save(conn, current)
                self.terminal_notices.pop(ident, None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                pending['retry_at'] = time.time() + max(30, min(3600, float(getattr(exc, 'retry_after', 0) or 0)))
                self.diagnostic(GatewayError('TELEGRAM'), 'terminal_notice')
            finally:
                with self.connection(True) as conn:
                    current = self.transaction(ident, conn=conn)
                    if current.get('terminal_notice_owner') == token:
                        current.update(terminal_notice_owner=None, terminal_notice_until=0)
                        self.save(conn, current)

    async def start(self, bot):
        self.bot = bot
        if self.tasks:
            return []
        self._settlements_closing = False
        self._media_closing = False
        async def payments():
            while True:
                try:
                    await self.poll_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.diagnostic(exc, 'poll')
                await asyncio.sleep(5)
        async def cleanup():
            while True:
                try:
                    await self.retry_order_messages(bot)
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
        self._media_closing = True
        self._settlements_closing = True
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks = []
        await self.close_pending_media()
        await self.host.automatic_qris.close_settlements(self)
        await self.api.close()

    @staticmethod
    def owner_keyboard(rows):
        return InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=label, callback_data=PREFIX + 'a:' + action + (':' + str(value) if value is not None else ''))
             for label, action, value in line] for line in rows])

    async def owner_panel(self, call, *, note='', diagnostics=False):
        self.require_owner(call.from_user.id)
        proof = self.proof()
        try:
            base = urlsplit(self.config.base_url)
            base_display = (self.config.base_url if base.scheme == 'https' and base.hostname in API_HOSTS
                and base.port in {None, 443} and not base.username and not base.password
                and base.path == '/api/v1' and not base.query and not base.fragment else 'URL tidak valid (disembunyikan)')
        except (ValueError, TypeError, AttributeError):
            base_display = 'URL tidak valid (disembunyikan)'
        polling = any(not task.done() and task.get_name() == 'payinaja_payments' for task in self.tasks)
        settlement_jobs = sum(not task.done() for task in getattr(self, '_settlement_jobs', {}).values())
        with self.connection() as conn:
            active_count = conn.execute("SELECT COUNT(*) FROM settings WHERE key GLOB 'payinaja.active.*'").fetchone()[0]
        try:
            server = self.selected_server()
            _, health = self.creation_health()
            last = self.create_proof(server)
        except GatewayError:
            server, last, health = None, {}, 'CONFIG: pilihan server perlu diperbaiki.'
        last_row = (self.transaction(last['transaction_id']) if last.get('transaction_id')
                    and last.get('fingerprint') == self.fingerprint() else None)
        if last and last.get('checked_at', 0) < self.started_at:
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
                f'API Key: {"Tersedia" if self.config.key else "Belum diisi"}\n'
                'Base URL: ' + html.escape(base_display) + '\n'
                f'Server create: {server or "Periksa pengaturan"} • Sumber: {"database owner (mengalahkan ENV)" if self.setting("server", None) is not None else "ENV/default"}\n'
                'Endpoint create: ' + ({1: 'POST /qris/create', 2: 'POST /qris/create2'}.get(server, 'Periksa pilihan server')) + '\n'
                f'Batas waktu create: {self.config.create_timeout} detik\n'
                f'Izin membuat invoice: {"AKTIF" if self.enabled() else "NONAKTIF"}\n'
                f'Konfigurasi: {"Tersedia" if self.config.valid() and server is not None else "Periksa PAYINAJA_API_KEY / konfigurasi API"}\n'
                f'Autentikasi: {"Terverifikasi; merchant approved" if proof.get("approved") else "Belum terverifikasi"}\n'
                'Pemeriksaan profil terakhir: ' + (self.host.payment_receipts.format_wib(proof['checked_at'], compact=True)
                    if proof.get('checked_at') else 'Belum ada pada konfigurasi aktif') + '\n'
                f'Polling: {"Berjalan" if polling else "Belum berjalan"} • Antrean pembayaran: {active_count}\n'
                f'Settlement: {settlement_jobs} task aktif; status pengiriman produk dicatat terpisah\n'
                'Status pembuatan invoice: ' + html.escape(health) + '\n'
                'Sumber QR invoice terakhir: ' + qr_state + '\n'
                'Profil dan invoice diperiksa otomatis saat checkout. '
                'Pembayaran diverifikasi lewat API status; callback H2H tidak dipakai.\n'
                'Profil approved tidak membuktikan pembuatan QR berhasil.\n'
                'Kredensial tidak ditampilkan. Key KlikQRIS tidak dipakai untuk Payinaja.\n')
        if last:
            text += ('\nCreate terakhir: ' + html.escape(str(last.get('code') or 'UNKNOWN'))
                     + ' • HTTP: ' + str(last.get('http_status') or '-')
                     + '\nWaktu create: ' + (self.host.payment_receipts.format_wib(last['checked_at'], compact=True)
                         if last.get('checked_at') else '-')
                     + ' • ID: ' + html.escape(str(last.get('correlation_id') or '-')) + '\n')
        if proof.get('error') and not proof.get('approved'):
            text += ('\nPembayaran belum siap: ' + access_note(proof.get('error_denial'), proof.get('http_status')) +
                     '\nAktivasi hanya berhasil setelah akses API diterima; tidak ada invoice uji dibuat.\n')
        activation = self.setting('activation', {})
        checking = (activation.get('state') == 'checking' and activation.get('lease_until', 0) > time.time()
                    and activation.get('fingerprint') == self.fingerprint())
        if checking:
            text += '\n⏳ Aktivasi sedang memeriksa akses Payinaja. Pembayaran belum dinyatakan aktif.\n'
        elif activation.get('state') == 'denied' and not self.enabled():
            text += '\n❌ Percobaan aktivasi gagal. Tombol sudah diproses; akses API belum diterima.\n'
        if note:
            text += '\n' + html.escape(note[:500]) + '\n'
        hidden = 0
        for kind in ['create', 'activation', 'connection', 'checkout', 'status', 'image', 'telegram', 'cancel', 'poll', 'settlement', 'cleanup']:
            detail = last if kind == 'create' else self.setting('diagnostic.' + kind, {})
            if kind == 'create' and not detail:
                legacy = self.setting('diagnostic.create', {})
                if isinstance(legacy, dict):
                    source = legacy.get('server')
                    if source is None:
                        source = {'POST /qris/create': 1, 'POST /qris/create2': 2}.get(legacy.get('endpoint'))
                    if type(source) is int and source == server:
                        detail = legacy  # Preserve a known-route legacy failure, not creation proof.
                    elif source is None:
                        detail = dict(legacy, stage='create (server belum diketahui)')
            if not isinstance(detail, dict) or detail.get('fingerprint') != self.fingerprint():
                continue
            if detail.get('checked_at', 0) < self.started_at:
                continue  # Old diagnostics remain in storage/detail history, not the fresh process panel.
            block = ('\nTahap: ' + html.escape(str(detail['stage'])) + ' • Kode: ' + html.escape(str(detail['code'])) +
                     ' • HTTP: ' + str(detail.get('http_status') or '-') +
                     '\nWaktu: ' + self.host.payment_receipts.format_wib(detail['checked_at'], compact=True) +
                     ' • ID: ' + html.escape(detail['correlation_id']) + '\n')
            if detail.get('endpoint'):
                block += 'Request: ' + html.escape(str(detail['endpoint'])) + '\n'
            compact = block
            if detail.get('cached'):
                block += ('Sumber: cache penolakan sebelumnya; tidak ada request API baru pada pemeriksaan ini.\n'
                         'Waktu request API: ' + self.host.payment_receipts.format_wib(detail['request_checked_at'], compact=True) + '\n')
                compact += 'Sumber: cache penolakan sebelumnya.\n'
            if detail.get('denial'):
                block += access_note(detail['denial'], detail.get('http_status')) + '\n'
            if detail.get('schema'):
                block += 'Bentuk respons (tanpa nilai privat): ' + html.escape(encoded(detail['schema'])) + '\n'
            if detail.get('upstream'):
                hint = upstream_note(detail['upstream']) + '\n'
                block += hint + 'Konteks 5xx (tanpa nilai privat): ' + html.escape(encoded(detail['upstream'])) + '\n'
                compact += hint
            # Keep complete HTML blocks below Telegram's message limit. Older
            # diagnostics remain stored; they must not make the button go silent.
            if len((text + block).encode('utf-16-le')) // 2 <= 3600:
                text += block
            elif len((text + compact).encode('utf-16-le')) // 2 <= 3600:
                text += compact
            else:
                hidden += 1
        if hidden:
            text += '\nSebagian diagnosis tetap tersimpan. Detail transaksi tersedia di Riwayat.\n'
        if not diagnostics:
            status = self.setting('diagnostic.status', {})
            text = ('👑 <b>QRIS OTOMATIS • PAYINAJA</b>\n'
                    f'Versi bot: {html.escape(self.host.BOT_VERSION)} • Gateway: {ADAPTER_VERSION}\n\n'
                    f'Izin invoice: {"AKTIF" if self.enabled() else "NONAKTIF"}\n'
                    f'API Key: {"Tersedia" if self.config.key else "Belum diisi"} • Merchant: {"approved" if proof.get("approved") else "belum terverifikasi"}\n'
                    f'Server: {server or "CONFIG"} • Sumber: {"database owner (mengalahkan ENV)" if self.setting("server", None) is not None else "ENV/default"}\n'
                    f'Polling: {"Berjalan" if polling else "Belum berjalan"} • Antrean: {active_count}\n'
                    f'Settlement: {settlement_jobs} task aktif\n')
            if last:
                text += '\nCreate: ' + html.escape(str(last.get('code', '-'))) + ' • HTTP: ' + str(last.get('http_status') or '-') + '\n'
            if (isinstance(status, dict) and status.get('fingerprint') == self.fingerprint()
                    and status.get('checked_at', 0) >= self.started_at):
                text += 'Status: ' + html.escape(str(status.get('code', '-'))) + ' • HTTP: ' + str(status.get('http_status') or '-') + '\n'
                if status.get('checked_at'):
                    text += self.host.payment_receipts.format_wib(status['checked_at'], compact=True) + '\n'
            text += '\nStok pending = ditahan; SOLD hanya setelah akun terkirim.\nRincian API tersedia pada Detail Teknis.'
            if note:
                text += '\n' + html.escape(note[:250])
        controls = [[('⬅️ Ringkasan', 'menu', None)]] if diagnostics else [[('🔎 Detail Teknis', 'diagnostics', None)]]
        if checking:
            controls += [[('⏳ Memeriksa akses…', 'menu', None)], [('🔴 Batalkan Aktivasi', 'toggle', 'off')]]
        else:
            if self.enabled() and not proof.get('approved'):
                controls.append([('🔄 Verifikasi Ulang PayinAja', 'toggle', 'on')])
            label = ('🔴 Nonaktifkan' if self.enabled() else '🔄 Coba Aktifkan Kembali' if activation.get('state') == 'denied' else '🟢 Aktifkan Payinaja')
            controls.append([(label, 'toggle', 'off' if self.enabled() else 'on')])
        if proof.get('error_denial', {}).get('kind') == 'ip_restricted':
            controls.append([('🌐 Info IP Hosting', 'hosting_ip', None)])
        controls += [
            [('📊 Riwayat', 'history', '0'), ('⏳ Pending', 'pending', '0')],
            [('🔄 Rekonsiliasi', 'reconcile', None)],
            [('⚙️ Pilih Server QRIS', 'servers', None)],
            [('⚙️ Pilih Provider', 'providers', None)], [('⬅️ Pengaturan Pembayaran', 'back', None)]]
        await self.host.safe_edit_or_answer(call, text, parse_mode='HTML', reply_markup=self.owner_keyboard(controls))

    async def owner_server_menu(self, call):
        self.require_owner(call.from_user.id)
        try:
            server = str(self.selected_server())
        except GatewayError:
            server = 'belum valid'
        text = ('⚙️ <b>SERVER QRIS PAYINAJA</b>\n\nPilihan saat ini: ' + server + '\n'
                'Server 1: POST /qris/create\nServer 2: POST /qris/create2\n\n'
                'Pilihan bot disimpan dan diutamakan untuk invoice baru. Ikuti Hosting menghapus pilihan bot. '
                'Memilih server tidak membuat invoice atau mengaktifkan pembayaran. '
                'Invoice lama tetap memakai server asal dan tetap direkonsiliasi; tidak ada fallback otomatis.\n\n'
                'HTTP 500 berarti create belum berhasil. Server lain belum dijamin tersedia; '
                'QR hanya dikirim setelah API mengembalikan invoice dan sumber QR yang sah.')
        controls = [[('Gunakan Server 1', 'server', '1'), ('Gunakan Server 2', 'server', '2')],
                    [('Ikuti Hosting', 'server', 'env')], [('⬅️ QRIS Otomatis', 'menu', None)]]
        await self.host.safe_edit_or_answer(call, text, parse_mode='HTML', reply_markup=self.owner_keyboard(controls))

    async def owner_hosting_ip(self, call):
        self.require_owner(call.from_user.id)
        if (not call.message or str(call.message.chat.type) != 'private'
                or call.message.chat.id != call.from_user.id):
            raise GatewayError('FORBIDDEN')
        controls = self.owner_keyboard([[('⬅️ QRIS Otomatis', 'menu', None)]])
        await self.host.safe_edit_or_answer(call, '⏳ Mengambil info IP keluar service bot…', reply_markup=controls)
        try:
            address = await hosting_ipv4()
        except GatewayError:
            return await self.host.safe_edit_or_answer(call,
                'Info IP hosting belum tersedia. Status aktivasi dan pembayaran tidak diubah.', reply_markup=controls)
        text = ('🌐 <b>INFO IP HOSTING</b>\n\nIP keluar IPv4 ke layanan pemeriksa:\n<code>' + html.escape(address) + '</code>\n\n'
                'Alamat ini diamati dari service bot ke ipify; belum membuktikan IP yang diterima Payinaja. '
                'Rute proxy, tujuan, atau IPv6 dapat berbeda.\n\n'
                'Cocokkan pada akun Payinaja yang memakai API key aktif → Whitelist IP API Terima Pembayaran, lalu Simpan. '
                'Whitelist H2H PPOB berbeda. Jika tetap ditolak padahal cocok, minta Payinaja memeriksa aturan akses akun tersebut.\n\n'
                'Tidak ada invoice dibuat atau pengaturan pembayaran diubah.')
        return await self.host.safe_edit_or_answer(call, text, parse_mode='HTML', reply_markup=controls)

    def stock_summary(self, row):
        if row['purpose'] != 'order':
            return ''
        with self.connection() as conn:
            native = conn.execute('SELECT qty,stock_reserved,status FROM orders WHERE id=? AND user_id=?',
                                  (row['entity_id'], row['user_id'])).fetchone()
            counts = dict(conn.execute('SELECT status,COUNT(*) FROM inventory_items WHERE order_id=? GROUP BY status',
                                       (row['entity_id'],)).fetchall())
        held = (int(native['qty']) if native and native['stock_reserved'] == 1
                and native['status'] not in {'cancelled', 'expired', 'completed', 'rejected'} else 0)
        return f"Stok: {held} ditahan • {counts.get('allocated', 0)} dialokasikan • {counts.get('sold', 0)} SOLD"

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
            label = self.host.invoice(row['entity_id']) if row['purpose'] == 'order' else self.host.topup_invoice(row['entity_id'])
            text += html.escape(label) + ' • ' + self.host.rupiah(row['total_amount'] or row['amount']) + ' • ' + row['state'] + '\n'
            if pending and row['purpose'] == 'order':
                text += self.stock_summary(row) + '\n'
            controls.append([('🔎 ' + label, 'detail', ident)])
        if not keys:
            text += 'Belum ada transaksi.\n'
        elif pending:
            text += '\nDitahan belum berarti terkirim. Status provider terus diperiksa.'
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
        with self.connection() as conn:
            native = conn.execute('SELECT * FROM ' + ('orders' if row['purpose'] == 'order' else 'topups')
                + ' WHERE id=? AND user_id=?', (row['entity_id'], row['user_id'])).fetchone()
        attempt = None
        if row['purpose'] == 'order' and native:
            text += ('\nPembayaran lokal: ' + html.escape(str(native['payment_status']))
                     + '\nPengiriman akun: ' + html.escape(str(native['fulfillment_status']))
                     + '\nStatus pesanan: ' + html.escape(str(native['status']))
                     + '\nSETTLED adalah pencatatan pembayaran, bukan bukti akun sudah terkirim.')
            text += '\n' + self.stock_summary(row)
            try:
                attempt = self.host.payinaja_delivery_attempt(row['entity_id'])
            except self.host.PayinajaDeliveryUncertain:
                attempt = {'corrupt': True}
            if attempt:
                text += ('\n⚠️ Hasil pengiriman akun belum pasti. Pengiriman ulang ditahan agar tidak ganda.'
                         '\nOwner perlu mencocokkan pesan yang diterima pelanggan sebelum melanjutkan.')
        elif native:
            text += '\nStatus kredit saldo lokal: ' + html.escape(str(native['status']))
        text += '\nServer invoice: ' + str(row['server'])
        text += '\nID provider: ' + html.escape(row['provider_id'] or '-') + '\nKode: ' + html.escape(row['error'] or '-')
        checked = row.get('status_diagnostic')
        if isinstance(checked, dict) and checked.get('checked_at'):
            text += ('\nPemeriksaan status: ' + html.escape(str(checked.get('code', '-')))
                     + ' • HTTP: ' + str(checked.get('http_status') or '-')
                     + '\n' + self.host.payment_receipts.format_wib(checked['checked_at'], compact=True))
        settlement = row.get('settlement_diagnostic')
        if isinstance(settlement, dict):
            text += ('\nTahap settlement: ' + html.escape(str(settlement.get('code', '-')))
                     + '\nWaktu settlement: ' + self.host.payment_receipts.format_wib(settlement['checked_at'], compact=True)
                     + ' • ID: ' + html.escape(str(settlement.get('correlation_id', '-'))))
        text += '\nSumber QR: ' + ('tersedia' if self.has_qr(row) else 'belum tersedia')
        text += '\nPesan QR tercatat: ' + ('ada' if row['qr_messages'] else 'tidak ada')
        qr_detail = row.get('qr_diagnostic')
        if qr_detail:
            text += ('\nPemrosesan QR terakhir: ' + html.escape(qr_detail['stage']) +
                     ' • Kode: ' + html.escape(qr_detail['code']) + ' • HTTP: ' + str(qr_detail.get('http_status') or '-') +
                     '\nWaktu: ' + self.host.payment_receipts.format_wib(qr_detail['checked_at'], compact=True) +
                     ' • ID: ' + html.escape(qr_detail['correlation_id']))
            endpoint = qr_detail.get('endpoint')
            if isinstance(endpoint, str) and endpoint in {'LOCAL qris_source', 'LOCAL {qris_image}', 'GET {qris_image}'}:
                text += '\nAsal pemrosesan QR: ' + html.escape(endpoint)
            schema = qr_detail.get('schema')
            if isinstance(schema, dict):
                allowed = {
                    'qris_string': {'missing', 'invalid-type', 'blank', 'present'},
                    'qris_image_url': {'missing', 'invalid-type', 'blank', 'unsupported', 'inline',
                                       'quickchart', 'official-api', 'official-image'},
                }
                safe_schema = {key: schema[key] for key, values in allowed.items()
                               if isinstance(schema.get(key), str) and schema[key] in values}
                if safe_schema:
                    text += '\nBentuk sumber QR (tanpa nilai privat): ' + html.escape(encoded(safe_schema))
        detail = row.get('diagnostic')
        create = row.get('create_diagnostic')
        if create and (not row['error'] or not detail or create.get('correlation_id') != detail.get('correlation_id')):
            text += ('\nHasil create invoice ini: ' + html.escape(create['code']) +
                     ' • HTTP: ' + str(create.get('http_status') or '-') +
                     '\nRequest: ' + html.escape(create.get('endpoint') or '-') +
                     '\nWaktu: ' + self.host.payment_receipts.format_wib(create['checked_at'], compact=True) +
                     ' • ID: ' + html.escape(create['correlation_id']))
            if create.get('upstream'):
                text += '\n' + upstream_note(create['upstream'])
                text += '\nKonteks 5xx (tanpa nilai privat): ' + html.escape(encoded(create['upstream']))
        if detail and row['error']:
            text += ('\nTahap: ' + html.escape(detail['stage']) + ' • HTTP: ' + str(detail.get('http_status') or '-') +
                     '\nWaktu: ' + self.host.payment_receipts.format_wib(detail['checked_at'], compact=True) +
                     ' • ID: ' + html.escape(detail['correlation_id']))
            if detail.get('endpoint'):
                text += '\nRequest: ' + html.escape(detail['endpoint'])
            if detail.get('schema'):
                text += '\nBentuk respons (tanpa nilai privat): ' + html.escape(encoded(detail['schema']))
            if detail.get('upstream'):
                text += '\n' + upstream_note(detail['upstream'])
                text += '\nKonteks 5xx (tanpa nilai privat): ' + html.escape(encoded(detail['upstream']))
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
        if (row['purpose'] == 'order' and native and native['payment_status'] == 'paid'
                and native['fulfillment_status'] != 'delivered' and self.paid_proof(row)):
            controls.append([('🔎 Periksa Pengiriman Akun', 'delivery', ident)] if attempt else
                            [('📦 Lanjutkan Pengiriman', 'deliver', ident)])
        if row['state'] == 'REVIEW' and self.paid_proof(row):
            text += '\nPembayaran sah perlu penanganan owner; tidak ada saldo atau produk diproses otomatis.'
            if confirm:
                text += '\nKonfirmasi: kreditkan nominal pesanan ke saldo? Biaya provider tidak dikreditkan dan produk tidak dikirim.'
                controls.append([('✅ Konfirmasi Kredit Saldo', 'credit', ident)])
            else:
                controls.append([('💰 Pindahkan ke Saldo', 'credit_confirm', ident)])
        controls.append([('⬅️ Kembali', 'pending', '0'), ('🏠 QRIS Otomatis', 'menu', None)])
        await self.host.safe_edit_or_answer(call, text, parse_mode='HTML', reply_markup=self.owner_keyboard(controls))

    async def owner_delivery_review(self, call, ident, *, received=None):
        """Review one uncertain account chunk; never infer delivery from payment."""
        if (not call.message or str(call.message.chat.type) != 'private'
                or call.message.chat.id != call.from_user.id):
            raise GatewayError('FORBIDDEN')
        row = self.transaction(ident, call.from_user.id, admin=True)
        if row['purpose'] != 'order' or not self.paid_proof(row):
            raise GatewayError('NOT_READY')
        with self.connection() as conn:
            native = conn.execute('SELECT payment_status FROM orders WHERE id=? AND user_id=?',
                (row['entity_id'], row['user_id'])).fetchone()
            if (not native or native['payment_status'] != 'paid'
                    or not self.payment_authorized(conn, 'order', row['entity_id'], settled=True)):
                raise GatewayError('NOT_READY')
        try:
            attempt = self.host.payinaja_delivery_attempt(row['entity_id'])
        except self.host.PayinajaDeliveryUncertain:
            raise GatewayError('STORAGE') from None
        if not attempt:
            return await self.owner_detail(call, ident)
        if received is not None and type(received) is not bool:
            raise GatewayError('INPUT')
        text = ('🔎 <b>PERIKSA PENGIRIMAN AKUN</b>\n\n🧾 ' + html.escape(self.host.invoice(row['entity_id']))
                + '\nBagian akun: ' + str(attempt['chunk'] + 1)
                + '\nPembayaran sudah tercatat; hasil pengiriman bagian ini belum pasti.'
                '\nCocokkan pesan di chat pelanggan. Bot tidak dapat memastikan penerimaan dari timeout Telegram.'
                '\nPilihan ini tidak mengubah pembayaran, saldo, harga, atau akun yang dialokasikan.')
        if received is None:
            controls = [[('✅ Bagian Ini Sudah Diterima', 'drecv', ident)],
                        [('🔄 Bagian Ini Belum Terkirim', 'dnone', ident)]]
        else:
            nonce = secrets.token_hex(8)
            with self.connection(True) as conn:
                row = self.transaction(ident, call.from_user.id, admin=True, conn=conn)
                current = self.host.payinaja_delivery_attempt(row['entity_id'], conn=conn)
                if not current or current['attempt_id'] != attempt['attempt_id']:
                    raise GatewayError('CONFIRM_EXPIRED')
                row['delivery_review_prompt'] = dict(nonce=nonce, actor=call.from_user.id,
                    attempt_id=current['attempt_id'], received=received, expires_at=time.time() + 300)
                self.save(conn, row)
            text += ('\n\nKonfirmasi: bagian ini sudah diterima. Bot akan mencatat bagian ini selesai dan melanjutkan sisa pengiriman.'
                     if received else '\n\nKonfirmasi: bagian ini benar-benar belum terkirim. Bot akan mencoba bagian yang sama, memakai akun yang sudah dialokasikan.')
            controls = [[('✅ Konfirmasi Hasil Pemeriksaan', 'dconfirm', ident + '.' + nonce)]]
        controls.append([('⬅️ Detail Transaksi', 'detail', ident)])
        await self.host.safe_edit_or_answer(call, text, parse_mode='HTML', reply_markup=self.owner_keyboard(controls))

    async def confirm_delivery_review(self, call, ident, nonce):
        if (not call.message or str(call.message.chat.type) != 'private'
                or call.message.chat.id != call.from_user.id):
            raise GatewayError('FORBIDDEN')
        row = self.transaction(ident, call.from_user.id, admin=True)
        if row['purpose'] != 'order' or not self.paid_proof(row):
            raise GatewayError('NOT_READY')
        prompt = row.get('delivery_review_prompt', {})
        if (not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{16}', nonce)
                or prompt.get('actor') != call.from_user.id or prompt.get('expires_at', 0) < time.time()
                or type(prompt.get('received')) is not bool
                or not hmac.compare_digest(str(prompt.get('nonce', '')), nonce)):
            raise GatewayError('CONFIRM_EXPIRED')
        ok, reason = self.host.resolve_payinaja_delivery_attempt(row['entity_id'], call.from_user.id,
            prompt.get('attempt_id'), received=prompt['received'])
        if not ok:
            await self.host.safe_callback_notice(call,
                'Hasil belum diubah. Pengiriman masih berjalan atau konfirmasi sudah tidak berlaku.', show_alert=True)
            return await self.owner_detail(call, ident)
        with self.connection(True) as conn:
            current = self.transaction(ident, call.from_user.id, admin=True, conn=conn)
            if current.get('delivery_review_prompt', {}).get('nonce') == nonce:
                current.pop('delivery_review_prompt', None)
                self.save(conn, current)
        return await self.resume_order_delivery(call, ident)

    async def resume_order_delivery(self, call, ident):
        if (not call.message or str(call.message.chat.type) != 'private'
                or call.message.chat.id != call.from_user.id):
            raise GatewayError('FORBIDDEN')
        row = self.transaction(ident, call.from_user.id, admin=True)
        if row['purpose'] != 'order' or not self.paid_proof(row):
            raise GatewayError('NOT_READY')
        try:
            if self.host.payinaja_delivery_attempt(row['entity_id']):
                return await self.owner_delivery_review(call, ident)
        except self.host.PayinajaDeliveryUncertain:
            raise GatewayError('STORAGE') from None
        try:
            await self.host.fulfill_order(row['entity_id'], call.bot)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logging.warning('Payinaja delivery recovery deferred order=%s type=%s',row['entity_id'],type(exc).__name__)
        return await self.owner_detail(call, ident)


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
            elif action == 'servers':
                await gateway.owner_server_menu(call)
            elif action == 'server':
                if value not in {'1', '2', 'env'}:
                    raise GatewayError('INPUT')
                gateway.set_server(call.from_user.id, None if value == 'env' else int(value))
                await gateway.owner_panel(call, note='Pilihan server untuk invoice baru disimpan. Tidak ada invoice dibuat.')
            elif action == 'connect':
                await gateway.check_connection(call.from_user.id)
                await gateway.owner_panel(call, note='Profil diperiksa; tidak ada invoice dibuat.')
            elif action == 'toggle':
                if value == 'on':
                    async def progress():
                        await host.safe_edit_or_answer(call,
                            '⏳ <b>Memeriksa akses Payinaja…</b>\n\nTombol Aktifkan sudah diterima. '
                            'Bot sedang meminta profil akun; belum ada invoice dibuat.', parse_mode='HTML',
                            reply_markup=gateway.owner_keyboard([[('🔴 Batalkan Aktivasi', 'toggle', 'off')]]))
                    await gateway.activate(call.from_user.id, progress=progress)
                elif value == 'off':
                    gateway.disable(call.from_user.id)
                else:
                    raise GatewayError('INPUT')
                await gateway.owner_panel(call)
            elif action == 'diagnostics':
                await gateway.owner_panel(call, diagnostics=True)
            elif action == 'hosting_ip':
                await gateway.owner_hosting_ip(call)
            elif action in {'history', 'pending'}:
                if not value or not re.fullmatch('[0-9]{1,6}', value):
                    raise GatewayError('INPUT')
                await gateway.owner_list(call, pending=action == 'pending', page=int(value))
            elif action == 'reconcile':
                await gateway.poll_once()
                await gateway.owner_list(call, pending=True)
            elif action == 'detail':
                await gateway.owner_detail(call, value)
            elif action == 'delivery':
                await gateway.owner_delivery_review(call, value)
            elif action in {'drecv', 'dnone'}:
                await gateway.owner_delivery_review(call, value, received=action == 'drecv')
            elif action == 'dconfirm':
                bits = (value or '').split('.')
                if len(bits) != 2:
                    raise GatewayError('INPUT')
                await gateway.confirm_delivery_review(call, bits[0], bits[1])
            elif action == 'deliver':
                await gateway.resume_order_delivery(call, value)
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
            if getattr(exc, 'code', '') == 'CONFIRM_EXPIRED' and not owner and action == 'confirm':
                # An expired UI confirmation is not a failed gateway request.
                # Offer a fresh explicit confirmation; never submit a cancel here.
                try:
                    await gateway.prompt_cancel(call, (value or '').split('.')[0])
                except (GatewayError, sqlite3.Error):
                    return await host.safe_callback_notice(call, 'Konfirmasi belum dapat ditampilkan. Buka kembali invoice.', show_alert=True)
                return await host.safe_callback_notice(call,
                    'Konfirmasi diperbarui. Tekan konfirmasi baru jika ingin membatalkan; belum ada pembatalan baru diajukan.', show_alert=True)
            detail = gateway.diagnostic(exc, 'owner' if owner else 'checkout')
            text = 'Payinaja belum dapat diproses. Periksa status invoice; tagihan pengganti tidak dibuat.'
            if getattr(exc, 'code', '') == 'MIN_AMOUNT':
                text = 'Minimum pembayaran QRIS Payinaja Rp500. Pilih metode lain untuk nominal lebih kecil.'
            elif owner and getattr(exc, 'code', '') == 'AUTH':
                text = access_note(getattr(exc, 'denial', None), getattr(exc, 'http_status', 0))
            elif owner and getattr(exc, 'code', '') in {'BUSY', 'RATE_LIMIT'}:
                text = 'Pemeriksaan aktivasi sedang berjalan atau terlalu sering diminta. Tunggu sebentar.'
            elif owner and getattr(exc, 'code', '') == 'ACTIVATION_CANCELLED':
                text = 'Aktivasi dibatalkan atau digantikan permintaan terbaru. Respons lama tidak mengaktifkan pembayaran.'
            elif owner and getattr(exc, 'code', '') == 'TELEGRAM':
                text = 'Pesan aktivasi belum dapat diperbarui. Silakan coba kembali; tidak ada invoice dibuat.'
            if owner and host.is_owner(call.from_user.id):
                try:
                    await gateway.owner_panel(call, note=text + '\nKode: ' + detail['code'] + ' • ID: ' + detail['correlation_id'])
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
