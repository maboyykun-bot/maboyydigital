"""Small, fail-closed client for the documented AM send/verify endpoints.

Only safe membership evidence leaves this module. Provider messages, account
credentials, magic links, tokens and unrecognized fields are never returned.
POST requests are never retried or redirected.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import os
import re
from typing import Literal, Mapping, TypedDict
from urllib.parse import urlsplit

import aiohttp


VERSION = '17.57'
BASE_URL = 'https://am-api-service.vercel.app'
BODY_LIMIT = 256 * 1024
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 16384
MAX_PLAN_LENGTH = 120


class AMServiceError(Exception):
    """A deliberately body-free error suitable for safe application handling."""

    def __init__(self, code: str, *, http_status: int = 0,
                 uncertain: bool = False, retry_after: int = 0):
        super().__init__(code)
        self.code = code
        self.http_status = http_status
        self.uncertain = uncertain
        self.retry_after = retry_after


@dataclass(frozen=True)
class AMServiceConfig:
    enabled: bool = False
    api_key: str = field(default='', repr=False)
    timeout_seconds: int = 20
    issues: tuple[str, ...] = field(default=(), repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> 'AMServiceConfig':
        values = os.environ if env is None else env
        issues = []
        raw_enabled = values.get('AM_SERVICE_ENABLED', 'false').strip().lower()
        if raw_enabled not in {'true', 'false', '1', '0'}:
            issues.append('AM_SERVICE_ENABLED')
        enabled = raw_enabled in {'true', '1'}
        key = values.get('AM_SERVICE_API_KEY', '').strip()
        raw_timeout = values.get('AM_SERVICE_HTTP_TIMEOUT_SECONDS', '20').strip()
        timeout = 20
        if re.fullmatch(r'[0-9]{1,2}', raw_timeout) and 5 <= int(raw_timeout) <= 60:
            timeout = int(raw_timeout)
        else:
            issues.append('AM_SERVICE_HTTP_TIMEOUT_SECONDS')
        return cls(enabled=enabled, api_key=key, timeout_seconds=timeout,
                   issues=tuple(issues))

    def valid(self) -> bool:
        return (type(self.enabled) is bool and not self.issues
                and isinstance(self.api_key, str) and 1 <= len(self.api_key) <= 4096
                and all(33 <= ord(char) <= 126 for char in self.api_key)
                and type(self.timeout_seconds) is int and 5 <= self.timeout_seconds <= 60)


class SendLinkResult(TypedDict):
    accepted: bool | None
    http_status: int


class VerifyLinkResult(TypedDict):
    status: Literal['PREMIUM_ACTIVE', 'UNCONFIRMED']
    valid_until: str | None
    plan_name: str | None
    http_status: int


def _email(value: object) -> str:
    if not isinstance(value, str) or len(value) > 254 or value.count('@') != 1:
        raise AMServiceError('INVALID_EMAIL')
    local, domain = value.rsplit('@', 1)
    if (not 1 <= len(local) <= 64 or not domain or '..' in local
            or local.startswith('.') or local.endswith('.')
            or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local)):
        raise AMServiceError('INVALID_EMAIL')
    labels = domain.split('.')
    if (len(labels) < 2 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                               for label in labels)):
        raise AMServiceError('INVALID_EMAIL')
    return value.casefold()


def _magic_link(value: object) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 8192
            or any(ord(char) <= 32 or ord(char) == 127 for char in value)
            or '\\' in value):
        raise AMServiceError('INVALID_MAGIC_LINK')
    try:
        link = urlsplit(value)
        if (link.scheme != 'https' or link.username is not None or link.password is not None
                or link.port not in {None, 443} or link.fragment):
            raise ValueError
        if link.hostname == 'alightcreative.com':
            if not (link.path.startswith('/auth_action/') or link.path == '/__/auth/action'):
                raise ValueError
        elif link.hostname == 'alightcreative.page.link':
            if not link.path or link.path == '/':
                raise ValueError
        else:
            raise ValueError
    except ValueError:
        raise AMServiceError('INVALID_MAGIC_LINK') from None
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError


def _check_json_tree(data: object) -> None:
    pending = [(data, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_NODES:
            raise AMServiceError('SCHEMA', http_status=200, uncertain=True)
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)


def _response_layers(data: object, expected_email: str) -> list[dict]:
    if not isinstance(data, dict):
        raise AMServiceError('SCHEMA', http_status=200, uncertain=True)
    layers = [data]
    if 'raw' in data:
        if not isinstance(data['raw'], dict) or 'raw' in data['raw']:
            raise AMServiceError('SCHEMA', http_status=200, uncertain=True)
        layers.append(data['raw'])

    # All returned email fields must describe the requested account, even when
    # they occur inside an otherwise ignored object.
    pending = [data]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for name, value in item.items():
                if name == 'email':
                    try:
                        matches = _email(value) == expected_email
                    except AMServiceError:
                        matches = False
                    if not matches:
                        raise AMServiceError('MISMATCH', http_status=200, uncertain=True)
                elif isinstance(value, (dict, list)):
                    pending.append(value)
        elif isinstance(item, list):
            pending.extend(item)

    if 'success' not in data:
        raise AMServiceError('SCHEMA', http_status=200, uncertain=True)
    for layer in layers:
        if 'success' in layer:
            if type(layer['success']) is not bool:
                raise AMServiceError('SCHEMA', http_status=200, uncertain=True)
            if layer['success'] is not True:
                raise AMServiceError('REJECTED', http_status=200, uncertain=True)
        for name in ('error', 'errors'):
            if name in layer and layer[name] not in (None, False, '', [], {}):
                raise AMServiceError('REJECTED', http_status=200, uncertain=True)
    return layers


def _parse_expiry(value: object) -> datetime:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise AMServiceError('SCHEMA', http_status=200, uncertain=True)
    try:
        # A timezone is mandatory; a local calendar value cannot prove expiry.
        stamp = datetime.fromisoformat(value[:-1] + '+00:00' if value.endswith('Z') else value)
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError
        return stamp.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise AMServiceError('SCHEMA', http_status=200, uncertain=True) from None


def _safe_plan(layers: list[dict]) -> str | None:
    plans = []
    for layer in layers:
        if 'planName' not in layer:
            continue
        value = layer['planName']
        if (not isinstance(value, str) or not 1 <= len(value.strip()) <= MAX_PLAN_LENGTH
                or any(not char.isprintable() for char in value)
                or any(marker in value for marker in ('://', '@', '<', '>'))):
            return None
        plans.append(value.strip())
    return plans[0] if plans and len(set(plans)) == 1 else None


def _verify_result(data: dict, expected_email: str) -> VerifyLinkResult:
    layers = _response_layers(data, expected_email)
    # Membership evidence must identify the requested account in a documented
    # response layer. An unrelated nested metadata email cannot establish that.
    account_bound = any('email' in layer for layer in layers)
    active = False
    premium = False
    expiries = []
    now = datetime.now(timezone.utc)
    for layer in layers:
        for name in ('status', 'membershipStatus'):
            if name in layer:
                if not isinstance(layer[name], str):
                    raise AMServiceError('SCHEMA', http_status=200, uncertain=True)
                if layer[name] != 'PREMIUM_ACTIVE':
                    raise AMServiceError('REJECTED', http_status=200, uncertain=True)
                active = True
        if 'premium' in layer:
            if type(layer['premium']) is not bool:
                raise AMServiceError('SCHEMA', http_status=200, uncertain=True)
            if layer['premium'] is not True:
                raise AMServiceError('REJECTED', http_status=200, uncertain=True)
            premium = True
        if 'validUntil' in layer:
            stamp = _parse_expiry(layer['validUntil'])
            if stamp <= now:
                raise AMServiceError('REJECTED', http_status=200, uncertain=True)
            expiries.append(stamp)
    if expiries and any(stamp != expiries[0] for stamp in expiries[1:]):
        raise AMServiceError('SCHEMA', http_status=200, uncertain=True)
    if not (account_bound and active and premium and expiries):
        return {'status': 'UNCONFIRMED', 'valid_until': None,
                'plan_name': None, 'http_status': 200}
    return {'status': 'PREMIUM_ACTIVE',
            'valid_until': expiries[0].isoformat().replace('+00:00', 'Z'),
            'plan_name': _safe_plan(layers), 'http_status': 200}


def _retry_after(value: object) -> int:
    delay = 60
    if isinstance(value, str):
        try:
            delay = int(value)
        except ValueError:
            try:
                stamp = parsedate_to_datetime(value)
                if stamp.tzinfo is None:
                    raise ValueError
                delay = int((stamp - datetime.now(timezone.utc)).total_seconds())
            except (ValueError, TypeError, OverflowError):
                pass
    return min(86400, max(1, delay))


class AMServiceClient:
    def __init__(self, config: AMServiceConfig):
        self.config = config
        self.session: aiohttp.ClientSession | None = None

    def _ready(self) -> None:
        if self.config.enabled is not True:
            raise AMServiceError('DISABLED')
        if not self.config.valid():
            raise AMServiceError('CONFIG')

    async def close(self) -> None:
        if self.session is not None and not self.session.closed:
            await self.session.close()

    async def _request(self, path: str, body: dict) -> dict:
        self._ready()
        try:
            if self.session is None or self.session.closed:
                self.session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                    trust_env=True, cookie_jar=aiohttp.DummyCookieJar())
            async with self.session.request(
                    'POST', BASE_URL + path, json=body,
                    headers={'x-api-key': self.config.api_key, 'Accept': 'application/json'},
                    allow_redirects=False) as response:
                status = response.status
                if status == 429:
                    raise AMServiceError('RATE_LIMITED', http_status=status,
                                         retry_after=_retry_after(response.headers.get('Retry-After')))
                if status in {401, 403}:
                    raise AMServiceError('AUTH', http_status=status)
                if status == 400:
                    raise AMServiceError('BAD_REQUEST', http_status=status)
                if status == 404:
                    raise AMServiceError('NOT_FOUND', http_status=status)
                if 500 <= status <= 599:
                    raise AMServiceError('UPSTREAM', http_status=status, uncertain=True)
                if 300 <= status <= 399:
                    raise AMServiceError('REDIRECT', http_status=status, uncertain=True)
                if status != 200:
                    raise AMServiceError('HTTP', http_status=status, uncertain=not 400 <= status < 500)
                raw = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    if len(raw) + len(chunk) > BODY_LIMIT:
                        raise AMServiceError('RESPONSE_TOO_LARGE', http_status=status, uncertain=True)
                    raw.extend(chunk)
                try:
                    data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                                      parse_constant=_invalid_constant)
                except (ValueError, UnicodeError, RecursionError):
                    raise AMServiceError('INVALID_JSON', http_status=status, uncertain=True) from None
                _check_json_tree(data)
                if not isinstance(data, dict):
                    raise AMServiceError('SCHEMA', http_status=status, uncertain=True)
                return data
        except aiohttp.ClientSSLError:
            raise AMServiceError('TLS', uncertain=True) from None
        except aiohttp.ClientConnectorDNSError:
            raise AMServiceError('DNS', uncertain=True) from None
        except asyncio.TimeoutError:
            raise AMServiceError('TIMEOUT', uncertain=True) from None
        except (aiohttp.ClientError, OSError):
            raise AMServiceError('NETWORK', uncertain=True) from None

    async def send_link(self, email: str) -> SendLinkResult:
        self._ready()
        expected_email = _email(email)
        data = await self._request('/api/send-link', {'email': expected_email})
        _response_layers(data, expected_email)
        return {'accepted': True, 'http_status': 200}

    async def verify_link(self, email: str, magic_link: str) -> VerifyLinkResult:
        self._ready()
        expected_email = _email(email)
        link = _magic_link(magic_link)
        data = await self._request('/api/verify-link', {'email': expected_email, 'magicLink': link})
        return _verify_result(data, expected_email)
