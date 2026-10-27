"""SMSCode.gg v1 store. Uses the host's SQLite wallet, router and HTTP server.

Money POSTs are only replayed by the persistent reconciler with the original
body and idempotency key. No provider credentials or SMS are logged.
"""
import asyncio
import base64
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
import payment_receipts
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from urllib.parse import urlparse

import aiohttp
from aiohttp import web
from Crypto.Cipher import AES
from aiogram import F
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter
from aiogram.filters import Command
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import BufferedInputFile, CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup, LinkPreviewOptions

PREFIX = "smscode_otp:"
USER_BRAND = "MABOYY OTP STORE"
ADMIN_BRAND = "MABOYY OTP ADMIN"
TERMINAL = {"COMPLETED", "CANCELED", "EXPIRED", "FAILED"}
ACTIVE = {"ACTIVE", "OTP_RECEIVED"}
# Browsing is not a purchase authorization. Keep navigation usable for a day;
# quotes and all financial actions still validate their own expiry and owner.
NAVIGATION_ACTIONS = {"check", "read_sms", "confirm_cancel", "home", "shop", "main_menu", "balance", "help", "help_commands", "countries", "services",
                      "operators", "products", "orders", "history", "search", "admin", "admin_balance",
                      "admin_stats", "admin_profit", "admin_status", "admin_webhook", "admin_pending",
                      "admin_orders", "admin_prices_menu", "admin_prices", "admin_modes", "topup",
                      "topup_set", "topup_custom", "topup_confirm", "topup_pay", "topup_history",
                      "topup_status", "topup_back", "topup_noop"}
TEXT_MENU_ACTIONS = {"🏷️ List Produk", "🔥 Produk Populer", "⚡ Flash Sale", "🏠 Menu Utama", "🎁 Voucher",
                     "📁 Laporan Stok", "💰 Isi Saldo", "❓ Cara Order", "💬 Hubungi Owner"}
DEFINITIVE = {"UNAUTHORIZED", "FORBIDDEN", "VALIDATION_ERROR", "NO_OFFER_AVAILABLE",
              "INSUFFICIENT_BALANCE", "PROVIDER_ERROR", "NOT_FOUND"}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def integer(value, minimum=0, maximum=10**12):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise StoreError("INVALID_RESPONSE", "Nilai rupiah/ID dari provider tidak valid.")
    return value


def money(value):
    return "Rp" + f"{int(value):,}".replace(",", ".")


def escape(value):
    return html.escape(str(value or ""))


def qr_image(content):
    """Render the actual gateway QR content locally, without a third-party URL."""
    from io import BytesIO
    import qrcode
    output = BytesIO()
    qrcode.make(content).save(output, format="PNG")
    return output.getvalue()


def timestamp(value):
    if not value:
        return 0
    try:
        instant = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return instant.replace(tzinfo=timezone.utc).timestamp() if instant.tzinfo is None else instant.timestamp()
    except (ValueError, TypeError, OverflowError):
        return 0


async def bounded_body(stream, limit):
    parts, size = [], 0
    async for part in stream.iter_chunked(16384):
        size += len(part)
        if size > limit:
            raise StoreError("BODY_TOO_LARGE")
        parts.append(part)
    return b"".join(parts)


class StoreError(Exception):
    def __init__(self, code, message=None, *, uncertain=False, retry_after=0, request_id=""):
        super().__init__(code)
        self.code, self.uncertain = code, uncertain
        self.retry_after, self.request_id = retry_after, str(request_id)[:100]
        messages = {
            "UNAUTHORIZED": "Token SMSCode belum valid. Hubungi owner.",
            "FORBIDDEN": "Akses SMSCode ditolak.", "NOT_FOUND": "Pesanan/produk tidak ditemukan.",
            "INSUFFICIENT_BALANCE": "Saldo provider belum cukup. Hubungi owner.",
            "CANCEL_TOO_EARLY": "Nomor belum boleh dibatalkan. Tunggu batas waktu provider.",
            "NO_OFFER_AVAILABLE": "Stok nomor habis atau harga provider berubah.",
            "REQUEST_IN_PROGRESS": "Transaksi sedang diproses; jangan membeli ulang.",
            "IDEMPOTENCY_KEY_REUSED": "Transaksi perlu diperiksa owner; saldo tetap ditahan.",
            "RATE_LIMIT_EXCEEDED": "Provider membatasi permintaan. Coba kembali setelah jeda.",
            "TEMP_BANNED_ABUSE_GUARD": "Provider meminta jeda penggunaan.",
            "SERVICE_UNAVAILABLE": "Provider sementara tidak tersedia.",
            "NETWORK": "Koneksi provider belum memberikan hasil pasti.",
            "CONFLICT": "Status nomor belum mengizinkan tindakan ini.",
            "PROVIDER_ERROR": "Provider tidak dapat memproses permintaan.",
            "VALIDATION_ERROR": "Provider menolak parameter permintaan.",
        }
        self.public = message or messages.get(code, "Layanan OTP perlu diperiksa. Coba kembali nanti.")


@dataclass
class Config:
    token: str = ""
    base_url: str = "https://api.smscode.gg/v1"
    webhook_secret: str = ""
    webhook_url: str = ""
    enabled: bool = True
    mode: str = "percent"
    percent: str = "25"
    fixed: int = 0
    rounding: int = 100
    max_active: int = 2
    max_cost: int = 20000
    poll_seconds: int = 10
    quote_ttl: int = 60
    timeout: int = 15
    retries: int = 8
    retention_hours: int = 24
    hourly_limit: int = 60
    purchase_cooldown: int = 5
    error: str = ""

    @classmethod
    def environment(cls):
        c = cls()
        try:
            c.token = os.getenv("SMSCODE_API_TOKEN", "").strip()
            c.base_url = os.getenv("SMSCODE_API_BASE_URL", c.base_url).strip().rstrip("/")
            if c.base_url != "https://api.smscode.gg/v1":
                raise ValueError("SMSCODE_API_BASE_URL wajib https://api.smscode.gg/v1")
            c.webhook_secret = os.getenv("SMSCODE_WEBHOOK_SECRET", "").strip()
            c.webhook_url = os.getenv("SMSCODE_WEBHOOK_PUBLIC_URL", "").strip()
            if c.webhook_url and (urlparse(c.webhook_url).scheme != "https" or
                                  urlparse(c.webhook_url).path != "/webhooks/smscode/otp"):
                raise ValueError("URL webhook harus HTTPS dengan path /webhooks/smscode/otp")
            c.enabled = os.getenv("SMSCODE_OTP_ENABLED", "true").lower() in ("true", "1", "yes")
            c.mode = os.getenv("OTP_MARKUP_MODE", "percent").lower()
            c.percent = str(Decimal(os.getenv("OTP_MARKUP_PERCENT", "25")))
            if c.mode not in {"percent", "fixed", "combined"} or not Decimal(c.percent).is_finite() or not 0 <= Decimal(c.percent) <= 10000:
                raise ValueError("Mode/markup OTP tidak valid")
            for name, env, low, high in [
                ("fixed", "OTP_MARKUP_FIXED_IDR", 0, 10**9),
                ("rounding", "OTP_PRICE_ROUNDING_IDR", 0, 1000),
                ("max_active", "OTP_MAX_ACTIVE_ORDERS_PER_USER", 1, 20),
                ("max_cost", "OTP_MAX_PROVIDER_PRICE_IDR", 1, 10**9),
                ("poll_seconds", "OTP_POLL_INTERVAL_SECONDS", 10, 300),
                ("quote_ttl", "OTP_QUOTE_TTL_SECONDS", 15, 300),
                ("timeout", "OTP_HTTP_TIMEOUT_SECONDS", 3, 60),
                ("retries", "OTP_DELIVERY_MAX_RETRIES", 1, 30),
                ("retention_hours", "OTP_SMS_RETENTION_HOURS", 1, 720),
                ("hourly_limit", "OTP_MAX_PURCHASES_PER_HOUR", 1, 1000),
                ("purchase_cooldown", "OTP_PURCHASE_COOLDOWN_SECONDS", 1, 300),
            ]:
                value = int(os.getenv(env, str(getattr(c, name))))
                if not low <= value <= high:
                    raise ValueError(env + " di luar batas")
                setattr(c, name, value)
            if c.rounding not in {0, 100, 500, 1000}:
                raise ValueError("Pembulatan OTP: 0, 100, 500 atau 1000")
        except (ValueError, InvalidOperation) as exc:
            c.error, c.enabled = str(exc), False
        return c


def init_schema(conn):
    # Additive only; never replaces the existing wallet, orders or deposit tables.
    statements = [
        """CREATE TABLE IF NOT EXISTS otp_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at REAL NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS otp_pricing_rules(scope TEXT NOT NULL,scope_key TEXT NOT NULL,rule TEXT NOT NULL,
           updated_at REAL NOT NULL,PRIMARY KEY(scope,scope_key))""",
        """CREATE TABLE IF NOT EXISTS otp_quotes(quote_id TEXT PRIMARY KEY,buyer_user_id INTEGER NOT NULL,
           product TEXT NOT NULL,provider_price_idr INTEGER NOT NULL CHECK(provider_price_idr>=0),
           selling_price_idr INTEGER NOT NULL CHECK(selling_price_idr>=0),pricing_rule_snapshot TEXT NOT NULL,
           parent_order_id INTEGER,expires_at REAL NOT NULL,status TEXT NOT NULL DEFAULT 'OPEN')""",
        """CREATE TABLE IF NOT EXISTS otp_purchase_attempts(attempt_id TEXT PRIMARY KEY,quote_id TEXT NOT NULL UNIQUE,
           user_id INTEGER NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,request_body TEXT NOT NULL,request_hash TEXT NOT NULL,
           state TEXT NOT NULL,provider_order_id INTEGER UNIQUE,hold_idr INTEGER NOT NULL CHECK(hold_idr>=0),
           created_at REAL NOT NULL,updated_at REAL NOT NULL,next_retry_at REAL NOT NULL DEFAULT 0,
           retries INTEGER NOT NULL DEFAULT 0,lease_owner TEXT,lease_until REAL NOT NULL DEFAULT 0,error_code TEXT)""",
        """CREATE TABLE IF NOT EXISTS otp_payments(payment_id TEXT PRIMARY KEY,quote_id TEXT NOT NULL UNIQUE,
           user_id INTEGER NOT NULL,method TEXT NOT NULL,state TEXT NOT NULL,amount_idr INTEGER NOT NULL CHECK(amount_idr>0),
           payment_total_idr INTEGER NOT NULL CHECK(payment_total_idr>=amount_idr),topup_id INTEGER UNIQUE,
           partner_reference TEXT NOT NULL UNIQUE,qr_url TEXT NOT NULL DEFAULT '',qr_payload TEXT NOT NULL DEFAULT '',qr_message_id INTEGER,
           qr_delivery_state TEXT NOT NULL DEFAULT 'PENDING',attempt_id TEXT UNIQUE,created_at REAL NOT NULL,
           expires_at REAL NOT NULL,paid_at REAL,updated_at REAL NOT NULL,next_retry_at REAL NOT NULL DEFAULT 0,
           retries INTEGER NOT NULL DEFAULT 0,error_code TEXT,lease_owner TEXT,lease_until REAL NOT NULL DEFAULT 0)""",
        """CREATE TABLE IF NOT EXISTS otp_orders(id INTEGER PRIMARY KEY AUTOINCREMENT,buyer_user_id INTEGER NOT NULL,
           provider_order_id INTEGER NOT NULL UNIQUE,parent_order_id INTEGER,attempt_id TEXT NOT NULL UNIQUE,
           country_id INTEGER,platform_id INTEGER,operator_id INTEGER,product_id INTEGER,catalog_product_id INTEGER,
           country_name TEXT NOT NULL,platform_name TEXT NOT NULL,operator_name TEXT NOT NULL,phone_number TEXT NOT NULL,
           provider_cost_idr INTEGER NOT NULL CHECK(provider_cost_idr>=0),selling_price_idr INTEGER NOT NULL CHECK(selling_price_idr>=0),
           gross_profit_idr INTEGER NOT NULL,status TEXT NOT NULL,created_at REAL NOT NULL,expires_at TEXT,
           updated_at REAL NOT NULL,completed_at REAL,last_sms_revision INTEGER NOT NULL DEFAULT 0,
           idempotency_key TEXT NOT NULL UNIQUE,capabilities TEXT NOT NULL DEFAULT '{}',refund_idr INTEGER NOT NULL DEFAULT 0,
           refund_state TEXT NOT NULL DEFAULT 'NONE',provider_refund_idr INTEGER NOT NULL DEFAULT 0,
           next_poll_at REAL NOT NULL DEFAULT 0)""",
        """CREATE TABLE IF NOT EXISTS otp_sms_events(provider_order_id INTEGER NOT NULL,sms_revision INTEGER NOT NULL,
           encrypted_payload TEXT NOT NULL,received_at REAL NOT NULL,source TEXT NOT NULL,
           PRIMARY KEY(provider_order_id,sms_revision))""",
        """CREATE TABLE IF NOT EXISTS otp_notifications(notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
           dedup_key TEXT NOT NULL UNIQUE,order_id INTEGER NOT NULL,provider_order_id INTEGER NOT NULL,
           sms_revision INTEGER NOT NULL,user_id INTEGER NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'PENDING',
           attempts INTEGER NOT NULL DEFAULT 0,next_retry_at REAL NOT NULL DEFAULT 0,sent_at REAL,
           lease_owner TEXT,lease_until REAL NOT NULL DEFAULT 0,error_code TEXT,telegram_message_id INTEGER,
           part_index INTEGER NOT NULL DEFAULT 0)""",
        """CREATE TABLE IF NOT EXISTS otp_webhook_inbox(digest TEXT PRIMARY KEY,provider_order_id INTEGER NOT NULL,
           encrypted_payload TEXT NOT NULL,created_at REAL NOT NULL,status TEXT NOT NULL DEFAULT 'PENDING')""",
        """CREATE TABLE IF NOT EXISTS otp_actions(id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER NOT NULL,
           action TEXT NOT NULL,state TEXT NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL,
           response TEXT,error_code TEXT,lease_owner TEXT,lease_until REAL NOT NULL DEFAULT 0,next_retry_at REAL NOT NULL DEFAULT 0)""",
        """CREATE TABLE IF NOT EXISTS otp_callback_tokens(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,
           action TEXT NOT NULL,payload TEXT NOT NULL,expires_at REAL NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS otp_rate_limits(user_id INTEGER NOT NULL,action TEXT NOT NULL,
           window REAL NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(user_id,action))""",
        """CREATE TABLE IF NOT EXISTS otp_worker_leases(name TEXT PRIMARY KEY,owner TEXT NOT NULL,until_ts REAL NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS idx_otp_user_orders ON otp_orders(buyer_user_id,status,created_at)",
        "CREATE INDEX IF NOT EXISTS idx_otp_attempt_due ON otp_purchase_attempts(state,next_retry_at,lease_until)",
        "CREATE INDEX IF NOT EXISTS idx_otp_payment_due ON otp_payments(state,next_retry_at,lease_until)",
        "CREATE INDEX IF NOT EXISTS idx_otp_user_payments ON otp_payments(user_id,created_at)",
        "CREATE INDEX IF NOT EXISTS idx_otp_notification_due ON otp_notifications(status,next_retry_at,lease_until)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_otp_action_pending ON otp_actions(order_id) WHERE state IN ('REQUESTING','PENDING_RECONCILIATION')",
    ]
    for statement in statements:
        conn.execute(statement)
    # A restart after a partially deployed 16.78 remains additive/idempotent.
    if "provider_refund_idr" not in {row[1] for row in conn.execute("PRAGMA table_info(otp_orders)")}:
        conn.execute("ALTER TABLE otp_orders ADD COLUMN provider_refund_idr INTEGER NOT NULL DEFAULT 0")
    if "qr_payload" not in {row[1] for row in conn.execute("PRAGMA table_info(otp_payments)")}:
        conn.execute("ALTER TABLE otp_payments ADD COLUMN qr_payload TEXT NOT NULL DEFAULT ''")
    if "shop_refund_policy" not in {row[1] for row in conn.execute("PRAGMA table_info(otp_payments)")}:
        conn.execute("ALTER TABLE otp_payments ADD COLUMN shop_refund_policy INTEGER NOT NULL DEFAULT 0")


class APIClient:
    def __init__(self, config):
        self.config, self.session = config, None
        self.last_ok, self.last_error, self.blocked_until, self.last_request_id = 0, "", 0, ""

    async def request(self, method, path, *, params=None, body=None, key=None):
        if not self.config.token or self.config.error:
            raise StoreError("NOT_CONFIGURED", "Toko OTP belum dikonfigurasi owner.")
        if time.time() < self.blocked_until:
            raise StoreError("RATE_LIMIT_EXCEEDED", retry_after=self.blocked_until-time.time(), uncertain=method != "GET")
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.config.timeout), trust_env=True)
        headers = {"Authorization": "Bearer " + self.config.token, "Accept": "application/json"}
        if key:
            headers["Idempotency-Key"] = key
        try:
            async with self.session.request(method, self.config.base_url + path, params=params, json=body,
                                            headers=headers, allow_redirects=False) as response:
                request_id = response.headers.get("X-Request-Id", "")
                self.last_request_id = request_id[:100]
                try:
                    retry = min(86400, max(0, float(response.headers.get("Retry-After", "0"))))
                except ValueError:
                    retry = 0
                if response.status in (429, 503):
                    self.blocked_until = time.time() + max(retry, 10)
                try:
                    raw = await bounded_body(response.content, 1024*1024)
                except StoreError:
                    raise StoreError("INVALID_RESPONSE", uncertain=method != "GET") from None
                try:
                    result = json.loads(raw)
                except (ValueError, UnicodeDecodeError):
                    raise StoreError("INVALID_RESPONSE", uncertain=method != "GET")
                if not isinstance(result, dict):
                    raise StoreError("INVALID_RESPONSE", uncertain=method != "GET")
                if response.status < 200 or response.status >= 300 or result.get("success") is not True:
                    error = result.get("error") or {}
                    code = str(error.get("code") or "INVALID_RESPONSE") if isinstance(error, dict) else "INVALID_RESPONSE"
                    raise StoreError(code, uncertain=method != "GET" and code not in DEFINITIVE,
                                     retry_after=retry, request_id=request_id)
                if "data" not in result:
                    raise StoreError("INVALID_RESPONSE", uncertain=method != "GET")
                self.last_ok, self.last_error = time.time(), ""
                return result["data"]
        except StoreError as exc:
            self.last_error = exc.code
            request_id = re.sub(r"[^A-Za-z0-9_.:-]", "", exc.request_id)[:80]
            logging.warning("SMSCode API error code=%s request_id=%s", exc.code, request_id or "-")
            raise
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
            self.last_error = "NETWORK"
            raise StoreError("NETWORK", uncertain=method != "GET") from None

    async def close(self):
        if self.session is not None:
            await self.session.close()


class Repository:
    def __init__(self, host):
        self.host = host

    @contextmanager
    def connection(self, write=False):
        conn = self.host.db()
        try:
            if write:
                # Stronger durability only for OTP writes; host transaction logic
                # and database engine remain unchanged.
                conn.execute("PRAGMA synchronous=FULL")
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            if write:
                conn.commit()
        except BaseException:
            if write:
                conn.rollback()
            raise
        finally:
            conn.close()

    def one(self, sql, params=()):
        with self.connection() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def rows(self, sql, params=()):
        with self.connection() as conn:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]

    def execute(self, sql, params=()):
        with self.connection(True) as conn:
            return conn.execute(sql, params).rowcount

    def owned(self, user, order_id):
        try:
            order_id = int(order_id)
        except (ValueError, TypeError):
            raise StoreError("NOT_FOUND") from None
        row = self.one("SELECT * FROM otp_orders WHERE id=? AND buyer_user_id=?", (order_id, user))
        if not row:
            raise StoreError("NOT_FOUND")
        return row

    def rate(self, user, action, count=10, seconds=60):
        now = time.time()
        with self.connection(True) as conn:
            row = conn.execute("SELECT * FROM otp_rate_limits WHERE user_id=? AND action=?", (user, action)).fetchone()
            new_window = not row or now-row["window"] >= seconds
            hits = 1 if new_window else row["count"]+1
            if hits > count:
                raise StoreError("COOLDOWN", "Terlalu banyak permintaan. Tunggu sebentar.")
            conn.execute("INSERT OR REPLACE INTO otp_rate_limits VALUES(?,?,?,?)",
                         (user, action, now if new_window else row["window"], hits))


class WalletAdapter:
    @staticmethod
    def change(conn, user, kind, amount, reference):
        previous = conn.execute("SELECT id FROM wallet_ledger WHERE user_id=? AND type=? AND reference=?",
                                (user, kind, reference)).fetchone()
        if previous:
            return False
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute("INSERT OR IGNORE INTO wallets(user_id,balance,updated_at) VALUES(?,0,?)", (user, now))
        old = conn.execute("SELECT balance FROM wallets WHERE user_id=?", (user,)).fetchone()[0]
        new = old + amount
        if new < 0:
            raise StoreError("USER_BALANCE", "Saldo kamu tidak cukup. Isi saldo melalui menu deposit yang tersedia.")
        integer(new)
        conn.execute("UPDATE wallets SET balance=?,updated_at=? WHERE user_id=?", (new, now, user))
        conn.execute("""INSERT INTO wallet_ledger(user_id,type,amount,balance_after,reference,note,created_at)
                     VALUES(?,?,?,?,?,'SMSCode OTP',?)""", (user, kind, amount, new, reference, now))
        return True


class PricingService:
    def __init__(self, store):
        self.store = store

    def calculate(self, product, cost=None):
        cost = integer(product.get("price") if cost is None else cost)
        settings = self.store.settings()
        rule = {"mode": settings["mode"], "percent": settings["percent"], "fixed": settings["fixed"]}
        scopes = [("product", str(product["id"])),
                  ("country_service", f"{product.get('country_id')}:{product.get('platform_id')}"),
                  ("service", str(product.get("platform_id"))), ("country", str(product.get("country_id")))]
        scope = "global"
        for kind, key in scopes:
            found = self.store.repo.one("SELECT rule FROM otp_pricing_rules WHERE scope=? AND scope_key=?", (kind, key))
            if found:
                rule, scope = json.loads(found["rule"]), kind + ":" + key
                break
        if "sale" in rule:
            sale = integer(rule["sale"])
        else:
            base = Decimal(cost)
            if rule["mode"] in {"percent", "combined"}:
                base *= 1 + Decimal(str(rule.get("percent", "0")))/100
            if rule["mode"] in {"fixed", "combined"}:
                base += integer(rule.get("fixed", 0))
            sale = int(base.to_integral_value(rounding=ROUND_CEILING))
        rounding = settings["rounding"]
        if rounding:
            sale = ((sale + rounding - 1)//rounding)*rounding
        integer(sale)
        if sale < cost and not settings["allow_loss"]:
            raise StoreError("BELOW_COST", "Harga jual berada di bawah modal; owner perlu memperbarui harga.")
        snapshot = {"scope": scope, "rule": rule, "rounding": rounding, "allow_loss": settings["allow_loss"]}
        return sale, encoded(snapshot)


class CatalogService:
    def __init__(self, store):
        self.store = store

    async def listing(self, path, params=None):
        rows = await self.store.api.request("GET", path, params=params)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise StoreError("INVALID_RESPONSE")
        return rows

    @staticmethod
    def named_rows(rows, *, operators=False):
        valid, seen = [], set()
        field = "operator_id" if operators else "id"
        for row in rows:
            if (row.get("active") is False if operators else row.get("active") is not True):
                continue
            if field not in row:
                continue
            ident = row[field]
            try:
                if ident is not None or not operators:
                    integer(ident, 1)
            except StoreError:
                continue
            if operators:
                # Official operator names may be null. Keep the carrier ID so
                # carrier-specific stock remains reachable.
                name = next((row[key].strip() for key in ("name", "local_name", "code")
                             if isinstance(row.get(key), str) and row[key].strip()),
                            "Any" if ident is None else f"Operator #{ident}")
                row = {**row, "name": name}
            elif not isinstance(row.get("name"), str) or not row["name"].strip():
                continue
            if ident not in seen:
                valid.append(row)
                seen.add(ident)
        return valid

    async def products(self, country, platform, operator=None, page=1, *, limit=50):
        params = {"country_id": country, "platform_id": platform, "page": page, "limit": limit, "sort": "price_asc"}
        if operator is not None:
            params["operator_id"] = operator
        raw = await self.listing("/catalog/products", params)
        rows = []
        for row in raw:
            if row.get("active") is not True:
                continue
            try:
                for field in ("id", "catalog_product_id", "country_id", "platform_id", "available"):
                    integer(row.get(field), 1)
                integer(row.get("price"))
                if row.get("operator_id") is not None:
                    integer(row["operator_id"], 1)
            except StoreError:
                continue
            if (row["country_id"] == country and row["platform_id"] == platform
                    and row.get("operator_id") == operator):
                rows.append(row)
        return rows, len(raw) >= limit

    async def live_product(self, product):
        if not isinstance(product, dict):
            raise StoreError("INVALID_RESPONSE")
        for field in ("id", "catalog_product_id", "country_id", "platform_id"):
            integer(product.get(field), 1)
        if product.get("operator_id") is not None:
            integer(product["operator_id"], 1)
        for page in range(1, 201):
            rows, more = await self.products(product["country_id"], product["platform_id"], product.get("operator_id"), page)
            for row in rows:
                if row["id"] == product["id"] and row["catalog_product_id"] == product["catalog_product_id"]:
                    return {**product, **row}
            if not more:
                break
        raise StoreError("NO_OFFER_AVAILABLE")


class PurchaseService:
    def __init__(self, store):
        self.store = store

    async def quote(self, user, product, parent=None):
        self.store.require_ready()
        if parent:
            current = await self.store.api.request("GET", f"/orders/{parent['provider_order_id']}")
            if current.get("can_reactivate") is not True:
                raise StoreError("CONFLICT", "Nomor ini belum mendukung reaktivasi.")
            options = await self.store.api.request("GET", f"/orders/{parent['provider_order_id']}/reactivate-options")
            cost = integer(options.get("cost"))
        else:
            product = await self.store.catalog.live_product(product)
            cost = integer(product["price"])
        if cost > self.store.config.max_cost:
            raise StoreError("PRICE_LIMIT", "Modal nomor melebihi batas toko.")
        sale, rule = self.store.pricing.calculate(product, cost)
        quote_id = secrets.token_urlsafe(12)
        self.store.repo.execute("""INSERT INTO otp_quotes(quote_id,buyer_user_id,product,provider_price_idr,
               selling_price_idr,pricing_rule_snapshot,parent_order_id,expires_at) VALUES(?,?,?,?,?,?,?,?)""",
               (quote_id, user, encoded(product), cost, sale, rule, parent["id"] if parent else None,
                time.time()+self.store.config.quote_ttl))
        return self.store.repo.one("SELECT * FROM otp_quotes WHERE quote_id=?", (quote_id,))

    async def revalidate(self, user, quote):
        quote_id = quote["quote_id"]
        product = json.loads(quote["product"])
        parent = self.store.repo.owned(user, quote["parent_order_id"]) if quote["parent_order_id"] else None
        if parent:
            current = await self.store.api.request("GET", f"/orders/{parent['provider_order_id']}")
            if current.get("can_reactivate") is not True:
                raise StoreError("CONFLICT")
            fresh = await self.store.api.request("GET", f"/orders/{parent['provider_order_id']}/reactivate-options")
            cost = integer(fresh.get("cost"))
        else:
            fresh = await self.store.catalog.live_product(product)
            cost = integer(fresh["price"])
        sale, rule = self.store.pricing.calculate(product, cost)
        if cost > self.store.config.max_cost:
            raise StoreError("PRICE_LIMIT")
        if cost != quote["provider_price_idr"] or sale != quote["selling_price_idr"] or rule != quote["pricing_rule_snapshot"]:
            self.store.repo.execute("UPDATE otp_quotes SET status='PRICE_CHANGED' WHERE quote_id=? AND status IN ('OPEN','PAYMENT_PENDING')", (quote_id,))
            raise StoreError("PRICE_CHANGED", "Harga berubah. Pilih kembali produk untuk menyetujui harga terbaru.")
        body = {"id": parent["provider_order_id"], "max_price": cost} if parent else {
            "catalog_product_id": product["catalog_product_id"], "quantity": 1, "max_price": cost}
        if not parent and product.get("operator_id") is not None:
            body["operator_id"] = product["operator_id"]
        return body

    async def buy(self, user, quote_id, *, payment_id=None):
        self.store.payments.require_checkout(user)
        quote = self.store.repo.one("SELECT * FROM otp_quotes WHERE quote_id=? AND buyer_user_id=?", (quote_id, user))
        if not quote:
            raise StoreError("NOT_FOUND")
        existing = self.store.repo.one("SELECT * FROM otp_purchase_attempts WHERE quote_id=?", (quote_id,))
        if existing:
            return existing
        funded = self.store.payments.owned(user, payment_id) if payment_id else None
        if funded:
            if funded["quote_id"] != quote_id or funded["state"] != "PAID" or quote["status"] != "PAYMENT_PENDING":
                raise StoreError("PAYMENT_PENDING")
        elif quote["status"] == "PAYMENT_PENDING":
            raise StoreError("PAYMENT_PENDING")
        elif quote["status"] != "OPEN" or quote["expires_at"] <= time.time():
            raise StoreError("QUOTE_EXPIRED", "Konfirmasi harga kedaluwarsa. Pilih produk lagi.")
        body = await self.revalidate(user, quote)
        sale = quote["selling_price_idr"]
        attempt_id, key, now = secrets.token_urlsafe(18), secrets.token_hex(24), time.time()
        with self.store.repo.connection(True) as conn:
            duplicate = conn.execute("SELECT * FROM otp_purchase_attempts WHERE quote_id=?", (quote_id,)).fetchone()
            if duplicate:
                return dict(duplicate)
            settings = self.store.settings(conn)
            if not settings["enabled"]:
                raise StoreError("DISABLED", "Pembelian baru sedang ditutup owner.")
            live_quote = conn.execute("SELECT * FROM otp_quotes WHERE quote_id=?", (quote_id,)).fetchone()
            if funded:
                payment = conn.execute("SELECT * FROM otp_payments WHERE payment_id=? AND user_id=? AND quote_id=?",
                                       (payment_id, user, quote_id)).fetchone()
                if not payment or payment["state"] != "PAID" or payment["amount_idr"] != sale or live_quote["status"] != "PAYMENT_PENDING":
                    raise StoreError("PAYMENT_PENDING")
            elif live_quote["status"] == "PAYMENT_PENDING":
                raise StoreError("PAYMENT_PENDING")
            elif live_quote["status"] != "OPEN" or live_quote["expires_at"] <= now:
                raise StoreError("QUOTE_EXPIRED", "Konfirmasi kedaluwarsa. Pilih produk lagi.")
            active = conn.execute("SELECT count(*) FROM otp_orders WHERE buyer_user_id=? AND status IN ('ACTIVE','OTP_RECEIVED')", (user,)).fetchone()[0]
            pending = conn.execute("SELECT count(*) FROM otp_purchase_attempts WHERE user_id=? AND state IN ('RESERVED','REQUESTING','PENDING_RECONCILIATION')", (user,)).fetchone()[0]
            if active + pending >= settings["max_active"]:
                raise StoreError("ORDER_LIMIT", "Batas pesanan aktif tercapai. Selesaikan pesanan sebelumnya.")
            recent = conn.execute("SELECT count(*) FROM otp_purchase_attempts WHERE user_id=? AND created_at>?", (user, now-3600)).fetchone()[0]
            latest = conn.execute("SELECT max(created_at) FROM otp_purchase_attempts WHERE user_id=?", (user,)).fetchone()[0]
            if recent >= settings["hourly_limit"] or latest and now-latest < settings["purchase_cooldown"]:
                raise StoreError("COOLDOWN", "Batas/jeda pembelian tercapai. Tunggu sebelum membeli lagi.")
            if funded:
                # Move the payment hold to the existing purchase hold in the
                # same transaction. No available-wallet window or second debit.
                WalletAdapter.change(conn, user, "OTP_QRIS_RESERVE_RELEASE", sale, "OTPQRIS:"+payment_id)
            WalletAdapter.change(conn, user, "OTP_HOLD", -sale, "OTP:"+attempt_id)
            conn.execute("""INSERT INTO otp_purchase_attempts(attempt_id,quote_id,user_id,idempotency_key,request_body,
                 request_hash,state,hold_idr,created_at,updated_at) VALUES(?,?,?,?,?,?,'RESERVED',?,?,?)""",
                 (attempt_id, quote_id, user, key, encoded(body), hashlib.sha256(encoded(body).encode()).hexdigest(), sale, now, now))
            conn.execute("UPDATE otp_quotes SET status='RESERVED' WHERE quote_id=?", (quote_id,))
            if funded:
                conn.execute("UPDATE otp_payments SET state='BUYING',attempt_id=?,updated_at=? WHERE payment_id=?",
                             (attempt_id, now, payment_id))
        await self.process(attempt_id)
        return self.store.repo.one("SELECT * FROM otp_purchase_attempts WHERE attempt_id=?", (attempt_id,))

    async def process(self, attempt_id):
        owner, now = secrets.token_hex(12), time.time()
        with self.store.repo.connection(True) as conn:
            row = conn.execute("SELECT * FROM otp_purchase_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
            if not row or row["state"] not in {"RESERVED", "REQUESTING", "PENDING_RECONCILIATION"} or row["lease_until"] > now or row["next_retry_at"] > now:
                return
            attempt = dict(row)
            quote = dict(conn.execute("SELECT * FROM otp_quotes WHERE quote_id=?", (row["quote_id"],)).fetchone())
            conn.execute("UPDATE otp_purchase_attempts SET state='REQUESTING',lease_owner=?,lease_until=?,updated_at=? WHERE attempt_id=?",
                         (owner, now+self.store.config.timeout+30, now, attempt_id))
        try:
            if hashlib.sha256(attempt["request_body"].encode()).hexdigest() != attempt["request_hash"]:
                raise StoreError("REQUEST_HASH", uncertain=True)
            data = await self.store.api.request("POST", "/orders/reactivate" if quote["parent_order_id"] else "/orders/create",
                       body=json.loads(attempt["request_body"]), key=attempt["idempotency_key"])
            self.capture(attempt, quote, data, owner)
        except StoreError as exc:
            if exc.code in DEFINITIVE and not exc.uncertain and attempt["state"] == "RESERVED":
                # A definitive first response confirms no order. An uncertain prior
                # attempt must never be released based on a later generic error.
                self.release(attempt, exc.code, owner)
            else:
                self.defer(attempt, owner, exc.code, exc.retry_after)
        except (sqlite3.Error, ValueError, TypeError, KeyError):
            self.defer(attempt, owner, "LOCAL_PERSISTENCE_OR_RESPONSE", 30)

    def capture(self, attempt, quote, data, owner):
        orders = data.get("orders") if isinstance(data, dict) else None
        if not isinstance(orders, list) or len(orders) != 1 or not isinstance(orders[0], dict):
            if orders == [] and data.get("failed_count") == 1:
                raise StoreError("PROVIDER_ERROR")
            raise StoreError("INVALID_RESPONSE", uncertain=True)
        order, product = orders[0], json.loads(quote["product"])
        provider_id, cost = integer(order.get("id"), 1), integer(order.get("amount"))
        number = order.get("phone_number")
        if cost > quote["provider_price_idr"] or not isinstance(number, str) or not re.fullmatch(r"\+?[0-9]{5,20}", number):
            raise StoreError("INVALID_RESPONSE", uncertain=True)
        if order.get("catalog_product_id") != product["catalog_product_id"] or order.get("operator_id") != product.get("operator_id") or order.get("status") not in ACTIVE:
            raise StoreError("INVALID_RESPONSE", uncertain=True)
        if quote["parent_order_id"]:
            parent = self.store.repo.owned(attempt["user_id"], quote["parent_order_id"])
            if number != parent["phone_number"] or provider_id == parent["provider_order_id"]:
                raise StoreError("INVALID_RESPONSE", uncertain=True)
        sale, now, reference = quote["selling_price_idr"], time.time(), "OTP:"+attempt["attempt_id"]
        with self.store.repo.connection(True) as conn:
            current = conn.execute("SELECT * FROM otp_purchase_attempts WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()
            if current["state"] == "CAPTURED":
                return
            if current["lease_owner"] != owner or current["state"] != "REQUESTING":
                raise StoreError("LEASE_LOST", uncertain=True)
            cursor = conn.execute("""INSERT INTO otp_orders(buyer_user_id,provider_order_id,parent_order_id,attempt_id,
                 country_id,platform_id,operator_id,product_id,catalog_product_id,country_name,platform_name,operator_name,
                 phone_number,provider_cost_idr,selling_price_idr,gross_profit_idr,status,created_at,expires_at,updated_at,
                 idempotency_key,capabilities) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                 (attempt["user_id"], provider_id, quote["parent_order_id"], attempt["attempt_id"], product.get("country_id"),
                  product.get("platform_id"), product.get("operator_id"), integer(order.get("product_id"), 1),
                  product["catalog_product_id"], product.get("country_name", ""), product.get("platform_name", ""),
                  product.get("operator_name") or "Any", number, cost, sale, sale-cost, order["status"], now,
                  order.get("expires_at"), now, attempt["idempotency_key"], self.store.capabilities(order)))
            WalletAdapter.change(conn, attempt["user_id"], "OTP_CAPTURE_RELEASE", sale, reference)
            WalletAdapter.change(conn, attempt["user_id"], "PURCHASE", -sale, reference)
            conn.execute("UPDATE otp_purchase_attempts SET state='CAPTURED',provider_order_id=?,updated_at=?,lease_until=0,lease_owner=NULL WHERE attempt_id=?",
                         (provider_id, now, attempt["attempt_id"]))
            conn.execute("UPDATE otp_quotes SET status='CAPTURED' WHERE quote_id=?", (quote["quote_id"],))
            self.store.queue(conn, cursor.lastrowid, provider_id, attempt["user_id"], "PURCHASE", 0)
        # Inbox deliveries that arrived before this mapping are processed by worker.

    def release(self, attempt, code, owner):
        with self.store.repo.connection(True) as conn:
            row = conn.execute("SELECT * FROM otp_purchase_attempts WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()
            if row["state"] == "CAPTURED" or row["lease_owner"] != owner:
                return
            WalletAdapter.change(conn, row["user_id"], "OTP_RELEASE", row["hold_idr"], "OTP:"+row["attempt_id"])
            conn.execute("UPDATE otp_purchase_attempts SET state='FAILED',error_code=?,lease_until=0,lease_owner=NULL,updated_at=? WHERE attempt_id=?",
                         (code, time.time(), row["attempt_id"]))
            conn.execute("UPDATE otp_quotes SET status='FAILED' WHERE quote_id=?", (row["quote_id"],))

    def defer(self, attempt, owner, code, retry):
        delay = max(retry, min(3600, 10*2**min(attempt["retries"], 8)))
        self.store.repo.execute("""UPDATE otp_purchase_attempts SET state='PENDING_RECONCILIATION',error_code=?,
            retries=retries+1,next_retry_at=?,lease_owner=NULL,lease_until=0,updated_at=? WHERE attempt_id=? AND lease_owner=?""",
            (code, time.time()+delay, time.time(), attempt["attempt_id"], owner))


class PaymentService:
    """Shared manual-QRIS funding lifecycle; original gateway recovery is kept.

    Subclasses only select their quote/attempt tables and notifications. All
    money still uses the host's topups, owner approval and existing wallet.
    SQL identifiers below are class constants, never callback/user input.
    """
    table = "otp_payments"
    quote_table, quote_user, quote_state, quote_sale = "otp_quotes", "buyer_user_id", "status", "selling_price_idr"
    attempt_table, success_state = "otp_purchase_attempts", "CAPTURED"
    wallet_prefix, receipt_source = "OTP", "otp_payment"
    order_table, order_user, brand, subject = 'otp_orders', 'buyer_user_id', USER_BRAND, 'nomor'
    error_class, errors = StoreError, (StoreError,)
    wallet_change = staticmethod(WalletAdapter.change)

    def __init__(self, store):
        self.store = store

    def owned(self, user, payment_id):
        row = self.store.repo.one(f"SELECT * FROM {self.table} WHERE payment_id=? AND user_id=?", (payment_id, user))
        if not row:
            raise self.error_class("NOT_FOUND")
        return row

    @staticmethod
    def queue_notice(conn, payment):
        conn.execute("""INSERT OR IGNORE INTO otp_notifications(dedup_key,order_id,provider_order_id,sms_revision,user_id,kind)
            VALUES(?,0,0,0,?,'PAYMENT')""", ("PAYMENT:"+payment["payment_id"], payment["user_id"]))

    def require_checkout(self, user):
        self.store.require_ready()
        if getattr(self.store.host,'security_blocked',lambda uid:False)(user):
            raise self.error_class('FORBIDDEN','Akun kamu dibatasi owner.')
        if not self.store.host.is_owner(user) and (self.store.host.safe_mode_enabled() or self.store.host.maintenance_enabled()):
            raise self.error_class("PAYMENT_UNAVAILABLE", "Pembayaran sementara ditahan. Coba kembali nanti.")

    async def create(self, user, quote_id):
        # Keep the old entry point to reject previously rendered pay_qris
        # callbacks server-side. Legacy settlement/status/worker paths remain
        # intact so already-issued invoices and paid funds are not orphaned.
        self.require_checkout(user)
        quote = self.store.repo.one(f"SELECT * FROM {self.quote_table} WHERE quote_id=? AND {self.quote_user}=?", (quote_id, user))
        if not quote:
            raise self.error_class("NOT_FOUND")
        if quote["status"] == "OPEN" and quote["expires_at"] <= time.time():
            raise self.error_class("QUOTE_EXPIRED")
        raise self.error_class("WALLET_ONLY", "Pembelian OTP memakai saldo bot. Pilih Buy Saldo atau Isi Saldo.")

    def manual_ready(self):
        return bool(str(self.store.host.get_setting("qris_file_id", "") or "").strip())

    def awaiting_owner(self, payment, conn=None):
        if payment['method']!='QRIS_MANUAL' or not payment['topup_id']:return False
        if conn is None:
            topup=self.store.repo.one('SELECT * FROM topups WHERE id=? AND user_id=?',(payment['topup_id'],payment['user_id']))
        else:
            topup=conn.execute('SELECT * FROM topups WHERE id=? AND user_id=?',(payment['topup_id'],payment['user_id'])).fetchone()
        return self.store.host.manual_qris_awaiting_owner(topup)

    def pending(self, payment):
        return payment['state'] in {'PENDING','CREATING','CREATE_UNKNOWN'} and (not payment['expires_at'] or payment['expires_at']>time.time() or self.awaiting_owner(payment))

    @staticmethod
    def order_card_keyboard(ui, order, user):
        return ui.order_keyboard(order,user)

    def manual_guard(self, user):
        self.require_checkout(user)
        if not self.store.settings()["enabled"]:
            raise self.error_class("DISABLED", "Pembelian baru sedang ditutup owner.")
        if not self.manual_ready():
            raise self.error_class("PAYMENT_UNAVAILABLE", "QRIS manual belum dipasang owner. Gunakan saldo bot.")

    async def create_manual(self, user, quote_id):
        # A quote can fund exactly one purchase. Repeated clicks return the same
        # invoice, including after its quote TTL or a later shop closure.
        existing = self.store.repo.one(f"SELECT * FROM {self.table} WHERE quote_id=? AND user_id=?", (quote_id, user))
        if existing:
            return existing
        self.manual_guard(user)
        now, payment_id = time.time(), secrets.token_hex(12)
        with self.store.repo.connection(True) as conn:
            duplicate = conn.execute(f"SELECT * FROM {self.table} WHERE quote_id=? AND user_id=?", (quote_id, user)).fetchone()
            if duplicate:
                return dict(duplicate)
            self.manual_guard(user)
            quote = conn.execute(f"SELECT * FROM {self.quote_table} WHERE quote_id=? AND {self.quote_user}=?", (quote_id, user)).fetchone()
            if not quote:
                raise self.error_class("NOT_FOUND")
            if quote[self.quote_state] != "OPEN" or quote["expires_at"] <= now:
                raise self.error_class("QUOTE_EXPIRED")
            amount = quote[self.quote_sale]
            if type(amount) is not int or not 0 < amount <= 10**12:
                raise self.error_class("PRICE_LIMIT")
            pending = conn.execute("SELECT count(*) FROM topups WHERE user_id=? AND status IN ('pending','processing')", (user,)).fetchone()[0]
            if pending >= 5:
                raise self.error_class("PAYMENT_UNAVAILABLE", "Selesaikan atau batalkan invoice pembayaran sebelumnya dahulu.")
            code = self.store.host.unique_code_for_order(conn)
            stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            expires = now + self.store.host.MANUAL_QRIS_MINUTES*60
            cursor = conn.execute("""INSERT INTO topups(user_id,username,amount,unique_code,payment_total,
                payment_method,status,created_at,expires_at) VALUES(?,'',?,?,?,'QRIS_MANUAL','pending',?,?)""",
                (user, amount, code, amount+code, stamp,datetime.fromtimestamp(expires,timezone.utc).isoformat(timespec='seconds')))
            topup_id = cursor.lastrowid
            # Approval must arrive before this persisted invoice deadline to
            # fund a product purchase. Later verified money goes to the wallet.
            # Snapshot the QR image so later QR settings do not alter invoices.
            conn.execute(f"""INSERT INTO {self.table}(payment_id,quote_id,user_id,method,state,amount_idr,
                payment_total_idr,topup_id,partner_reference,qr_url,created_at,expires_at,updated_at,shop_refund_policy)
                VALUES(?,?,?,'QRIS_MANUAL','PENDING',?,?,?,?,?,?,?,?,1)""",
                (payment_id, quote_id, user, amount, amount+code, topup_id,
                 self.store.host.topup_invoice(topup_id), self.store.host.get_setting("qris_file_id", ""), now, expires, now))
            conn.execute(f"UPDATE {self.quote_table} SET {self.quote_state}='PAYMENT_PENDING' WHERE quote_id=?", (quote_id,))
        return self.owned(user, payment_id)

    def queue_result(self, conn, payment):
        # OTP capture already enqueues its existing PURCHASE notification.
        pass

    def settle(self, conn, payment, *, already_credited=False, owner_reviewed=False):
        if payment["paid_at"] is not None:
            return
        reference, amount, now = self.wallet_prefix+"QRIS:"+payment["payment_id"], payment["amount_idr"], time.time()
        if not already_credited:
            self.wallet_change(conn, payment["user_id"], "TOPUP", amount, reference)
        eligible = payment["state"] in {"PENDING", "CREATING", "CREATE_UNKNOWN"} and (not payment["expires_at"] or now < payment["expires_at"] or owner_reviewed or self.awaiting_owner(payment,conn))
        if eligible:
            self.wallet_change(conn, payment["user_id"], self.wallet_prefix+"_QRIS_HOLD", -amount, reference)
        state = "PAID" if eligible else "WALLET_CREDITED"
        conn.execute(f"UPDATE {self.table} SET state=?,paid_at=?,updated_at=?,error_code=?,next_retry_at=0 WHERE payment_id=?",
                     (state, now, now, "" if eligible else "LATE_PAYMENT", payment["payment_id"]))
        if not eligible:
            self.queue_notice(conn, payment)

    def accept_topup(self, conn, topup):
        """Called inside the host's successful TOPUP credit transaction only."""
        payment = conn.execute(f"SELECT * FROM {self.table} WHERE topup_id=?", (topup["id"],)).fetchone()
        if not payment:
            return False
        if payment["method"] != "QRIS_MANUAL" or payment["user_id"] != topup["user_id"] or payment["amount_idr"] != topup["amount"] or payment["payment_total_idr"] != topup["payment_total"]:
            raise sqlite3.IntegrityError("OTP payment mapping mismatch")
        self.settle(conn, dict(payment), already_credited=True,
                    owner_reviewed=self.store.host.manual_qris_awaiting_owner(topup))
        return True

    async def notify_topup_receipt(self, bot, topup_id):
        payment = self.store.repo.one(f"SELECT * FROM {self.table} WHERE topup_id=?", (topup_id,))
        if not payment:
            return False
        if payment["state"] != "PAID":
            # Late payment outcomes already have a durable wallet notification.
            return True
        await payment_receipts.notify(self.store.host, bot, self.receipt_source, payment["payment_id"])
        return True  # The same durable photo will receive the product outcome.

    def gateway_callback(self, payload):
        """The host verifies the existing gateway RSA signature before routing."""
        try:
            reference = payload.get("originalPartnerReferenceNo")
            amount = payload.get("amount")
            if not isinstance(amount, dict) or amount.get("currency") != "IDR":
                raise ValueError
            value = Decimal(str(amount.get("value")))
            if not value.is_finite() or value != value.to_integral_value() or not 0 < value <= 10**12:
                raise ValueError
            with self.store.repo.connection(True) as conn:
                row = conn.execute(f"SELECT * FROM {self.table} WHERE partner_reference=? AND method='AUTO_QRIS'", (reference,)).fetchone()
                if not row:
                    return web.json_response({"responseCode":"4045600","responseMessage":"Invoice Not Found"}, status=404)
                if int(value) != row["payment_total_idr"]:
                    raise ValueError
                if payload.get("latestTransactionStatus") == "00":
                    self.settle(conn, dict(row))
            return web.json_response({"responseCode":"2005600","responseMessage":"Successful"})
        except (InvalidOperation, ValueError, TypeError):
            return web.json_response({"responseCode":"4005600","responseMessage":"Reference/Amount Mismatch"}, status=400)
        except sqlite3.Error:
            return web.json_response({"responseCode":"5035600","responseMessage":"Retry Later"}, status=503)

    def release_to_wallet(self, payment_id, code):
        with self.store.repo.connection(True) as conn:
            row = conn.execute(f"SELECT * FROM {self.table} WHERE payment_id=?", (payment_id,)).fetchone()
            if not row or row["state"] != "PAID":
                return
            self.wallet_change(conn, row["user_id"], self.wallet_prefix+"_QRIS_RELEASE", row["amount_idr"], self.wallet_prefix+"QRIS:"+payment_id)
            conn.execute(f"UPDATE {self.table} SET state='WALLET_CREDITED',error_code=?,updated_at=?,lease_owner=NULL,lease_until=0 WHERE payment_id=?",
                         (code, time.time(), payment_id))
            conn.execute(f"UPDATE {self.quote_table} SET {self.quote_state}='PAYMENT_CLOSED' WHERE quote_id=? AND {self.quote_state}='PAYMENT_PENDING'", (row["quote_id"],))
            self.queue_notice(conn, dict(row))

    def expire_manual_due(self):
        """Unpaid only, same write lock as owner credit; never expire held funds."""
        now=time.time()
        with self.store.repo.connection(True) as conn:
            due=conn.execute(f"""SELECT * FROM {self.table}
                WHERE method='QRIS_MANUAL' AND state='PENDING' AND paid_at IS NULL
                  AND expires_at>0 AND expires_at<=?""",(now,)).fetchall()
            for payment in due:
                if self.awaiting_owner(payment,conn):continue
                conn.execute("UPDATE topups SET status='expired' WHERE id=? AND user_id=? AND status='pending'",
                    (payment['topup_id'],payment['user_id']))
                conn.execute(f"""UPDATE {self.table} SET state='EXPIRED',updated_at=?
                    WHERE payment_id=? AND paid_at IS NULL AND state='PENDING'
                      AND EXISTS(SELECT 1 FROM topups t WHERE t.id={self.table}.topup_id AND t.status='expired')""",
                    (now,payment['payment_id']))

    async def reconcile(self):
        self.expire_manual_due()
        if not self.store.lease("payments", max(60, self.store.config.timeout+30)):
            return
        now = time.time()
        waiting = self.store.repo.rows(f"SELECT * FROM {self.table} WHERE state IN ('CREATING','CREATE_UNKNOWN','PENDING') ORDER BY created_at LIMIT 100")
        for row in waiting:
            topup = self.store.repo.one("SELECT * FROM topups WHERE id=?", (row["topup_id"],)) if row["topup_id"] else None
            if topup and topup["status"] == "completed":
                # Compatibility with a host deployed without the atomic bridge:
                # money is already available in its wallet, so do not debit it.
                with self.store.repo.connection(True) as conn:
                    changed = conn.execute(f"UPDATE {self.table} SET state='WALLET_CREDITED',paid_at=?,updated_at=?,error_code='CREDIT_ALREADY_AVAILABLE' WHERE payment_id=? AND paid_at IS NULL",
                                           (now, now, row["payment_id"])).rowcount
                    if changed:
                        self.queue_notice(conn, row)
                continue
            closed = topup and topup["status"] in {"cancelled", "rejected", "expired"}
            if closed or (row["expires_at"] and row["expires_at"] <= now and not self.awaiting_owner(row)):
                state = "CANCELLED" if topup and topup["status"] in {"cancelled", "rejected"} else "EXPIRED"
                self.store.repo.execute(f"UPDATE {self.table} SET state=?,updated_at=? WHERE payment_id=? AND paid_at IS NULL AND state IN ('CREATING','CREATE_UNKNOWN','PENDING')",
                                        (state, now, row["payment_id"]))
        for payment in self.store.repo.rows(f"SELECT * FROM {self.table} WHERE state='PAID' AND next_retry_at<=? ORDER BY paid_at LIMIT 20", (now,)):
            try:
                await self.store.purchase.buy(payment["user_id"], payment["quote_id"], payment_id=payment["payment_id"])
            except self.errors as exc:
                # No provider POST has happened until the existing purchase
                # attempt commits. A temporary catalog error keeps funds held.
                if exc.code in {"PRICE_CHANGED", "NO_OFFER_AVAILABLE", "NOT_FOUND", "DISABLED", "ORDER_LIMIT", "PRICE_LIMIT", "CONFLICT", "BELOW_COST", "CONFIG", "NOT_CONFIGURED", "UNAUTHORIZED", "ENCRYPTION", "PAYMENT_UNAVAILABLE", "CLOSED", "ACTIVE_LIMIT", "TYPE", "CURRENCY", "INPUT", "MIN_MAX", "MAINTENANCE", "QUOTE_EXPIRED", "FORBIDDEN"}:
                    self.release_to_wallet(payment["payment_id"], exc.code)
                elif exc.code == "PAYMENT_PENDING":
                    pass
                else:
                    delay = max(getattr(exc, "retry_after", 0) or 0, min(900, 10*2**min(payment["retries"], 6)))
                    self.store.repo.execute(f"UPDATE {self.table} SET next_retry_at=?,retries=retries+1,error_code=? WHERE payment_id=? AND state='PAID'",
                                            (now+delay, exc.code, payment["payment_id"]))
            except Exception as exc:
                # Preserve held funds and any committed attempt. A failure for
                # one invoice must not block other buyers in this batch.
                logging.warning("OTP payment reconciliation: %s", type(exc).__name__)
                delay = min(900, 10*2**min(payment["retries"], 6))
                self.store.repo.execute(f"UPDATE {self.table} SET next_retry_at=?,retries=retries+1,error_code='INTERNAL_ERROR' WHERE payment_id=? AND state='PAID'",
                                        (now+delay, payment["payment_id"]))
        for payment in self.store.repo.rows(f"SELECT p.*,a.state attempt_state FROM {self.table} p JOIN {self.attempt_table} a ON a.attempt_id=p.attempt_id WHERE p.state='BUYING'"):
            if payment["attempt_state"] in {self.success_state, "FAILED", "CANCELED"}:
                state = "COMPLETED" if payment["attempt_state"] == self.success_state else "WALLET_CREDITED"
                with self.store.repo.connection(True) as conn:
                    updated = conn.execute(f"UPDATE {self.table} SET state=?,updated_at=? WHERE payment_id=? AND state='BUYING'", (state, now, payment["payment_id"])).rowcount
                    if updated:
                        if state == "COMPLETED":
                            self.queue_result(conn, payment)
                        elif payment["attempt_state"] != "CANCELED":
                            self.queue_notice(conn, payment)

    def cancel(self, user, payment_id):
        payment = self.owned(user, payment_id)
        if payment["paid_at"] is not None or payment["state"] == "BUYING":
            raise self.error_class("PAYMENT_PAID")
        if payment["topup_id"]:
            _, status = self.store.host.cancel_topup_atomic(payment["topup_id"], user)
            if status not in {"cancelled", "already_cancelled", "invalid_status"}:
                raise self.error_class("PAYMENT_PAID")
        self.store.repo.execute(f"UPDATE {self.table} SET state='CANCELLED',updated_at=? WHERE payment_id=? AND user_id=? AND paid_at IS NULL AND state IN ('CREATING','CREATE_UNKNOWN','PENDING')",
                                (time.time(), payment_id, user))
        return self.owned(user, payment_id)

    async def retire_qr(self, bot):
        for row in self.store.repo.rows(f"SELECT * FROM {self.table} WHERE qr_message_id IS NOT NULL AND qr_delivery_state='SENT' AND state IN ('PAID','BUYING','COMPLETED','WALLET_CREDITED','CANCELLED','EXPIRED') LIMIT 20"):
            if await self.store.host.retire_topup_payment_message(bot, row["user_id"], row["qr_message_id"]):
                self.store.repo.execute(f"UPDATE {self.table} SET qr_delivery_state='RETIRED' WHERE payment_id=?", (row["payment_id"],))


class SMSEventProcessor:
    def __init__(self, store):
        self.store = store

    def process(self, data, source):
        provider_id = integer(data.get("order_id", data.get("id")), 1)
        revision = integer(data.get("sms_revision"), 1)
        code, message = data.get("otp_code"), data.get("otp_message")
        if code is not None and not isinstance(code, str) or message is not None and not isinstance(message, str):
            raise StoreError("INVALID_RESPONSE")
        if not code and not message:
            return False
        if len(code or "") > 2048 or len(message or "") > 100000:
            raise StoreError("INVALID_RESPONSE")
        payload = self.store.encrypt({"otp_code": code, "otp_message": message})
        with self.store.repo.connection(True) as conn:
            order = conn.execute("SELECT * FROM otp_orders WHERE provider_order_id=?", (provider_id,)).fetchone()
            if not order:
                return False
            for field in ("phone_number", "product_id", "catalog_product_id", "operator_id"):
                if field in data and data[field] != order[field]:
                    raise StoreError("ORDER_IDENTITY", "Snapshot SMS tidak cocok dengan pesanan lokal.")
            if revision <= order["last_sms_revision"]:
                return True
            # Both webhook and polling share this unique revision and queue.
            conn.execute("INSERT OR IGNORE INTO otp_sms_events VALUES(?,?,?,?,?)", (provider_id, revision, payload, time.time(), source))
            conn.execute("UPDATE otp_orders SET last_sms_revision=?,status=CASE WHEN status='ACTIVE' THEN 'OTP_RECEIVED' ELSE status END,updated_at=? WHERE id=?", (revision, time.time(), order["id"]))
            self.store.queue(conn, order["id"], provider_id, order["buyer_user_id"], "SMS", revision)
        return True


class RefundService:
    def __init__(self, store):
        self.store = store

    def shop_failure(self, order, status):
        """Return a new manual invoice's sale to the buyer, independently of
        reimbursement to the provider account. Never refund an unknown create
        result, a completed number, or an order that has received an SMS.
        """
        if status not in {'FAILED', 'CANCELED', 'EXPIRED'}:
            return False
        with self.store.repo.connection(True) as conn:
            current = conn.execute('SELECT * FROM otp_orders WHERE id=?',(order['id'],)).fetchone()
            if not current or current['status']=='COMPLETED' or current['last_sms_revision']>0:
                return False
            funded = conn.execute("SELECT 1 FROM otp_payments WHERE attempt_id=? AND user_id=? AND paid_at IS NOT NULL AND method='QRIS_MANUAL' AND shop_refund_policy=1",(current['attempt_id'],current['buyer_user_id'])).fetchone()
            if not funded:
                return False
            if current['refund_state']=='REFUNDED':
                return True
            WalletAdapter.change(conn,current['buyer_user_id'],'REFUND',current['selling_price_idr'],'OTP:ORDER:'+str(current['id']))
            conn.execute("UPDATE otp_orders SET status=?,refund_idr=selling_price_idr,refund_state='REFUNDED',updated_at=? WHERE id=?",(status,time.time(),current['id']))
            self.store.queue(conn,current['id'],current['provider_order_id'],current['buyer_user_id'],'REFUND',0)
        return True

    def recover_shop_failures(self):
        for order in self.store.repo.rows("""SELECT o.* FROM otp_orders o JOIN otp_payments p ON p.attempt_id=o.attempt_id
            WHERE p.shop_refund_policy=1 AND p.paid_at IS NOT NULL AND p.method='QRIS_MANUAL'
              AND o.status IN ('FAILED','CANCELED','EXPIRED') AND o.last_sms_revision=0 AND o.refund_state!='REFUNDED' LIMIT 100"""):
            self.shop_failure(order,order['status'])

    def confirm(self, order, response):
        if not isinstance(response, dict) or response.get("order_id") != order["provider_order_id"] or response.get("status") not in {"CANCELED", "EXPIRED"}:
            raise StoreError("INVALID_RESPONSE", uncertain=True)
        if 'refund_amount' not in response and self.shop_failure(order,response['status']):
            return
        try:
            amount = integer(response.get("refund_amount"))
        except StoreError:
            raise StoreError("INVALID_RESPONSE", uncertain=True) from None
        if self.shop_failure(order,response['status']):
            self.store.repo.execute('UPDATE otp_orders SET provider_refund_idr=MAX(provider_refund_idr,?) WHERE id=?',(amount,order['id']))
            return
        with self.store.repo.connection(True) as conn:
            current = conn.execute("SELECT * FROM otp_orders WHERE id=?", (order["id"],)).fetchone()
            if current["refund_state"] == "REFUNDED":
                return
            if current["status"] == "COMPLETED" or current["last_sms_revision"] > 0:
                conn.execute("UPDATE otp_orders SET refund_state='REVIEW_REQUIRED' WHERE id=?", (order["id"],))
                return
            if amount < current["provider_cost_idr"]:
                conn.execute("UPDATE otp_orders SET status=?,refund_state='PARTIAL_RECONCILIATION',provider_refund_idr=?,updated_at=? WHERE id=?",
                             (response["status"], amount, time.time(), order["id"]))
                return
            WalletAdapter.change(conn, current["buyer_user_id"], "REFUND", current["selling_price_idr"], "OTP:ORDER:"+str(order["id"]))
            conn.execute("UPDATE otp_orders SET status=?,refund_idr=selling_price_idr,refund_state='REFUNDED',provider_refund_idr=?,updated_at=? WHERE id=?",
                         (response["status"], amount, time.time(), order["id"]))
            self.store.queue(conn, order["id"], order["provider_order_id"], order["buyer_user_id"], "REFUND", 0)


class OrderService:
    def __init__(self, store):
        self.store = store

    async def refresh(self, order):
        data = await self.store.api.request("GET", f"/orders/{order['provider_order_id']}")
        self.apply(order, data)
        return data

    def apply(self, order, data):
        if not isinstance(data, dict) or data.get("id") != order["provider_order_id"] or data.get("status") not in ACTIVE | TERMINAL:
            raise StoreError("INVALID_RESPONSE")
        if isinstance(data.get("sms_revision"), int) and data["sms_revision"] > 0 and (data.get("otp_message") or data.get("otp_code")):
            self.store.sms.process(data, "polling")
        now = time.time()
        self.store.repo.execute("""UPDATE otp_orders SET status=CASE WHEN status IN ('COMPLETED','CANCELED','EXPIRED','FAILED')
            THEN status WHEN last_sms_revision>0 AND ?='ACTIVE' THEN 'OTP_RECEIVED' ELSE ? END,capabilities=?,expires_at=COALESCE(?,expires_at),
            updated_at=?,completed_at=CASE WHEN ?='COMPLETED' THEN COALESCE(completed_at,?) ELSE completed_at END,
            next_poll_at=? WHERE id=?""", (data["status"], data["status"], self.store.capabilities(data), data.get("expires_at"),
            now, data["status"], now, now+self.store.config.poll_seconds, order["id"]))
        if data["status"] in {"CANCELED", "EXPIRED"}:
            if "refund_amount" in data:
                self.store.refund.confirm(order, {**data, "order_id": data["id"]})
            elif not self.store.refund.shop_failure(order,data['status']):
                # The official GET schema has no refund_amount. A terminal status
                # alone is insufficient evidence of a credit to the provider wallet.
                self.store.repo.execute("UPDATE otp_orders SET refund_state='AWAITING_PROVIDER_PROOF' WHERE id=? AND refund_state='NONE'", (order["id"],))
        elif data['status']=='FAILED':
            self.store.refund.shop_failure(order,data['status'])

    async def action(self, user, order_id, action):
        order = self.store.repo.owned(user, order_id)
        self.store.repo.rate(user, "action:"+action, 3 if action == "resend" else 6, 60)
        data = await self.refresh(order)
        if data.get("can_"+action) is not True:
            at = data.get({"cancel": "cancel_available_at", "resend": "resend_available_at"}.get(action, ""))
            raise StoreError("CONFLICT", "Tindakan belum diizinkan provider." + (" Tersedia: " + str(at) if at else ""))
        if action == "cancel" and (data.get("otp_message") or data.get("otp_code") or data.get("otp_received_at")):
            raise StoreError("CONFLICT", "SMS sudah diterima. Gunakan Selesai.")
        now, owner = time.time(), secrets.token_hex(12)
        with self.store.repo.connection(True) as conn:
            pending = conn.execute("SELECT id FROM otp_actions WHERE order_id=? AND state IN ('REQUESTING','PENDING_RECONCILIATION')", (order["id"],)).fetchone()
            if pending:
                raise StoreError("REQUEST_IN_PROGRESS")
            latest = conn.execute("SELECT max(created_at) FROM otp_actions WHERE order_id=? AND action='resend'", (order["id"],)).fetchone()[0]
            if action == "resend" and latest and now-latest < 30:
                raise StoreError("COOLDOWN", "Tunggu 30 detik sebelum resend berikutnya.")
            cursor = conn.execute("INSERT INTO otp_actions(order_id,action,state,created_at,updated_at,lease_owner,lease_until) VALUES(?,?,'REQUESTING',?,?,?,?)",
                                  (order["id"], action, now, now, owner, now+self.store.config.timeout+30))
            action_id = cursor.lastrowid
        try:
            response = await self.store.api.request("POST", "/orders/"+action, body={"id": order["provider_order_id"]})
            if not isinstance(response, dict) or response.get("order_id") != order["provider_order_id"]:
                raise StoreError("INVALID_RESPONSE", uncertain=True)
            # Persist provider refund proof before updating wallet; restart can replay locally.
            self.store.repo.execute("UPDATE otp_actions SET response=?,updated_at=? WHERE id=?", (encoded(response), time.time(), action_id))
            self.complete(action_id, order, action, response)
            return response
        except StoreError as exc:
            self.store.repo.execute("UPDATE otp_actions SET state=?,error_code=?,lease_owner=NULL,lease_until=0,next_retry_at=?,updated_at=? WHERE id=?",
               ("PENDING_RECONCILIATION" if exc.uncertain else "FAILED", exc.code, time.time()+max(30, exc.retry_after), time.time(), action_id))
            raise
        except sqlite3.Error:
            # REQUESTING remains durable and gets reconciled after the lease expires.
            raise StoreError("LOCAL_DATABASE", "Hasil tindakan akan direkonsiliasi; jangan mengulang.", uncertain=True) from None

    def complete(self, action_id, order, action, response):
        if action in {"cancel", "refund-proof"}:
            self.store.refund.confirm(order, response)
        elif action == "finish":
            if response.get("status") != "COMPLETED":
                raise StoreError("INVALID_RESPONSE", uncertain=True)
            self.store.repo.execute("UPDATE otp_orders SET status='COMPLETED',completed_at=?,updated_at=? WHERE id=?", (time.time(), time.time(), order["id"]))
        elif action == "resend" and response.get("resent") is not True:
            raise StoreError("CONFLICT")
        self.store.repo.execute("UPDATE otp_actions SET state='DONE',updated_at=?,lease_owner=NULL,lease_until=0 WHERE id=?", (time.time(), action_id))

    async def reconcile_actions(self):
        for row in self.store.repo.rows("SELECT * FROM otp_actions WHERE state IN ('REQUESTING','PENDING_RECONCILIATION','PROOF_RECORDED') AND lease_until<? AND next_retry_at<? LIMIT 10", (time.time(), time.time())):
            owner = secrets.token_hex(12)
            if not self.store.repo.execute("UPDATE otp_actions SET lease_owner=?,lease_until=? WHERE id=? AND lease_until<?", (owner, time.time()+self.store.config.timeout+30, row["id"], time.time())):
                continue
            order = self.store.repo.one("SELECT * FROM otp_orders WHERE id=?", (row["order_id"],))
            try:
                if row["response"]:
                    self.complete(row["id"], order, row["action"], json.loads(row["response"]))
                    continue
                data = await self.refresh(order)
                if row["action"] == "finish" and data["status"] == "COMPLETED":
                    self.complete(row["id"], order, "finish", {"order_id": order["provider_order_id"], "status": "COMPLETED"})
                elif row["action"] == "cancel":
                    if data['status'] in {'CANCELED','EXPIRED','FAILED'} and self.store.refund.shop_failure(order,data['status']):
                        self.store.repo.execute("UPDATE otp_actions SET state='DONE',lease_owner=NULL,lease_until=0,updated_at=? WHERE id=?",(time.time(),row['id']))
                        continue
                    # GET lacks money proof. Don't infer refund or repeat a money mutation.
                    self.store.repo.execute("UPDATE otp_orders SET refund_state='AWAITING_PROVIDER_PROOF' WHERE id=? AND refund_state!='REFUNDED'", (order["id"],))
                    self.store.repo.execute("UPDATE otp_actions SET next_retry_at=?,state='PENDING_RECONCILIATION',lease_until=0 WHERE id=?", (time.time()+300, row["id"]))
                else:
                    self.store.repo.execute("UPDATE otp_actions SET state='REVIEW_REQUIRED',lease_until=0 WHERE id=?", (row["id"],))
            except (StoreError, sqlite3.Error, ValueError):
                self.store.repo.execute("UPDATE otp_actions SET state='PENDING_RECONCILIATION',next_retry_at=?,lease_until=0 WHERE id=?", (time.time()+60, row["id"]))


class NotificationQueue:
    def __init__(self, store):
        self.store = store

    async def deliver(self, bot):
        now = time.time()
        self.store.repo.execute("UPDATE otp_notifications SET status='UNKNOWN',error_code='DELIVERY_UNCERTAIN' WHERE status='DISPATCHING' AND lease_until<?",(now,))
        jobs = self.store.repo.rows("SELECT * FROM otp_notifications WHERE status IN ('PENDING','SENDING') AND next_retry_at<=? AND lease_until<? ORDER BY notification_id LIMIT 20", (now, now))
        for job in jobs:
            owner = secrets.token_hex(12)
            if not self.store.repo.execute("UPDATE otp_notifications SET status='SENDING',lease_owner=?,lease_until=? WHERE notification_id=? AND status IN ('PENDING','SENDING') AND lease_until<?",
                     (owner, time.time()+120, job["notification_id"], time.time())):
                continue
            order = self.store.repo.one("SELECT * FROM otp_orders WHERE id=?", (job["order_id"],))
            dispatching=False
            try:
                if job['kind'] in {'PURCHASE','PAYMENT'}:
                    if job['kind']=='PURCHASE' and (not order or order['buyer_user_id']!=job['user_id']):
                        raise StoreError('FORBIDDEN')
                    if job['kind']=='PAYMENT':self.store.payments.owned(job['user_id'],job['dedup_key'].removeprefix('PAYMENT:'))
                    source,entity=('otp_order',job['order_id']) if job['kind']=='PURCHASE' else ('otp_payment',job['dedup_key'].removeprefix('PAYMENT:'))
                    shown=await payment_receipts.notify(self.store.host,bot,source,entity)
                    key=self.store.host.PAYMENT_RECEIPTS.store_key(source,entity,job['user_id'])
                    receipt=self.store.repo.one('SELECT status,message_id FROM payment_receipts WHERE source=? AND entity_id=?',key) if key else None
                    if shown or receipt and receipt['status'] in {'LEGACY','RETIRING','RETIRED'}:
                        self.store.repo.execute("UPDATE otp_notifications SET status='SENT',sent_at=?,telegram_message_id=?,lease_until=0,lease_owner=NULL WHERE notification_id=? AND lease_owner=?",(time.time(),receipt['message_id'] if receipt else None,job['notification_id'],owner))
                        continue
                    if receipt and receipt['status']=='UNKNOWN':
                        self.store.repo.execute("UPDATE otp_notifications SET status='UNKNOWN',error_code='INVOICE_UNCERTAIN',lease_until=0,lease_owner=NULL WHERE notification_id=? AND lease_owner=?",(job['notification_id'],owner))
                        continue
                    raise StoreError('LOCAL_DATABASE','Invoice sedang disiapkan; pesanan tetap tersimpan.')
                payment, payload = None, {}
                if job["kind"] == "PAYMENT":
                    payment = self.store.payments.owned(job["user_id"], job["dedup_key"].removeprefix("PAYMENT:"))
                    texts = [f"🛍️ <b>{USER_BRAND}</b>\n💰 Pembayaran QRIS {money(payment['amount_idr'])} tersedia di saldo kamu.\n"
                             "Nomor belum dibeli. Pembayaran terlambat, harga/stok berubah, atau pembelian tidak dapat diselesaikan. "
                             "Gunakan Buy Saldo untuk memilih nomor kembali; tidak perlu membayar QRIS lagi."]
                elif not order or order["buyer_user_id"] != job["user_id"]:
                    raise StoreError("NOT_FOUND")
                elif job["kind"] == "SMS":
                    event = self.store.repo.one("SELECT * FROM otp_sms_events WHERE provider_order_id=? AND sms_revision=?", (job["provider_order_id"], job["sms_revision"]))
                    if not event or not event["encrypted_payload"]:
                        raise StoreError("RETENTION", "SMS melewati masa retensi.")
                    payload = self.store.decrypt(event["encrypted_payload"])
                    await payment_receipts.notify(self.store.host,bot,'otp_order',order['id'])
                    texts = self.store.ui.sms_texts(order, payload, job["sms_revision"])
                elif job["kind"] == "REFUND":
                    texts = [f"✅ Refund OTP #{order['id']} berhasil: <b>{money(order['refund_idr'])}</b> masuk ke saldo kamu."]
                else:
                    texts = ["✅ <b>PEMBELIAN BERHASIL</b>\n"+self.store.ui.order_text(order)+"\n📩 SMS akan dikirim otomatis saat masuk."]
                for index in range(job["part_index"], len(texts)):
                    if not self.store.repo.execute("UPDATE otp_notifications SET lease_until=? WHERE notification_id=? AND lease_owner=?",
                            (time.time()+120, job["notification_id"], owner)):
                        raise StoreError("LEASE_LOST")
                    self.store.repo.execute("UPDATE otp_notifications SET status='DISPATCHING' WHERE notification_id=? AND lease_owner=?",(job['notification_id'],owner))
                    dispatching=True
                    sent = await bot.send_message(job["user_id"], texts[index], parse_mode="HTML",
                         reply_markup=self.store.ui.navigation(job['user_id'],'check',{'id':order['id']}) if index==len(texts)-1 and not payment else self.store.ui.home_keyboard(job['user_id']) if payment else None,
                         link_preview_options=LinkPreviewOptions(is_disabled=True))
                    self.store.repo.execute("UPDATE otp_notifications SET status='SENDING',part_index=?,telegram_message_id=? WHERE notification_id=? AND lease_owner=?",
                           (index+1, getattr(sent, "message_id", None), job["notification_id"], owner))
                    dispatching=False
                self.store.repo.execute("UPDATE otp_notifications SET status='SENT',sent_at=?,lease_until=0,lease_owner=NULL WHERE notification_id=? AND lease_owner=?", (time.time(), job["notification_id"], owner))
            except asyncio.CancelledError:
                if dispatching:self.store.repo.execute("UPDATE otp_notifications SET status='UNKNOWN',error_code='CANCELLED',lease_until=0,lease_owner=NULL WHERE notification_id=? AND lease_owner=?",(job['notification_id'],owner))
                raise
            except Exception as exc:
                # Exception strings may include request payloads. Store class only.
                attempts = job["attempts"]+1
                delay = max(getattr(exc, "retry_after", 0) or 0, min(3600, 5*2**min(attempts, 10)))
                self.store.repo.execute("UPDATE otp_notifications SET status=?,attempts=?,next_retry_at=?,error_code=?,lease_until=0,lease_owner=NULL WHERE notification_id=? AND lease_owner=?",
                    ("UNKNOWN" if dispatching and not isinstance(exc,(TelegramBadRequest,TelegramForbiddenError,TelegramRetryAfter)) else "FAILED" if attempts >= self.store.config.retries else "PENDING", attempts, time.time()+delay, type(exc).__name__, job["notification_id"], owner))


class WebhookController:
    def __init__(self, store):
        self.store = store

    async def handle(self, request):
        secret = self.store.config.webhook_secret
        if not secret or not self.store.has_encryption():
            return web.json_response({"ok": False}, status=503)
        try:
            if request.content_length and request.content_length > 262144:
                return web.json_response({"ok": False}, status=413)
            try:
                raw = await bounded_body(request.content, 262144)
            except StoreError:
                return web.json_response({"ok": False}, status=413)
            expected = "sha256="+hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
            signature = request.headers.get("X-Webhook-Signature", "")
            if not re.fullmatch(r"sha256=[0-9a-f]{64}", signature) or not hmac.compare_digest(signature, expected):
                return web.json_response({"ok": False}, status=401)
            event = json.loads(raw)
            if not isinstance(event, dict) or not isinstance(event.get("data"), dict):
                return web.json_response({"ok": False}, status=400)
            if event.get("event") == "webhook.test":
                self.store.set_setting("last_webhook_at", time.time())
                return web.json_response({"ok": True})
            if event.get("event") not in {"order.otp_received", "order.completed", "order.expired", "order.canceled"}:
                return web.json_response({"ok": True, "ignored": True})
            provider_id = integer(event["data"].get("order_id"), 1)
            if event["event"] == "order.otp_received":
                integer(event["data"].get("sms_revision"), 1)
                for key in ("otp_code", "otp_message"):
                    value = event["data"].get(key)
                    if value is not None and (not isinstance(value, str) or len(value) > 100000):
                        raise StoreError("INVALID_RESPONSE")
            digest = hashlib.sha256(raw).hexdigest()
            encrypted = self.store.encrypt(event)
            self.store.repo.execute("INSERT OR IGNORE INTO otp_webhook_inbox(digest,provider_order_id,encrypted_payload,created_at) VALUES(?,?,?,?)", (digest, provider_id, encrypted, time.time()))
            self.store.set_setting("last_webhook_at", time.time())
            # No provider request or Telegram send before this fast durable response.
            return web.json_response({"ok": True})
        except (ValueError, UnicodeDecodeError, StoreError):
            return web.json_response({"ok": False}, status=400)
        except sqlite3.Error:
            return web.json_response({"ok": False}, status=503)

    async def drain(self):
        rows = self.store.repo.rows("""SELECT i.* FROM otp_webhook_inbox i LEFT JOIN otp_orders o
            ON o.provider_order_id=i.provider_order_id WHERE i.status='PENDING'
            ORDER BY (o.id IS NOT NULL) DESC,i.created_at LIMIT 100""")
        for row in rows:
            order = self.store.repo.one("SELECT * FROM otp_orders WHERE provider_order_id=?", (row["provider_order_id"],))
            if not order:
                # A create may not yet be persisted. Keep encrypted orphan for 24h.
                if time.time()-row["created_at"] > 86400:
                    self.store.repo.execute("UPDATE otp_webhook_inbox SET status='UNMAPPED',encrypted_payload='' WHERE digest=?", (row["digest"],))
                continue
            try:
                event = self.store.decrypt(row["encrypted_payload"])
                if event["event"] == "order.otp_received":
                    self.store.sms.process(event["data"], "webhook")
                else:
                    # Terminal webhook lacks a refund amount; verify via official GET.
                    self.store.repo.execute("UPDATE otp_orders SET next_poll_at=0 WHERE id=?", (order["id"],))
                self.store.repo.execute("UPDATE otp_webhook_inbox SET status='DONE',encrypted_payload='' WHERE digest=?", (row["digest"],))
            except StoreError:
                self.store.repo.execute("UPDATE otp_webhook_inbox SET status='REVIEW_REQUIRED' WHERE digest=?", (row["digest"],))


class Store:
    def __init__(self, host, config=None):
        self.host, self.config = host, config or Config.environment()
        self.repo, self.api = Repository(host), APIClient(self.config)
        self.pricing, self.catalog, self.purchase = PricingService(self), CatalogService(self), PurchaseService(self)
        self.payments = PaymentService(self)
        self.sms, self.refund, self.orders = SMSEventProcessor(self), RefundService(self), OrderService(self)
        self.notifications, self.webhook, self.ui = NotificationQueue(self), WebhookController(self), UIBuilder(self)
        self.topups = TopupBridge(self)
        self.worker_id = secrets.token_hex(16)
        self._tasks = []

    def encryption_key(self):
        seed = os.getenv("OTP_STORAGE_ENCRYPTION_KEY", "") or getattr(self.host, "TEMPMAIL_ENCRYPTION_KEY", "") or getattr(self.host, "BOT_TOKEN", "")
        if not seed:
            raise StoreError("ENCRYPTION", "Kunci penyimpanan OTP belum dikonfigurasi.")
        return hashlib.sha256(("maboyy:smscode:otp:v1:"+seed).encode()).digest()

    def has_encryption(self):
        try:
            self.encryption_key()
            return True
        except StoreError:
            return False

    def encrypt(self, payload):
        cipher = AES.new(self.encryption_key(), AES.MODE_GCM, nonce=secrets.token_bytes(12))
        cipher.update(b"smscode-otp-v1")
        encrypted, tag = cipher.encrypt_and_digest(encoded(payload).encode())
        return base64.b64encode(cipher.nonce+tag+encrypted).decode()

    def decrypt(self, payload):
        try:
            raw = base64.b64decode(payload, validate=True)
            cipher = AES.new(self.encryption_key(), AES.MODE_GCM, nonce=raw[:12])
            cipher.update(b"smscode-otp-v1")
            return json.loads(cipher.decrypt_and_verify(raw[28:], raw[12:28]))
        except (ValueError, KeyError):
            raise StoreError("ENCRYPTION", "Data SMS tidak dapat dibaca dengan kunci penyimpanan saat ini.") from None

    def settings(self, conn=None):
        c = self.config
        result = {"enabled": c.enabled, "mode": c.mode, "percent": c.percent, "fixed": c.fixed,
                  "rounding": c.rounding, "max_active": c.max_active, "allow_loss": False,
                  "hourly_limit": c.hourly_limit, "purchase_cooldown": c.purchase_cooldown, "last_webhook_at": 0,
                  "last_poll_at": 0, "last_delivery_at": 0, "last_worker_error": ""}
        rows = conn.execute("SELECT key,value FROM otp_settings").fetchall() if conn else self.repo.rows("SELECT key,value FROM otp_settings")
        for row in rows:
            result[row["key"]] = json.loads(row["value"])
        return result

    def set_setting(self, key, value, actor=None):
        if actor is not None and not self.host.is_owner(actor):
            raise StoreError("FORBIDDEN")
        self.repo.execute("INSERT INTO otp_settings VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at", (key, encoded(value), time.time()))

    def require_ready(self):
        if self.config.error:
            raise StoreError("CONFIG", "Konfigurasi toko OTP perlu diperbaiki owner.")
        if not self.config.token or not self.has_encryption():
            raise StoreError("NOT_CONFIGURED", "Toko OTP belum dikonfigurasi owner.")
        if not self.settings()["enabled"]:
            raise StoreError("DISABLED", "Pembelian baru sedang ditutup owner. Pesanan lama tetap dipantau.")

    @staticmethod
    def capabilities(data):
        return encoded({key: data.get(key) for key in ["can_cancel", "can_finish", "can_resend", "can_reactivate", "resend_available_at", "cancel_available_at"]})

    @staticmethod
    def queue(conn, order_id, provider_id, user, kind, revision):
        conn.execute("""INSERT OR IGNORE INTO otp_notifications(dedup_key,order_id,provider_order_id,sms_revision,user_id,kind)
                     VALUES(?,?,?,?,?,?)""", (f"{kind}:{provider_id}:{revision}", order_id, provider_id, revision, user, kind))

    def token(self, user, action, payload=None, ttl=300):
        token = secrets.token_urlsafe(12)
        self.repo.execute("INSERT INTO otp_callback_tokens VALUES(?,?,?,?,?)", (token, user, action, encoded(payload or {}), time.time()+ttl))
        return PREFIX+token

    def read_token(self, user, token):
        row = self.repo.one("SELECT * FROM otp_callback_tokens WHERE token=? AND user_id=? AND expires_at>?", (token, user, time.time()))
        if not row:
            raise StoreError("TOKEN", "Tombol kedaluwarsa atau bukan milik kamu. Buka /otp lagi.")
        return row["action"], json.loads(row["payload"])

    def lease(self, name, seconds=120):
        now = time.time()
        with self.repo.connection(True) as conn:
            row = conn.execute("SELECT * FROM otp_worker_leases WHERE name=?", (name,)).fetchone()
            if row and row["until_ts"] > now and row["owner"] != self.worker_id:
                return False
            conn.execute("INSERT OR REPLACE INTO otp_worker_leases VALUES(?,?,?)", (name, self.worker_id, now+seconds))
        return True

    async def polling_cycle(self):
        lease_seconds = max(60, self.config.timeout+30)
        if not self.lease("polling", lease_seconds):
            return
        orders = self.repo.rows("SELECT * FROM otp_orders WHERE status IN ('ACTIVE','OTP_RECEIVED') AND next_poll_at<=? ORDER BY next_poll_at LIMIT 100", (time.time(),))
        if not orders:
            self.set_setting("last_poll_at", time.time())
            return
        try:
            active = await self.catalog.listing("/orders/active")
        except StoreError as exc:
            if exc.retry_after or time.time() < getattr(self.api, "blocked_until", 0):
                raise
            # An oversized/malformed account-wide response must not prevent
            # checking relevant individual local orders through the official API.
            active = []
        by_id = {row.get("id"): row for row in active}
        for order in orders:
            if not self.lease("polling", lease_seconds):
                break
            try:
                data = by_id.get(order["provider_order_id"])
                if data is not None:
                    self.orders.apply(order, data)
                else:
                    await self.orders.refresh(order)
            except StoreError as exc:
                self.repo.execute("UPDATE otp_orders SET next_poll_at=? WHERE id=?", (time.time()+max(exc.retry_after, self.config.poll_seconds), order["id"]))
                if exc.retry_after:
                    break
        self.set_setting("last_poll_at", time.time())

    async def bootstrap_webhook(self):
        data = await self.api.request("GET", "/webhook")
        if not isinstance(data, dict):
            raise StoreError("INVALID_RESPONSE")
        official = data.get("webhook_secret")
        if self.config.webhook_url and data.get("webhook_url") == self.config.webhook_url and official:
            if self.config.webhook_secret and not hmac.compare_digest(self.config.webhook_secret, official):
                self.set_setting("webhook_config_error", "SECRET_MISMATCH")
                self.config.webhook_secret = ""
            else:
                self.config.webhook_secret = official
                self.set_setting("webhook_config_error", "")
        return data

    async def configure_webhook(self, actor):
        if not self.host.is_owner(actor):
            raise StoreError("FORBIDDEN")
        if not self.config.webhook_url:
            raise StoreError("CONFIG", "Isi SMSCODE_WEBHOOK_PUBLIC_URL dengan URL HTTPS endpoint bot.")
        data = await self.api.request("GET", "/webhook")
        if data.get("webhook_url") not in {None, "", self.config.webhook_url}:
            raise StoreError("WEBHOOK_CONFLICT", "Akun provider sudah memakai webhook sistem lain. Pengaturan tidak diubah.")
        # Keep the provider's existing signing secret. On first setup the provider
        # generates it officially; adopt the returned value, never invent a key.
        response = await self.api.request("PATCH", "/webhook", body={"webhook_url": self.config.webhook_url})
        if response.get("webhook_url") != self.config.webhook_url or not response.get("webhook_secret"):
            raise StoreError("INVALID_RESPONSE")
        self.config.webhook_secret = response["webhook_secret"]
        self.set_setting("webhook_config_error", "")
        return response

    def cleanup(self):
        now = time.time()
        self.repo.execute("DELETE FROM otp_callback_tokens WHERE expires_at<?", (now,))
        # Pending delivery is retained until successful/exhausted; live orders also
        # retain their SMS so resend and /otp cek remain usable during the rental.
        self.repo.execute("""UPDATE otp_sms_events SET encrypted_payload='' WHERE received_at<? AND encrypted_payload!=''
            AND NOT EXISTS(SELECT 1 FROM otp_orders o WHERE o.provider_order_id=otp_sms_events.provider_order_id AND o.status IN ('ACTIVE','OTP_RECEIVED'))
            AND NOT EXISTS(SELECT 1 FROM otp_notifications n WHERE n.provider_order_id=otp_sms_events.provider_order_id
            AND n.sms_revision=otp_sms_events.sms_revision AND n.status IN ('PENDING','SENDING'))""", (now-self.config.retention_hours*3600,))

    async def run_loop(self, kind, bot):
        last_cleanup = 0
        while True:
            try:
                if kind == "notifications":
                    if self.has_encryption():
                        await self.notifications.deliver(bot)
                        await self.payments.retire_qr(bot)
                        self.set_setting("last_delivery_at", time.time())
                elif kind == "polling":
                    if self.has_encryption():
                        await self.webhook.drain()
                    if self.config.token and not self.config.error:
                        await self.polling_cycle()
                elif kind == "reconciliation":
                    await self.payments.reconcile()
                    self.refund.recover_shop_failures()
                    if self.config.token and not self.config.error:
                        for row in self.repo.rows("SELECT attempt_id FROM otp_purchase_attempts WHERE state IN ('RESERVED','REQUESTING','PENDING_RECONCILIATION') AND next_retry_at<=? AND lease_until<? LIMIT 10", (time.time(), time.time())):
                            await self.purchase.process(row["attempt_id"])
                        await self.orders.reconcile_actions()
                if kind == "reconciliation" and time.time()-last_cleanup > 300:
                    self.cleanup()
                    last_cleanup = time.time()
                self.set_setting("worker_error_"+kind, "")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logging.warning("OTP worker %s: %s", kind, type(exc).__name__)
                try:
                    self.set_setting("worker_error_"+kind, type(exc).__name__)
                except sqlite3.Error:
                    pass
            await asyncio.sleep(self.config.poll_seconds if kind == "polling" else 2)

    async def start(self, bot):
        if any(not task.done() for task in self._tasks):
            return self._tasks
        if self.config.token and not self.config.error:
            try:
                await self.bootstrap_webhook()
            except StoreError:
                pass
        self._tasks = [asyncio.create_task(self.run_loop(kind, bot), name="smscode_otp_"+kind)
                       for kind in ("polling", "notifications", "reconciliation")]
        return self._tasks

    async def close(self):
        try:
            self.repo.execute("DELETE FROM otp_worker_leases WHERE owner=?", (self.worker_id,))
        finally:
            await self.api.close()


class OTPState(StatesGroup):
    search = State()
    admin_value = State()
    topup_amount = State()
    topup_proof = State()


class UserFormatter:
    """Public shop text; never format internal pricing, API or refund evidence."""

    @staticmethod
    def label(value):
        # Catalog labels can contain upstream branding/URLs. SMS bodies and OTP
        # codes never use this function: their original contents are preserved.
        text = re.sub(r"https?://[^\s<>]+", "", str(value or ""), flags=re.IGNORECASE)
        text = re.sub(r"\b(?:[a-z0-9_-]+\.)*smscode\.gg(?:/[^\s<>]*)?", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\bsmscode\b(?:\s*\.\s*gg\b)?", "", text, flags=re.IGNORECASE)
        return " ".join(text.split()).strip(" •|·-/") or "-"

    @staticmethod
    def status(value):
        return {"ACTIVE": "Menunggu SMS", "OTP_RECEIVED": "SMS diterima", "COMPLETED": "Selesai",
                "CANCELED": "Dibatalkan", "EXPIRED": "Kedaluwarsa", "FAILED": "Gagal",
                "RESERVED": "Sedang diproses", "REQUESTING": "Sedang diproses",
                "PENDING_RECONCILIATION": "Menunggu kepastian transaksi"}.get(value, "Sedang diperiksa")

    @staticmethod
    def refund_status(value):
        return {"NONE": "Belum ada refund", "REFUNDED": "Sudah masuk ke saldo",
                "AWAITING_PROVIDER_PROOF": "Menunggu konfirmasi pengembalian dana",
                "PARTIAL_RECONCILIATION": "Pengembalian dana sedang diperiksa",
                "REVIEW_REQUIRED": "Pengembalian dana sedang diperiksa"}.get(value, "Sedang diperiksa")

    @staticmethod
    def error(exc):
        # Select by code, rather than exposing API/config details or arbitrary
        # exception messages. Admin errors are handled in their own context.
        if getattr(exc, "code", "") == "FORBIDDEN" and getattr(exc, "public", "") in {
                "Menu ini hanya untuk owner.", "Akun kamu dibatasi owner."}:
            return exc.public
        return {
            "PRIVATE": "Gunakan /otp melalui chat privat bot.",
            "CHANNEL": "Akses mengikuti verifikasi channel bot. Buka /start dan ikuti petunjuk bergabung dahulu.",
            "FORBIDDEN": "Layanan OTP sementara belum tersedia. Hubungi owner.",
            "NOT_FOUND": "Pesanan atau produk tidak ditemukan.",
            "USER_BALANCE": "Saldo kamu tidak cukup. Gunakan tombol Isi Saldo di menu OTP.",
            "UNAUTHORIZED": "Pembelian OTP sementara belum tersedia. Hubungi owner.",
            "NOT_CONFIGURED": "Pembelian OTP sementara belum tersedia. Hubungi owner.",
            "CONFIG": "Pembelian OTP sementara belum tersedia. Hubungi owner.",
            "ENCRYPTION": "Data SMS sementara tidak tersedia. Hubungi owner.",
            "INSUFFICIENT_BALANCE": "Nomor sementara tidak dapat dibeli. Saldo yang ditahan untuk pembelian gagal akan dilepas.",
            "CANCEL_TOO_EARLY": "Nomor belum boleh dibatalkan. Tunggu sampai pembatalan tersedia.",
            "NO_OFFER_AVAILABLE": "Stok nomor habis atau harga berubah. Pilih produk kembali.",
            "PRICE_CHANGED": "Harga berubah. Pilih kembali produk untuk menyetujui harga terbaru.",
            "PRICE_LIMIT": "Produk ini belum tersedia untuk dibeli di toko.",
            "BELOW_COST": "Harga produk perlu diperbarui. Pilih produk lain atau hubungi owner.",
            "QUOTE_EXPIRED": "Konfirmasi harga kedaluwarsa. Pilih produk lagi.",
            "DISABLED": "Pembelian baru sedang ditutup. Pesanan lama tetap dipantau.",
            "ORDER_LIMIT": "Batas pesanan aktif tercapai. Selesaikan pesanan sebelumnya.",
            "COOLDOWN": "Batas atau jeda permintaan tercapai. Tunggu sebelum mencoba kembali.",
            "RATE_LIMIT_EXCEEDED": "Terlalu banyak permintaan. Coba kembali setelah jeda.",
            "TEMP_BANNED_ABUSE_GUARD": "Layanan meminta jeda penggunaan. Coba kembali nanti.",
            "REQUEST_IN_PROGRESS": "Transaksi sedang diproses; jangan membeli ulang.",
            "IDEMPOTENCY_KEY_REUSED": "Transaksi sedang diperiksa; jangan membeli ulang.",
            "NETWORK": "Hasil permintaan belum pasti. Periksa pesanan dan jangan membeli ulang.",
            "LOCAL_DATABASE": "Hasil tindakan sedang diperiksa; jangan mengulang.",
            "CONFLICT": "Tindakan belum tersedia untuk pesanan ini. Cek status pesanan.",
            "TOKEN": "Tombol kedaluwarsa atau bukan milik kamu. Buka /otp lagi.",
            "INPUT": "Perintah tidak valid. Gunakan /otp bantuan untuk format yang benar.",
            "RETENTION": "SMS sudah melewati masa penyimpanan.",
            "PAYMENT_PENDING": "QRIS untuk pembelian ini sudah dibuat. Periksa invoice di Pesanan Saya sebelum memilih pembayaran lain.",
            "PAYMENT_PAID": "Pembayaran sudah diterima atau sedang diproses. Periksa Pesanan Saya; jangan membayar ulang.",
            "PAYMENT_UNAVAILABLE": "Pembayaran saldo sementara ditahan. Coba kembali nanti atau hubungi owner.",
            "WALLET_ONLY": "Pembelian OTP memakai saldo bot. Pilih Buy Saldo atau Isi Saldo, lalu pilih nomor kembali.",
        }.get(getattr(exc, "code", ""), "Layanan OTP mengalami gangguan sementara. Coba kembali nanti.")


class OwnerFormatter:
    """Private dashboard text; balance is supplied by GET /balance only."""

    @staticmethod
    def dashboard(*, stats, settings, balance, api_status, attempts, notifications, worker_errors, config_error, details=False):
        if not details:
            attention = attempts+stats['refund_review']
            return (f"👑 <b>{ADMIN_BRAND}</b>\n📱 SMSCode.gg • Status API: {escape(api_status)}\n\n"
                    f"💰 Saldo provider: {escape(balance)}\n"
                    f"🛍️ Toko: {'ON' if settings['enabled'] else 'OFF'} • 📦 Aktif: {stats['pending']}\n"
                    f"🛒 Total penjualan: {stats['total']} • ✅ Selesai: {stats['completed']}\n"
                    f"💵 Omzet: {money(stats['revenue'])}\n📈 Profit kotor sementara: {money(stats['profit'])}\n"
                    f"📩 Notifikasi menunggu/gagal: {notifications} • ⚠️ Perlu diperiksa: {attention}\n\n"
                    "Pilih menu untuk melihat rincian dan pengaturan.")
        return (f"👑 <b>{ADMIN_BRAND}</b>\n📱 Provider: SMSCode.gg (v1 IDR)\n"
            f"🔌 Status API: {escape(api_status)}\n"
            f"💰 Saldo provider: {escape(balance)}\n🛒 Total penjualan: {stats['total']}\n"
            f"✅ Selesai: {stats['completed']} • ⏳ Aktif: {stats['pending']} • ❌ Terminal lain: {stats['canceled']}\n"
            f"💵 Omzet setelah refund: {money(stats['revenue'])}\n📈 Profit kotor sementara: {money(stats['profit'])}\n"
            f"📈 Markup: {escape(settings['percent'])}% • Tambahan: {money(settings['fixed'])}\n"
            f"⚙️ Mode harga: {escape(settings['mode'])}\n"
            f"⚠️ Refund perlu rekonsiliasi: {stats['refund_review']}\n⏳ Pembelian belum pasti: {attempts}\n"
            f"📩 Notifikasi pending/gagal: {notifications}\n🛍 Toko: {'ON' if settings['enabled'] else 'OFF'}\n"
            f"📦 Limit aktif: {settings['max_active']}/user\n🕒 Poll terakhir: {settings['last_poll_at'] or 'belum'}\n"
            f"Webhook terakhir: {settings['last_webhook_at'] or 'belum'}\n"
            f"Worker: {escape(worker_errors or settings['last_worker_error']) or 'Tidak ada error tercatat'}\n"
            f"Config: {escape(config_error) or 'valid'}\n"
            "OTP dan isi SMS user tidak ditampilkan di dashboard.")

    @staticmethod
    def dashboard_rows():
        return [
            [("💰 SALDO PROVIDER", "admin_balance", {}), ("📊 STATISTIK", "admin_stats", {})],
            [("⚙️ PENGATURAN HARGA", "admin_prices_menu", {}), ("📈 MARKUP & PROFIT", "admin_profit", {})],
            [("📦 SEMUA ORDER", "admin_orders", {}), ("⏳ PEMBELIAN PENDING", "admin_pending", {})],
            [("📩 STATUS AUTO SMS", "admin_status", {}), ("📩 WEBHOOK", "admin_webhook", {})],
            [("🟢 TOKO ON/OFF", "admin_toggle", {}), ("🛍️ TOKO PEMBELI", "shop", {})]]


class MenuMessage:
    """Edit the callback's menu; delivery notifications keep using send_message."""

    def __init__(self, message, *, message_id=None):
        self.message = message
        self.target_id = message_id if isinstance(message_id, int) and not isinstance(message_id, bool) and message_id > 0 else None

    def __getattr__(self, name):
        return getattr(self.message, name)

    async def answer(self, text, **kwargs):
        try:
            if self.target_id:
                return await self.message.bot.edit_message_text(text, chat_id=self.message.chat.id, message_id=self.target_id, **kwargs)
            if getattr(self.message, "text", None) is not None:
                return await self.message.edit_text(text, **kwargs)
        except TelegramBadRequest as exc:
            reason = exc.message.lower()
            if "message is not modified" in reason:
                return self.message
            if not any(value in reason for value in ("message to edit not found", "message can't be edited",
                                                     "message can not be edited", "there is no text")):
                raise
        # A missing menu or a payment photo cannot be edited as a text menu.
        # Network timeouts never reach this fallback: an edit may already exist.
        self.message = await self.message.bot.send_message(self.message.chat.id, text, **kwargs)
        self.target_id = None
        return self.message


class TopupState:
    """Use the existing proof handlers with a state isolated to the OTP menu."""

    def __init__(self, state, host):
        self.state, self.host = state, host

    def __getattr__(self, name):
        return getattr(self.state, name)

    async def get_state(self):
        current = await self.state.get_state()
        return self.host.CheckoutState.waiting_payment_proof.state if current == OTPState.topup_proof.state else current

    async def set_state(self, state):
        if state == self.host.CheckoutState.waiting_payment_proof or state == self.host.CheckoutState.waiting_payment_proof.state:
            state = OTPState.topup_proof
        await self.state.set_state(state)


class TopupBot:
    def __init__(self, bot, bridge, user):
        self.bot, self.bridge, self.user = bot, bridge, user

    def __getattr__(self, name):
        return getattr(self.bot, name)

    async def send_photo(self, chat_id, **kwargs):
        if chat_id == self.user and kwargs.get("reply_markup"):
            kwargs["reply_markup"] = self.bridge.keyboard(self.user, kwargs["reply_markup"])
        return await self.bot.send_photo(chat_id, **kwargs)


class TopupMessage(MenuMessage):
    def __init__(self, message, bridge, user, *, message_id=None):
        super().__init__(message, message_id=message_id)
        self.bridge, self.user = bridge, user

    @property
    def bot(self):
        return TopupBot(self.message.bot, self.bridge, self.user)

    async def answer(self, text, **kwargs):
        kwargs["reply_markup"] = self.bridge.keyboard(self.user, kwargs.get("reply_markup"))
        # Keep the original photo available to the host's cancellation cleanup.
        if self.target_id or getattr(self.message.from_user, "is_bot", False):
            result = await MenuMessage(self.message, message_id=self.target_id).answer(text, **kwargs)
        else:
            result = await self.message.answer(text, **kwargs)
        self.target_id = result.message_id
        return result

    async def edit_text(self, text, **kwargs):
        return await self.answer(text, **kwargs)

    async def edit_caption(self, **kwargs):
        kwargs["reply_markup"] = self.bridge.keyboard(self.user, kwargs.get("reply_markup"))
        return await self.message.edit_caption(**kwargs)


class TopupCall:
    def __init__(self, call, message, data, bridge, user):
        self.call, self.message, self.data = call, message, data
        self.bot = message.bot
        self.from_user = call.from_user if call else message.from_user

    def __getattr__(self, name):
        return getattr(self.call, name)

    async def answer(self, text=None, **kwargs):
        # The OTP router already acknowledged the callback before rendering.
        if text and self.call:
            try:
                return await self.call.answer(text, **kwargs)
            except Exception:
                return None
        if text:
            return await self.message.answer("⚠️ "+escape(text), parse_mode="HTML")


class TopupBridge:
    """Navigation adapter only: all invoices, proof checks and credits stay in the host."""

    def __init__(self, store):
        self.store = store

    def keyboard(self, user, keyboard=None):
        rows, mapped = [], keyboard is None
        for row in getattr(keyboard, "inline_keyboard", []) or []:
            buttons = []
            for button in row:
                data, action, payload = button.callback_data or "", None, {}
                fixed = {"wallet": "balance", "wallet:topup": "topup", "wallet:history": "topup_history",
                         "home": "home", "products": "countries", "noop": "topup_noop", "topup:custom": "topup_custom"}
                action = fixed.get(data)
                match = re.fullmatch(r"topup:(set|confirm|pay):([0-9]{1,19})", data)
                method = re.fullmatch(r"topupmethod:(qris|bank):([0-9]{1,19})", data)
                invoice = re.fullmatch(r"(proofsubmit|statuscheck|userproofback|proofback):topup:([0-9]{1,19})", data)
                cancel = re.fullmatch(r"topupcancel:([0-9]{1,19})", data)
                if match:
                    action, payload = "topup_"+match[1], {"amount": match[2]}
                elif method:
                    action, payload = "topup_"+method[1], {"amount": method[2]}
                elif invoice:
                    action = {"proofsubmit": "topup_proof", "statuscheck": "topup_status",
                              "userproofback": "topup_back", "proofback": "topup_back"}[invoice[1]]
                    payload = {"id": invoice[2]}
                elif cancel:
                    action, payload = "topup_cancel", {"id": cancel[1]}
                if action:
                    label = "🏠 Menu Awal" if action == "home" else "⬅️ Kembali" if button.text.startswith("⬅️") else button.text
                    # Proof/cancel buttons must remain usable throughout a deposit
                    # invoice, just like the host's original ownership-checked buttons.
                    token = (self.store.token(user, action, payload, ttl=86400) if action in {"topup_proof", "topup_cancel"}
                             else self.store.ui.callback(user, action, payload))
                    button = button.model_copy(update={"text": label, "callback_data": token})
                    mapped = True
                buttons.append(button)
            rows.append(buttons)
        if not mapped:
            return keyboard  # In particular, never change owner proof-review buttons.
        if not any(button.text == "⬅️ Kembali" for row in rows for button in row):
            rows.append([InlineKeyboardButton(text="⬅️ Kembali", callback_data=self.store.ui.callback(user, "balance"))])
        if not any(button.text == "🏠 Menu Awal" for row in rows for button in row):
            rows.append([InlineKeyboardButton(text="🏠 Menu Awal", callback_data=self.store.ui.callback(user, "home"))])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    async def exit(self, user, state):
        values = await state.get_data()
        current = await state.get_state()
        if current in {OTPState.topup_proof.state, self.store.host.CheckoutState.waiting_payment_proof.state}:
            entity, entity_id = self.store.host.payment_proof_data_target(values)
            if entity == "topup" and entity_id:
                await self.store.host.clear_matching_topup_proof_context(user, entity_id, TopupState(state, self.store.host))

    async def handle(self, message, user, action, payload, state, call=None):
        host = self.store.host
        native = message.message if isinstance(message, MenuMessage) else message
        menu = TopupMessage(native, self, user)
        proxy_state = TopupState(state, host)
        targets = {
            "topup": ("wallet:topup", host.wallet_topup, True),
            "topup_custom": ("topup:custom", host.wallet_topup_custom, True),
            "topup_history": ("wallet:history", host.wallet_history, False),
        }
        if action == "topup_noop":
            return
        if action in {"topup_set", "topup_confirm", "topup_pay", "topup_qris", "topup_bank"}:
            amount = host.parse_manual_topup_amount(str(payload.get("amount", "")))
            if amount is None:
                raise StoreError("INPUT", "Nominal isi saldo tidak valid.")
            verb = action.removeprefix("topup_")
            data = f"topupmethod:{verb}:{amount}" if verb in {"qris", "bank"} else f"topup:{verb}:{amount}"
            targets[action] = (data, getattr(host, "wallet_topup_method_"+verb if verb in {"qris", "bank"} else "wallet_topup_"+verb), verb in {"set", "confirm"})
        elif action in {"topup_status", "topup_proof", "topup_back", "topup_cancel"}:
            numbers = host.callback_positive_numbers("invoice:"+str(payload.get("id", "")), "invoice")
            if not numbers:
                raise StoreError("INPUT", "Invoice tidak valid.")
            entity_id = numbers[0]
            if not self.store.repo.one("SELECT id FROM topups WHERE id=? AND user_id=?", (entity_id, user)):
                raise StoreError("NOT_FOUND")
            prefix, handler, with_state = {
                "topup_status": ("statuscheck:topup", host.user_check_transaction_status, False),
                "topup_proof": ("proofsubmit:topup", host.payment_proof_start, True),
                "topup_back": ("userproofback:topup", host.payment_proof_back, True),
                "topup_cancel": ("topupcancel", host.user_cancel_topup, True),
            }[action]
            targets[action] = (f"{prefix}:{entity_id}", handler, with_state)
        if action not in targets:
            raise StoreError("INPUT")
        data, handler, with_state = targets[action]
        proxy = TopupCall(call, menu, data, self, user)
        await handler(proxy, proxy_state) if with_state else await handler(proxy)
        if action == "topup_proof" and await state.get_state() == OTPState.topup_proof.state:
            # SQLite FSM already persists this isolated upload. Do not arm the
            # host's generic media recovery after a user switches to another command.
            self.store.repo.execute("DELETE FROM payment_proof_sessions WHERE user_id=? AND entity_type='topup' AND entity_id=?",
                                    (user, entity_id))
        if action == "topup_custom" and await state.get_state() == host.OwnerState.topup_amount.state:
            await state.set_state(OTPState.topup_amount)
        if await state.get_state() in {OTPState.topup_amount.state, OTPState.topup_proof.state}:
            await state.update_data(otp_menu_message_id=menu.target_id or native.message_id)


class UIBuilder:
    def __init__(self, store):
        self.store = store

    def callback(self, user, action, payload=None):
        return self.store.token(user, action, payload, ttl=86400 if action in NAVIGATION_ACTIONS else 300)

    def keyboard(self, user, rows):
        if any(action.startswith("admin") for row in rows for _, action, _ in row) and not self.store.host.is_owner(user):
            raise StoreError("FORBIDDEN", "Menu ini hanya untuk owner.")
        return InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text=label[:64], callback_data=self.callback(user, action, payload))
            for label, action, payload in row] for row in rows])

    def admin_keyboard(self, user, rows):
        if not self.store.host.is_owner(user):
            raise StoreError("FORBIDDEN", "Menu ini hanya untuk owner.")
        return self.keyboard(user, rows)

    def home_keyboard(self, user):
        rows = [[("📱 BELI NOMOR OTP", "countries", {})],
                [("📦 PESANAN SAYA", "orders", {}), ("🔐 CEK KODE OTP", "orders", {})],
                [("➕ Isi Saldo", "topup", {}), ("💰 SALDO SAYA", "balance", {})],
                [("📜 RIWAYAT", "history", {}), ("❓ BANTUAN", "help", {})]]
        if self.store.host.is_owner(user):
            rows.append([("⚙️ OTP ADMIN", "admin", {})])
        keyboard = self.keyboard(user, rows)
        keyboard.inline_keyboard.append([InlineKeyboardButton(text="⬅️ Kembali", callback_data=self.callback(user, "main_menu"))])
        return keyboard

    def navigation(self, user, back="home", payload=None):
        return self.keyboard(user, [[("⬅️ Kembali", back, payload or {}), ("🏠 Menu Awal", "home", {})]])

    async def balance(self, message, user):
        rows = [[("➕ Isi Saldo", "topup", {}), ("📑 Riwayat Saldo", "topup_history", {})]]
        # Unfinished deposits remain reachable when the user leaves the invoice.
        invoices = self.store.repo.rows("""SELECT t.id,t.amount FROM topups t
            WHERE t.user_id=? AND t.status IN ('pending','processing')
              AND NOT EXISTS (SELECT 1 FROM otp_payments p WHERE p.topup_id=t.id)
              AND NOT EXISTS (SELECT 1 FROM sosmed_payments p WHERE p.topup_id=t.id)
            ORDER BY t.id DESC LIMIT 5""", (user,))
        for row in invoices:
            rows.append([(f"🧾 Isi Saldo #{row['id']} • {money(row['amount'])}", "topup_status", {"id": row["id"]})])
        rows.append([("⬅️ Kembali", "shop" if self.store.host.is_owner(user) else "home", {}), ("🏠 Menu Awal", "home", {})])
        await self.send(message, f"💰 <b>SALDO SAYA</b>\n\nSaldo kamu: <b>{money(self.store.host.get_balance(user))}</b>\n\n"
                        "Pilih Isi Saldo untuk menambah saldo melalui pembayaran bot. Saldo bertambah setelah pembayaran terkonfirmasi.", self.keyboard(user, rows))

    @staticmethod
    def order_text(order):
        return (f"🛍️ <b>{USER_BRAND}</b>\n🆔 Order: <b>#{order['id']}</b>\n"
                f"🌍 Negara: {escape(UserFormatter.label(order['country_name']))}\n📱 Layanan: {escape(UserFormatter.label(order['platform_name']))}\n"
                f"📶 Operator: {escape(UserFormatter.label(order['operator_name']))}\n📞 Nomor: <code>{escape(order['phone_number'])}</code>\n"
                f"💰 Harga: {money(order['selling_price_idr'])}\n⏳ Status: {UserFormatter.status(order['status'])}\n"
                f"🕒 Beli: {payment_receipts.format_wib(order['created_at'])}\n"
                f"⌛ Kedaluwarsa: {payment_receipts.format_wib(order['expires_at'])}\n"
                + (f"✅ Selesai: {payment_receipts.format_wib(order['completed_at'])}\n" if order.get('completed_at') else "")
                + f"↩️ Refund: {money(order['refund_idr'])} • {UserFormatter.refund_status(order['refund_state'])}")

    def order_keyboard(self, order, user, *, otp_code=None, copy_phone=True):
        oid = {"id": order["id"]}
        caps = json.loads(order["capabilities"])
        rows = [[("🔄 CEK OTP", "check", oid)]]
        if order["status"] in ACTIVE:
            if caps.get("can_resend"):
                rows.append([("📨 RESEND", "resend", oid)])
            if not order.get('last_sms_revision',0):
                rows.append([("❌ Batalkan Pesanan", "confirm_cancel", oid)])
            if caps.get("can_finish"):
                rows.append([("✅ SELESAI", "confirm_finish", oid)])
        elif caps.get("can_reactivate"):
            rows.append([("♻️ AKTIFKAN LAGI", "reactivate", oid)])
        rows.append([("⬅️ Kembali", "orders", {}), ("🏠 Menu Awal", "home", {})])
        keyboard = self.keyboard(user, rows)
        copies = []
        phone = str(order.get("phone_number") or "").strip()
        if copy_phone and phone and len(phone) <= 256:
            copies.append(InlineKeyboardButton(text="SALIN NOMOR", copy_text=CopyTextButton(text=phone)))
        # Copy only a real retained SMS code. Never infer a code from a phone
        # number/status or silently truncate codes exceeding Telegram's limit.
        if otp_code is not None and 0 < len(str(otp_code)) <= 256:
            copies.append(InlineKeyboardButton(text="SALIN OTP", copy_text=CopyTextButton(text=str(otp_code))))
        if copies:
            keyboard.inline_keyboard.insert(0, copies)
        return keyboard

    def receipt_view(self, order, data):
        """Compact single photo caption; full SMS remains encrypted in its store."""
        label=lambda value,limit:escape(UserFormatter.label(str(value))[:limit])
        phone=str(order.get('phone_number') or '')
        text=(f"✅ <b>PEMBELIAN BERHASIL</b>\n🛍️ <b>{USER_BRAND}</b>\n"
            +f"🧾 Invoice: <b>{escape(data['reference'])}</b>\n🆔 Order: #{order['id']}\n"
            +f"🌍 {label(order['country_name'],45)} • 📶 {label(order['operator_name'],30)}\n"
            +f"📱 {label(order['platform_name'],90)}\n📞 Nomor: <code>{escape(phone) if len(phone)<=40 else 'Gunakan Salin Nomor'}</code>\n"
            +f"💰 Total: <b>{money(data['amount'])}</b>\n⏳ Status: {UserFormatter.status(order['status'])}\n"
            +f"🕒 Beli: {payment_receipts.format_wib(order['created_at'])}\n⌛ Kedaluwarsa: {payment_receipts.format_wib(order['expires_at'])}\n")
        if order.get('refund_idr'):text+=f"↩️ Refund ke saldo: {money(order['refund_idr'])}\n"
        event=self.store.repo.one('SELECT * FROM otp_sms_events WHERE provider_order_id=? ORDER BY sms_revision DESC LIMIT 1',(order['provider_order_id'],))
        payload=self.store.decrypt(event['encrypted_payload']) if event and event['encrypted_payload'] else {}
        code=payload.get('otp_code')
        if code:
            text+=('🔐 OTP: <code>'+escape(str(code))+'</code>\n') if len(str(code))<=64 else '🔐 OTP tersedia melalui tombol / isi SMS lengkap.\n'
        elif payload:text+='📩 SMS diterima tanpa kode verifikasi.\n'
        else:text+='📩 SMS dikirim otomatis saat masuk.\n'
        keyboard=self.order_keyboard(order,order['buyer_user_id'],otp_code=code)
        if payload:
            keyboard.inline_keyboard.insert(-1,[InlineKeyboardButton(text='📩 Baca SMS Lengkap',callback_data=self.callback(order['buyer_user_id'],'read_sms',{'id':order['id']}))])
        return text,keyboard

    @staticmethod
    def sms_texts(order, payload, revision):
        header = (f"🛍️ <b>{USER_BRAND}</b>\n📩 <b>SMS OTP MASUK!</b>\n"
                  f"📱 {escape(UserFormatter.label(order['platform_name']))} • 🌍 {escape(UserFormatter.label(order['country_name']))}\n"
                  f"📞 <code>{escape(order['phone_number'])}</code>\n🆔 #{order['id']} • SMS ke-{revision}\n")
        code_parts = []
        if payload.get("otp_code"):
            code = escape(payload["otp_code"])
            if len(code) <= 1000:
                header += "🔐 KODE VERIFIKASI: <code>"+code+"</code>\n"
            else:
                # Preserve a long classified token without exceeding message limits.
                part = ""
                for character in payload["otp_code"]:
                    encoded_char = escape(character)
                    if len(part)+len(encoded_char) > 2500:
                        code_parts.append("🔐 KODE VERIFIKASI • #"+str(order["id"])+"\n<pre>"+part+"</pre>")
                        part = ""
                    part += encoded_char
                code_parts.append("🔐 KODE VERIFIKASI • #"+str(order["id"])+"\n<pre>"+part+"</pre>")
                header += "🔐 Kode panjang dikirim lengkap pada pesan berikutnya.\n"
        else:
            header += "📩 SMS diterima tanpa kode verifikasi.\n"
        message = payload.get("otp_message") or "Isi SMS belum tersedia."
        # Small escaped chunks also handle non-numeric SMS and Telegram's limit.
        chunks, part = [], ""
        for character in message:
            encoded_char = escape(character)
            if len(part)+len(encoded_char) > 2500:
                chunks.append(part)
                part = ""
            part += encoded_char
        chunks.append(part)
        return [(header if index == 0 else f"📩 SMS #{order['id']} • lanjutan {index+1}\n")+
                "📨 ISI SMS:\n<pre>"+chunk+"</pre>\n✅ OTP DITERIMA" for index, chunk in enumerate(chunks)] + code_parts

    async def send(self, message, text, keyboard=None, *, fresh=False):
        if keyboard is None and isinstance(message, MenuMessage) and not fresh:
            user = message.chat.id
            keyboard = self.navigation(user)
        options = {"reply_markup": keyboard, "parse_mode": "HTML", "link_preview_options": LinkPreviewOptions(is_disabled=True)}
        if fresh:
            return await message.bot.send_message(message.chat.id, text, **options)
        return await message.answer(text, **options)

    async def home(self, message, user):
        settings, api = self.store.settings(), self.store.api
        # Owner enablement is durable; API activity is not the store's ON/OFF
        # state. Idle shops and restarts must not turn an enabled shop unknown.
        status = "Aktif" if settings["enabled"] else "Ditutup owner"
        if not settings["enabled"]:
            note = "Pembelian baru ditutup. Pesanan lama tetap dipantau."
        elif self.store.config.error or not self.store.config.token or not self.store.has_encryption():
            note = "Pembelian belum tersedia; owner perlu melengkapi pengaturan toko."
        elif getattr(api, "blocked_until", 0) > time.time():
            note = "Layanan sedang jeda. Coba kembali setelah "+str(max(1, int(api.blocked_until-time.time())+1))+" detik."
        else:
            note = "Stok dan layanan diperiksa saat memilih nomor."
        profile = self.store.repo.one("SELECT username FROM verified_users WHERE user_id=?", (user,))
        username = profile["username"] if profile else ""
        if message.from_user and message.from_user.id == user:
            username = getattr(message.from_user, "username", "") or username
        identity = "@"+username.lstrip("@") if username else f"User {user}"
        mode = "🛍️ Mode pembeli • saldo wallet pribadi\n" if self.store.host.is_owner(user) else ""
        await self.send(message, f"🛍️ <b>{USER_BRAND}</b>\n🏠 <b>Menu Awal</b>\n👤 User: {escape(identity)}\n\n"
            + mode +
            f"💰 Saldo Kamu: <b>{money(self.store.host.get_balance(user))}</b>\n"
            f"🛍️ Status toko: {escape(status)}\n{escape(note)}\n\nPilih menu di bawah:", self.home_keyboard(user))

    async def selection(self, message, user, kind, payload=None, query=""):
        self.store.require_ready()
        payload = payload or {}
        page = max(0, min(int(payload.get("page", 0)), 1000))
        if kind == "countries":
            rows = await self.store.catalog.listing("/catalog/countries")
            rows = self.store.catalog.named_rows(rows)
            rows = [row for row in rows if query.casefold() in (str(row.get("name"))+str(row.get("code"))).casefold()]
            buttons = [(UserFormatter.label(row.get("emoji") or "🌍")+" "+UserFormatter.label(row["name"]), "services",
                        {"country": row["id"], "country_name": row["name"]}) for row in rows]
            title = "🌍 PILIH NEGARA"
        elif kind == "services":
            rows = await self.store.catalog.listing("/catalog/services", {"country_id": payload["country"]})
            rows = [row for row in self.store.catalog.named_rows(rows) if query.casefold() in row["name"].casefold()]
            buttons = [(UserFormatter.label(row["name"]), "operators", {**payload, "platform": row["id"], "platform_name": row["name"], "page": 0}) for row in rows]
            title = "📱 PILIH LAYANAN • "+escape(UserFormatter.label(payload.get("country_name")))
        elif kind == "operators":
            rows = await self.store.catalog.listing("/catalog/operators", {"country_id": payload["country"], "platform_id": payload["platform"]})
            rows = self.store.catalog.named_rows(rows, operators=True)
            if not rows:
                rows = [{"operator_id": None, "name": "Any"}]
            buttons = [(UserFormatter.label(row.get("name") or "Any"), "products", {**payload, "operator": row["operator_id"], "operator_name": row.get("name") or "Any", "page": 0}) for row in rows]
            title = "📶 PILIH OPERATOR"
        else:
            rows, more = await self.store.catalog.products(payload["country"], payload["platform"], payload.get("operator"), page+1, limit=8)
            buttons = []
            for row in rows[:8]:
                try:
                    sale, _ = self.store.pricing.calculate(row)
                    if integer(row["price"]) > self.store.config.max_cost:
                        continue
                    product = {**row, "country_name": payload["country_name"], "platform_name": payload["platform_name"]}
                    buttons.append((f"{money(sale)} • Stok {row['available']}", "quote", {"product": product}))
                except StoreError:
                    continue
            title = "🛒 PRODUK TERSEDIA • "+escape(UserFormatter.label(payload["platform_name"]))+" / "+escape(UserFormatter.label(payload["country_name"]))
            keyboard_rows = [[button] for button in buttons]
            nav = []
            if page:
                nav.append(("⬅️", kind, {**payload, "page": page-1}))
            if more:
                nav.append(("➡️", kind, {**payload, "page": page+1}))
            if nav:
                keyboard_rows.append(nav)
            keyboard_rows.append([("⬅️ Kembali", "operators", {**payload, "page": 0}), ("🏠 Menu Awal", "home", {})])
            return await self.send(message, title+f"\nHalaman {page+1}\n\n"+("Pilih harga nomor:" if buttons else "Belum ada stok pada halaman ini."), self.keyboard(user, keyboard_rows))
        subset = buttons[page*8:(page+1)*8]
        keyboard_rows = [[button] for button in subset]
        nav = []
        if page:
            nav.append(("⬅️", kind, {**payload, "page": page-1, "query": query}))
        if len(buttons) > (page+1)*8:
            nav.append(("➡️", kind, {**payload, "page": page+1, "query": query}))
        if nav:
            keyboard_rows.append(nav)
        if kind in {"countries", "services"}:
            keyboard_rows.append([("🔎 CARI", "search", {"kind": kind, "context": {**payload, "page": 0}})])
        back = {"countries": "home", "services": "countries", "operators": "services"}[kind]
        keyboard_rows.append([("⬅️ Kembali", back, {**payload, "page": 0, "query": ""}), ("🏠 Menu Awal", "home", {})])
        await self.send(message, title+f"\nHalaman {page+1} • {len(buttons)} pilihan\n"+("Pilih menu:" if subset else "Tidak ada hasil."), self.keyboard(user, keyboard_rows))

    async def quote(self, message, user, quote):
        product = json.loads(quote["product"])
        balance = self.store.host.get_balance(user)
        after = ("Saldo setelah beli: "+money(balance-quote["selling_price_idr"]) if balance >= quote["selling_price_idr"]
                 else "Saldo belum cukup. Pilih Isi Saldo, lalu pilih nomor kembali.")
        await self.send(message, "🛒 <b>KONFIRMASI "+("REAKTIVASI" if quote["parent_order_id"] else "PEMBELIAN")+"</b>\n\n"
            f"🌍 Negara: {escape(UserFormatter.label(product['country_name']))}\n📱 Layanan: {escape(UserFormatter.label(product['platform_name']))}\n"
            f"📶 Operator: {escape(UserFormatter.label(product.get('operator_name') or 'Any'))}\n"
            f"💰 Harga: <b>{money(quote['selling_price_idr'])}</b>\n💳 Saldo: {money(balance)}\n"
            f"{after}\n"
            f"⏳ Harga berlaku {self.store.config.quote_ttl} detik sebelum konfirmasi.\n"
            "Pilih saldo bot atau QRIS manual. Pembelian gagal terkonfirmasi dikembalikan ke saldo bot.",
            self.keyboard(user, [[("💰 BUY SALDO", "buy", {"quote": quote["quote_id"]})],
                                 *([[('📱 QRIS MANUAL', 'pay_manual', {'quote':quote['quote_id']})]] if self.store.payments.manual_ready() else []),
                                 [("➕ Isi Saldo", "topup", {})],
                                 [("⬅️ Kembali", "products", {"country": product['country_id'], "platform": product['platform_id'],
                                     "country_name": product['country_name'], "platform_name": product['platform_name'],
                                     "operator": product.get('operator_id'), "operator_name": product.get('operator_name')})] if not quote["parent_order_id"] else [("⬅️ Kembali", "check", {"id": quote["parent_order_id"]})],
                                 [("🏠 Menu Awal", "home", {})]]))

    async def manual_payment_photo(self, message, user, payment, caption, keyboard):
        """One owned manual invoice = one photo with its caption and buttons.

        Refresh edits the recorded photo. Only a confirmed missing photo may be
        sent again; an uncertain Telegram delivery never creates another copy.
        The purchase/payment/wallet lifecycle is deliberately not involved.
        """
        funding, payment_id = self.store.payments, payment['payment_id']
        funding.expire_manual_due()
        payment=funding.owned(user,payment_id)
        if not funding.pending(payment):
            return await UIBuilder.payment(self,message,user,payment_id)
        native = getattr(message,'message',message)
        if payment['qr_delivery_state']=='SENT' and payment['qr_message_id']:
            try:
                sent = await message.bot.edit_message_caption(chat_id=user,message_id=payment['qr_message_id'],
                    caption=caption,reply_markup=keyboard,parse_mode='HTML')
            except TelegramBadRequest as exc:
                reason = exc.message.lower()
                if 'message is not modified' in reason:
                    sent = native
                elif 'message to edit not found' in reason:
                    changed = self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='PENDING',qr_message_id=NULL WHERE payment_id=? AND qr_delivery_state='SENT' AND qr_message_id=? AND state='PENDING' AND paid_at IS NULL",(payment_id,payment['qr_message_id']))
                    if not changed:
                        return
                    payment = funding.owned(user,payment_id)
                    return await UIBuilder.manual_payment_photo(self,message,user,payment,caption,keyboard)
                else:
                    raise
            # Network failures escape; the known photo can be edited on the next
            # click. They must never fall through to send_photo.
        else:
            claimed = self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='SENDING' WHERE payment_id=? AND user_id=? AND state='PENDING' AND paid_at IS NULL AND qr_delivery_state='PENDING'",(payment_id,user))
            if not claimed:
                # A concurrent click must not replace an in-flight delivery.
                current = funding.owned(user,payment_id)
                if current['qr_delivery_state']=='SENT' and current['qr_message_id']:
                    return await UIBuilder.manual_payment_photo(self,message,user,current,caption,keyboard)
                if current['qr_delivery_state']=='UNKNOWN':
                    return await self.send(message,'⚠️ Pengiriman gambar QRIS belum dapat dipastikan. Periksa foto pada chat ini atau hubungi owner; jangan membayar dua kali.',self.navigation(user))
                return
            image = payment['qr_url'] or self.store.host.get_setting('qris_file_id','')
            if not image:
                self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='PENDING' WHERE payment_id=? AND qr_delivery_state='SENDING'",(payment_id,))
                return await self.send(message,'⚠️ Gambar QRIS belum tersedia. Jangan membayar sebelum gambar muncul; hubungi owner.',self.navigation(user))
            try:
                sent = await message.bot.send_photo(user,photo=image,caption=caption,reply_markup=keyboard,parse_mode='HTML')
            except TelegramBadRequest:
                self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='PENDING' WHERE payment_id=? AND qr_delivery_state='SENDING'",(payment_id,))
                return await self.send(message,'⚠️ Gambar QRIS belum dapat ditampilkan. Coba buka invoice kembali atau hubungi owner.',self.navigation(user))
            except asyncio.CancelledError:
                self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='UNKNOWN' WHERE payment_id=? AND qr_delivery_state='SENDING'",(payment_id,))
                raise
            except Exception:
                self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='UNKNOWN' WHERE payment_id=? AND qr_delivery_state='SENDING'",(payment_id,))
                raise
            self.store.repo.execute(f"UPDATE {funding.table} SET qr_message_id=?,qr_delivery_state='SENT' WHERE payment_id=? AND qr_delivery_state='SENDING'",(sent.message_id,payment_id))
            if payment['topup_id']:
                self.store.host.save_topup_payment_message(payment['topup_id'],user,sent.message_id)
        # Migrate an older split text invoice only when this exact owned reference
        # is visible in the source. Never delete a home menu, quote or receipt.
        old_text = getattr(native,'text',None) or ''
        source_id = getattr(message,'target_id',None) or getattr(native,'message_id',None)
        funding.expire_manual_due()
        current = funding.owned(user,payment_id)
        if (source_id and source_id!=current['qr_message_id'] and getattr(native.chat,'id',None)==user
                and payment['partner_reference'] in old_text and 'QRIS MANUAL' in old_text
                and 'Invoice:' in old_text and 'Total bayar:' in old_text):
            await self.store.host.retire_topup_payment_message(message.bot,user,source_id)
        # Owner approval may race the Telegram request. Retire the QR promptly;
        # do not leave fresh payment controls on an already-final invoice.
        if not funding.pending(current):
            if await self.store.host.retire_topup_payment_message(message.bot,user,current['qr_message_id']):
                self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='RETIRED' WHERE payment_id=? AND qr_message_id=?",(payment_id,current['qr_message_id']))
        return sent

    async def payment(self, message, user, payment_id):
        # Shared invoice presentation; each store keeps its own namespace and
        # order UI while using the same owner proof/confirmation flow.
        funding = self.store.payments
        funding.expire_manual_due()
        brand, subject = funding.brand, funding.subject
        callback = lambda action: self.store.token(user,action,{},ttl=86400)
        payment = self.store.payments.owned(user, payment_id)
        if payment["method"] == "QRIS_MANUAL" and payment["state"] in {'PAID','BUYING','COMPLETED','WALLET_CREDITED','CANCELLED','EXPIRED'}:
            if payment['qr_message_id'] and payment['qr_delivery_state']=='SENT':
                if await self.store.host.retire_topup_payment_message(message.bot,user,payment['qr_message_id']):
                    self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='RETIRED' WHERE payment_id=? AND qr_message_id=?",(payment_id,payment['qr_message_id']))
        if payment["attempt_id"]:
            order = self.store.repo.one(f"SELECT * FROM {funding.order_table} WHERE attempt_id=? AND {funding.order_user}=?", (payment["attempt_id"], user))
            if order:
                if await self.store.host.PAYMENT_RECEIPTS.present(message.bot,'otp_order' if funding.wallet_prefix=='OTP' else 'sosmed',order['id'],user=user,force=True):
                    return
                return await self.send(message, self.order_text(order), funding.order_card_keyboard(self,order,user))
        state, active = payment["state"], funding.pending(payment)
        if payment["method"] != "QRIS_MANUAL":
            if active and state == "PENDING":
                claimed = self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='SENDING' WHERE payment_id=? AND qr_delivery_state='PENDING'", (payment_id,))
                if claimed:
                    try:
                        image = payment["qr_url"] or (self.store.host.get_setting("qris_file_id", "") if payment["method"] != "AUTO_QRIS" else '')
                        if not image and payment["qr_payload"]:
                            content = self.store.decrypt(payment["qr_payload"])["qr_content"]
                            image = BufferedInputFile(await asyncio.to_thread(qr_image, content), filename="MaboyyOTPQRIS.png")
                        if not image:
                            raise StoreError("PAYMENT_UNAVAILABLE")
                        sent = await message.bot.send_photo(user, photo=image,
                            caption=f"🛍️ {brand}\n🧾 {payment['partner_reference']}\n💳 Total: {money(payment['payment_total_idr'])}\n"
                                    +('Tanpa kedaluwarsa. Kirim bukti untuk konfirmasi owner.' if not payment['expires_at'] else 'Bayar satu kali sesuai total invoice sebelum kedaluwarsa.'))
                        self.store.repo.execute(f"UPDATE {funding.table} SET qr_message_id=?,qr_delivery_state='SENT' WHERE payment_id=?", (sent.message_id, payment_id))
                        if payment["topup_id"]:
                            self.store.host.save_topup_payment_message(payment["topup_id"], user, sent.message_id)
                    except (TelegramBadRequest, StoreError):
                        self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='PENDING' WHERE payment_id=?", (payment_id,))
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        self.store.repo.execute(f"UPDATE {funding.table} SET qr_delivery_state='UNKNOWN' WHERE payment_id=?", (payment_id,))
        payment = self.store.payments.owned(user, payment_id)
        state = payment["state"]
        active = funding.pending(payment)
        awaiting = active and funding.awaiting_owner(payment)
        label = {"CREATING":"QRIS sedang disiapkan", "CREATE_UNKNOWN":"Hasil pembuatan QRIS sedang diperiksa",
                 "PENDING":"Menunggu pembayaran", "PAID":f"Pembayaran diterima, {subject} sedang diproses",
                 "BUYING":f"Pembelian {subject} sedang diproses", "COMPLETED":f"{subject.capitalize()} berhasil dibeli",
                 "WALLET_CREDITED":"Dana tersedia di saldo bot", "CANCELLED":"Invoice dibatalkan",
                 "EXPIRED":"Invoice kedaluwarsa"}.get(state, "Sedang diperiksa")
        if awaiting:label='Bukti tersimpan • menunggu konfirmasi owner'
        rows = []
        if active and not awaiting and payment["topup_id"]:
            rows.append([InlineKeyboardButton(text="📤 KIRIM BUKTI PEMBAYARAN", callback_data=f"proofsubmit:topup:{payment['topup_id']}")])
        ttl = max(300, min(3600, int(payment["expires_at"]-time.time())+300)) if payment['expires_at'] and not awaiting else 86400
        token = lambda action: self.store.token(user, action, {"payment": payment_id}, ttl=ttl)
        rows.append([InlineKeyboardButton(text="🔄 CEK PEMBAYARAN", callback_data=token("payment_status"))])
        if active:
            rows.append([InlineKeyboardButton(text="❌ BATALKAN INVOICE", callback_data=token("payment_cancel"))])
        rows.append([InlineKeyboardButton(text="⬅️ Kembali", callback_data=callback("orders")),
                     InlineKeyboardButton(text="🏠 Menu Awal", callback_data=callback("home"))])
        text = (f"🛍️ <b>{brand}</b>\n💳 <b>QRIS {'MANUAL' if payment['method']=='QRIS_MANUAL' else 'OTOMATIS'}</b>\n\n"
                f"🧾 Invoice: <b>{escape(payment['partner_reference'])}</b>\n"
                f"💰 Harga {subject}: {money(payment['amount_idr'])}\n"
                f"🔢 Kode unik: {money(payment['payment_total_idr']-payment['amount_idr'])}\n"
                f"💳 Total bayar: <b>{money(payment['payment_total_idr'])}</b>\n"
                + ('⌛ Konfirmasi owner tanpa batas waktu\n' if awaiting else f"⌛ Berlaku sampai: {payment_receipts.format_wib(payment['expires_at'])} (15 menit)\n" if payment['expires_at'] and payment['method']=='QRIS_MANUAL' else f"⌛ Berlaku sampai: {payment_receipts.format_wib(payment['expires_at'])}\n" if payment['expires_at'] else '⌛ Tanpa kedaluwarsa • konfirmasi owner\n')
                +
                f"⏳ Status: {label}\n\n")
        if active:
            text += ('Bukti sudah tersimpan; tidak perlu transfer atau mengirim bukti lagi. ' if awaiting else "Pembayaran QRIS diperiksa otomatis. " if payment["method"] == "AUTO_QRIS"
                     else "Kirim bukti pembayaran untuk verifikasi owner. ")
            text += f"{subject.capitalize()} diproses otomatis setelah pembayaran terkonfirmasi. Bayar satu kali sesuai total invoice.\n"
            if payment["method"] != "QRIS_MANUAL" and payment["qr_delivery_state"] != "SENT":
                text += "⚠️ Gambar QRIS belum berhasil ditampilkan. Jangan membayar sebelum QRIS tersedia; hubungi owner.\n"
        elif state in {"CANCELLED", "EXPIRED"}:
            text += "Jangan bayar invoice ini. Jika pembayaran terlambat terkonfirmasi, dana masuk ke saldo bot.\n"
        elif state == "WALLET_CREDITED":
            text += f"{subject.capitalize()} belum dibeli. Gunakan saldo untuk membeli kembali; tidak perlu membayar QRIS lagi.\n"
        text += 'Pembelian gagal terkonfirmasi dikembalikan ke saldo bot. Hasil yang belum pasti diperiksa dahulu.'
        if payment['payment_total_idr'] > payment['amount_idr']:
            text += " Kode unik tidak dikembalikan sebagai saldo."
        keyboard = InlineKeyboardMarkup(inline_keyboard=rows)
        if payment["method"] == "QRIS_MANUAL" and active and state == 'PENDING':
            return await UIBuilder.manual_payment_photo(self,message,user,payment,text,keyboard)
        return await self.send(message, text, keyboard)

    async def history(self, message, user, history=False, page=0, admin=False):
        if admin and not self.store.host.is_owner(user):
            raise StoreError("FORBIDDEN")
        clause, args = ("1=1", []) if admin else ("buyer_user_id=?", [user])
        if not history and not admin:
            clause += " AND status IN ('ACTIVE','OTP_RECEIVED')"
        rows = self.store.repo.rows("SELECT * FROM otp_orders WHERE "+clause+" ORDER BY id DESC LIMIT 6 OFFSET ?", (*args, max(0, page)*5))
        text, buttons = [f"👑 <b>{ADMIN_BRAND}</b>\n📦 SEMUA ORDER" if admin else "📜 <b>RIWAYAT OTP</b>" if history else "📦 <b>PESANAN OTP</b>"], []
        for order in rows[:5]:
            if admin:
                text.append(f"#{order['id']} • Buyer {order['buyer_user_id']} • {escape(order['platform_name'])} • {escape(order['status'])} • {money(order['selling_price_idr'])} • Modal {money(order['provider_cost_idr'])} • Refund {money(order['refund_idr'])}")
            else:
                summary = (f"🆔 <b>#{order['id']}</b> • {escape(UserFormatter.label(order['platform_name']))} / {escape(UserFormatter.label(order['country_name']))}\n"
                           f"📞 <code>{escape(order['phone_number'])}</code> • 💰 {money(order['selling_price_idr'])}\n"
                           f"⏳ {UserFormatter.status(order['status'])}")
                if order['refund_state'] != 'NONE':
                    summary += f"\n↩️ {money(order['refund_idr'])} • {UserFormatter.refund_status(order['refund_state'])}"
                text.append(summary)
                buttons.append([(f"🔎 #{order['id']}", "check", {"id": order["id"]})])
        if not rows:
            text.append("Belum ada pesanan.")
        pending = self.store.repo.rows("SELECT attempt_id,state,hold_idr FROM otp_purchase_attempts WHERE user_id=? AND state IN ('RESERVED','REQUESTING','PENDING_RECONCILIATION')", (user,))
        if not admin:
            for item in pending:
                text.append(f"⏳ {UserFormatter.status(item['state'])} • Saldo ditahan {money(item['hold_idr'])}; jangan membeli ulang.")
            payments = self.store.repo.rows("SELECT * FROM otp_payments WHERE user_id=? AND state IN ('CREATING','CREATE_UNKNOWN','PENDING','PAID') ORDER BY created_at DESC LIMIT 5", (user,))
            for payment in payments:
                text.append(f"💳 QRIS {escape(payment['partner_reference'])} • {money(payment['payment_total_idr'])}\n"
                            + ("Pembayaran diterima, nomor sedang diproses." if payment['state'] == 'PAID' else "Periksa invoice pembayaran."))
                buttons.append([("💳 "+payment['partner_reference'], "payment_status", {"payment": payment['payment_id']})])
        nav, action = [], "admin_orders" if admin else "history" if history else "orders"
        if page:
            nav.append(("⬅️", action, {"page": page-1}))
        if len(rows) > 5:
            nav.append(("➡️", action, {"page": page+1}))
        if nav:
            buttons.append(nav)
        buttons.append([("⬅️ Kembali", "home", {}), ("🏠 Menu Awal", "home", {})])
        await self.send(message, "\n\n".join(text), self.admin_keyboard(user, buttons) if admin else self.keyboard(user, buttons))

    async def check(self, message, user, order_id, *, full_sms=False):
        order = self.store.repo.owned(user, order_id)
        self.store.repo.rate(user, "status", 10, 60)
        try:
            await self.store.orders.refresh(order)
        except StoreError:
            pass
        order = self.store.repo.owned(user, order_id)
        if not full_sms:
            shown=await self.store.host.PAYMENT_RECEIPTS.present(message.bot,'otp_order',order_id,user=user,force=True)
            if shown:
                await self.store.host.PAYMENT_RECEIPTS.retire_source(message,user,'otp_order',order_id)
                return
        text = self.order_text(order)
        event = self.store.repo.one("SELECT * FROM otp_sms_events WHERE provider_order_id=? ORDER BY sms_revision DESC LIMIT 1", (order["provider_order_id"],))
        if event and event["encrypted_payload"]:
            payload = self.store.decrypt(event["encrypted_payload"])
            parts = self.sms_texts(order, payload, event["sms_revision"])
            if full_sms:
                for index,part in enumerate(parts):
                    await self.send(message,part,self.navigation(user,'check',{'id':order_id}) if index==len(parts)-1 else None,fresh=True)
                return
            if len(text)+len(parts[0]) <= 3900:
                text += "\n\n"+parts.pop(0)
            await self.send(message, text, self.navigation(user,'check',{'id':order_id}) if full_sms else self.order_keyboard(order, user, otp_code=payload.get("otp_code")))
            for part in parts:
                await self.send(message, part, fresh=True)
        else:
            await self.send(message, text+"\n\n📩 SMS belum diterima atau sudah melewati masa retensi. Tombol Salin OTP muncul setelah kode tersedia.", self.order_keyboard(order, user))


HELP = (f"🛍️ <b>{USER_BRAND}</b>\n❓ CARA BELI OTP\n\n"
        "1. Pilih negara, layanan, dan nomor.\n"
        "2. Pilih <b>Buy Saldo</b> atau <b>QRIS Manual</b> jika tersedia.\n"
        "3. QRIS manual diproses setelah owner mengonfirmasi pembayaran; saldo memakai wallet bot.\n"
        "4. SMS dan kode OTP masuk otomatis ke chat ini.\n\n"
        "Cek, resend, selesai, dan batal tersedia di Pesanan Saya sesuai status nomor. "
        "Refund yang terkonfirmasi masuk ke saldo bot. Buka /otp untuk kembali.")

COMMAND_HELP = (f"🛍️ <b>{USER_BRAND}</b>\n❓ PANDUAN TOKO OTP\n\n"
    "/otp — menu toko\n/otp beli • /otp negara — pilih negara\n/otp layanan — pilih layanan\n"
    "/otp saldo — saldo bot kamu\n/otp isi — isi saldo\n/otp pesanan — pesanan aktif\n/otp cek &lt;id&gt; — nomor dan SMS\n"
    "/otp ulang &lt;id&gt; — minta SMS baru jika tersedia\n/otp batal &lt;id&gt; — konfirmasi pembatalan\n"
    "/otp selesai &lt;id&gt; — konfirmasi selesai\n/otp riwayat — riwayat pribadi\n"
    "/otp aktifkan &lt;id&gt; — reaktivasi berbayar jika didukung\n/otp bantuan — panduan\n\n"
    "Gunakan ID order bot (#), bukan ID order orang lain. SMS dikirim otomatis ke chat privat ini. "
    "Saldo ditahan saat pemesanan dan ditagihkan setelah nomor terkonfirmasi. "
    "Refund masuk ke saldo setelah pembatalan dan pengembalian dana terkonfirmasi. "
    "Pengembalian dana yang belum pasti ditinjau owner.")


class AdminHandler:
    def __init__(self, store):
        self.store = store

    def authorize(self, user):
        if not self.store.host.is_owner(user):
            raise StoreError("FORBIDDEN", "Menu ini hanya untuk owner.")

    @staticmethod
    def price_label(value, fallback, limit=60):
        value = value if isinstance(value, str) and value.strip() else fallback
        value = " ".join("".join(char for char in value if char.isprintable() or char.isspace()).split())
        label = ""
        for char in value or fallback:
            escaped = escape(char)
            if len(label)+len(escaped) > limit:
                break
            label += escaped
        return label

    async def price_services(self, message, user, *, page, country, platform):
        self.authorize(user)
        context = {"kind": "both", "view": "services", "country": country, "platform": platform}
        title, buttons = "📋 <b>HARGA PROVIDER &amp; JUAL</b>\n📱 Pilih layanan SMSCode", []
        try:
            rows = await self.store.catalog.listing("/catalog/services", {"country_id": country} if country is not None else None)
        except StoreError as exc:
            text = title+"\n\n⚠️ Daftar layanan belum dapat diambil. "+escape(exc.public)
            buttons.append([("🔄 Coba Lagi", "admin_prices", {**context, "page": page})])
        else:
            services, seen = [], set()
            for row in rows:
                try:
                    ident = integer(row.get("id"), 1, 2**31-1)
                except StoreError:
                    continue
                if row.get("active") is not True or ident in seen or not isinstance(row.get("name"), str) or not row["name"].strip():
                    continue
                services.append(row)
                seen.add(ident)
            pages = max(1, (len(services)+7)//8)
            page = min(page, pages)
            text = title+f"\nHalaman {page}/{pages}\n\n"+("Pilih layanan untuk melihat modal dan harga jual." if services else "Belum ada layanan aktif.")
            for row in services[(page-1)*8:page*8]:
                label = html.unescape(self.price_label(row["name"], f"Layanan #{row['id']}", 160))
                buttons.append([("📱 "+label, "admin_prices", {"kind": "both", "country": country, "platform": row["id"], "page": 1, "services_page": page})])
            navigation = []
            if page > 1:
                navigation.append(("◀️ Sebelumnya", "admin_prices", {**context, "page": page-1}))
            if page < pages:
                navigation.append(("Berikutnya ▶️", "admin_prices", {**context, "page": page+1}))
            if navigation:
                buttons.append(navigation)
        buttons.append([("⬅️ Kembali", "admin_prices", {"kind": "both", "country": country, "platform": platform}), ("🏠 Menu Awal", "home", {})])
        return await self.store.ui.send(message, text, self.store.ui.admin_keyboard(user, buttons))

    async def prices(self, message, user, kind=None, *, page=1, country=None, platform=None, view="products", services_page=1):
        self.authorize(user)
        kind = "both" if kind is None else kind
        if not isinstance(kind, str) or kind not in {"provider", "jual", "both"}:
            raise StoreError("INPUT", "Buka daftar Harga Provider & Jual.")
        if not isinstance(view, str) or view not in {"products", "services"}:
            raise StoreError("INPUT", "Halaman harga tidak valid.")
        page = self.number(page, 1, 10000)
        services_page = self.number(services_page, 1, 10000)
        country = self.number(country, 1, 2**31-1) if country is not None else None
        platform = self.number(platform, 1, 2**31-1) if platform is not None else None
        if view == "services":
            return await self.price_services(message, user, page=page, country=country, platform=platform)
        params = {"page": page, "limit": 8, "sort": "price_asc"}
        if country is not None:
            params["country_id"] = country
        if platform is not None:
            params["platform_id"] = platform
        context = {"kind": "both", "country": country, "platform": platform, "services_page": services_page}
        title = "📋 <b>HARGA PROVIDER &amp; JUAL</b>"
        buttons = []
        try:
            rows = await self.store.catalog.listing("/catalog/products", params)
        except StoreError as exc:
            text = title+"\n\n⚠️ Daftar harga belum dapat diambil. "+escape(exc.public)
            buttons.append([("🔄 Coba Lagi", "admin_prices", {**context, "page": page})])
        else:
            # Provider names enrich this read-only owner view; a failed name
            # lookup must not hide live modal/sale prices or change checkout.
            results = await asyncio.gather(
                self.store.catalog.listing("/catalog/services", {"country_id": country} if country is not None else None),
                self.store.catalog.listing("/catalog/countries"), return_exceptions=True)
            names, incomplete = [], False
            for result in results:
                lookup = {}
                if isinstance(result, list):
                    for item in result:
                        try:
                            ident = integer(item.get("id"), 1, 2**31-1)
                        except StoreError:
                            continue
                        lookup.setdefault(ident, item)
                else:
                    incomplete = True
                names.append(lookup)
            service_names, country_names = names
            selected = self.price_label(service_names.get(platform, {}).get("name"), f"Layanan #{platform}") if platform is not None else "Semua layanan"
            text, shown, invalid, groups = [f"{title} • halaman {page}\n📱 {selected}\nModal dan jual per nomor"], 0, 0, {}
            for row in rows[:8]:
                if row.get("active") is not True:
                    continue
                try:
                    stock, cost, ident = integer(row.get("available")), integer(row.get("price")), integer(row.get("id"), 1)
                    country_id, platform_id = integer(row.get("country_id"), 1, 2**31-1), integer(row.get("platform_id"), 1, 2**31-1)
                    operator_id = row.get("operator_id")
                    if operator_id is not None:
                        integer(operator_id, 1, 2**31-1)
                except StoreError:
                    invalid += 1
                    continue
                if not stock:
                    continue
                if (country is not None and country_id != country) or (platform is not None and platform_id != platform):
                    continue
                if service_names.get(platform_id, {}).get("active") is False or country_names.get(country_id, {}).get("active") is False:
                    continue
                try:
                    sale, _ = self.store.pricing.calculate(row)
                    selling = money(sale)
                except (StoreError, InvalidOperation, KeyError, TypeError, ValueError):
                    # A stale override must not hide a valid provider price.
                    selling = "Perlu memperbarui aturan harga"
                service = self.price_label(service_names.get(platform_id, {}).get("name") or row.get("platform_name"), f"Layanan #{platform_id}")
                country_name = self.price_label(country_names.get(country_id, {}).get("name") or row.get("country_name"), f"Negara #{country_id}", 48)
                operator = self.price_label(row.get("operator_name"), "Any" if operator_id is None else f"Operator #{operator_id}", 32)
                entry = f"🌍 {country_name} • 📶 {operator}\nModal {money(cost)} • Jual {selling}\nStok {stock} • Produk {ident}"
                groups.setdefault(platform_id, (service, []))[1].append(entry)
                shown += 1
            for service, entries in groups.values():
                text.append("📱 <b>"+service+"</b>\n"+"\n\n".join(entries))
            if not shown:
                text.append("Belum ada produk aktif dan tersedia pada halaman ini.")
            if invalid:
                text.append(f"⚠️ {invalid} data produk belum valid; tidak ditampilkan.")
            if incomplete:
                text.append("ℹ️ Nama katalog belum lengkap; harga berasal dari produk live.")
            text = "\n\n".join(text)
            navigation = []
            if page > 1:
                navigation.append(("◀️ Sebelumnya", "admin_prices", {**context, "page": page-1}))
            if len(rows) >= 8:
                navigation.append(("Berikutnya ▶️", "admin_prices", {**context, "page": page+1}))
            if navigation:
                buttons.append(navigation)
        buttons.append([("📱 Pilih Layanan" if platform is None else "📱 Ganti Layanan", "admin_prices", {"kind": "both", "view": "services", "country": country, "platform": platform, "page": services_page})])
        if platform is not None:
            buttons.append([("🌐 Semua Layanan", "admin_prices", {"kind": "both", "country": country})])
        buttons.append([("⬅️ Kembali", "admin_prices_menu", {}), ("🏠 Menu Awal", "home", {})])
        return await self.store.ui.send(message, text, self.store.ui.admin_keyboard(user, buttons))

    async def handle(self, message, user, args):
        self.authorize(user)
        settings = self.store.settings()
        worker_errors = ", ".join(kind+":"+str(settings.get("worker_error_"+kind)) for kind in ("polling","notifications","reconciliation") if settings.get("worker_error_"+kind))
        args = list(args)
        section = args[0].lower() if args else "dashboard"
        if section not in {"dashboard", "saldo", "statistik", "profit", "orders", "pending", "harga", "status", "webhook", "on", "off", "limit", "markup", "retry", "refund-proof"}:
            raise StoreError("INPUT", "Command admin belum dikenal. Gunakan /otp admin.")
        if section == "retry":
            self.store.repo.execute("UPDATE otp_notifications SET status='PENDING',attempts=0,next_retry_at=0 WHERE status='FAILED'")
            return await self.store.ui.send(message, "✅ Notifikasi gagal dijadwalkan ulang.")
        if section == "pending":
            page = self.number(args[1], 1, 10000)-1 if len(args)>1 else 0
            rows = self.store.repo.rows("""SELECT attempt_id,user_id,state,hold_idr,retries,error_code,created_at FROM otp_purchase_attempts
                WHERE state IN ('RESERVED','REQUESTING','PENDING_RECONCILIATION') ORDER BY created_at LIMIT 10 OFFSET ?""", (page*10,))
            text = [f"⏳ REKONSILIASI PEMBELIAN • halaman {page+1}"]
            for row in rows:
                text.append(f"Ref {escape(row['attempt_id'])}\nBuyer {row['user_id']} • {escape(row['state'])}\nHold {money(row['hold_idr'])} • Retry {row['retries']} • Error {escape(row['error_code']) or '-'}")
            if not rows:
                text.append("Tidak ada attempt pending pada halaman ini.")
            text.append("Worker memakai key/request asli. Jangan membuat order pengganti atau melepas hold tanpa bukti hasil provider.")
            return await self.store.ui.send(message,"\n\n".join(text))
        if section == "refund-proof":
            # Official GET endpoints expose no refund amount. A provider-account
            # operator must reconcile a documented receipt for uncertain refunds.
            if len(args) != 4 or not re.fullmatch(r"[A-Za-z0-9_.:-]{4,100}", args[3]):
                raise StoreError("INPUT", "Gunakan refund-proof <id bot> <refund modal IDR> <referensi bukti provider>. Hanya setelah memeriksa bukti kredit provider.")
            oid, amount = self.number(args[1], 1, 2**31-1), self.number(args[2], 0, 10**9)
            order = self.store.repo.one("SELECT * FROM otp_orders WHERE id=?", (oid,))
            if not order:
                raise StoreError("NOT_FOUND")
            data = await self.store.orders.refresh(order)
            if data["status"] not in {"CANCELED", "EXPIRED"} or data.get("otp_message") or data.get("otp_code") or data.get("otp_received_at"):
                raise StoreError("CONFLICT", "Status provider belum memenuhi syarat refund tanpa SMS.")
            response = {"order_id": order["provider_order_id"], "status": data["status"], "refund_amount": amount,
                        "proof_reference": args[3], "proof_actor": user, "proof_source": "OWNER_VERIFIED_PROVIDER_RECEIPT"}
            now = time.time()
            with self.store.repo.connection(True) as conn:
                cursor = conn.execute("INSERT INTO otp_actions(order_id,action,state,created_at,updated_at,response) VALUES(?,'refund-proof','PROOF_RECORDED',?,?,?)", (oid, now, now, encoded(response)))
                proof_id = cursor.lastrowid
            self.store.refund.confirm(order, response)
            self.store.repo.execute("UPDATE otp_actions SET state='DONE',updated_at=? WHERE id=?", (time.time(), proof_id))
            self.store.repo.execute("UPDATE otp_actions SET state='DONE',lease_until=0 WHERE order_id=? AND action='cancel' AND state='PENDING_RECONCILIATION'", (oid,))
            return await self.store.ui.send(message, "✅ Bukti refund provider dicatat dengan identitas owner. Kredit user mengikuti jumlah modal yang terbukti; refund parsial tetap direkonsiliasi.")
        if section in {"on", "off"}:
            self.store.set_setting("enabled", section == "on", user)
            return await self.store.ui.send(message, "✅ Pembelian OTP "+("diaktifkan." if section == "on" else "ditutup. Pesanan lama tetap dipantau."))
        if section == "limit" and len(args) == 2:
            value = self.number(args[1], 1, 20)
            self.store.set_setting("max_active", value, user)
            return await self.store.ui.send(message, f"✅ Batas order aktif: {value}/user.")
        if section == "markup" and len(args) == 3:
            key, value = args[1].lower(), args[2].lower()
            if key == "persen":
                try:
                    decimal = Decimal(value)
                except InvalidOperation:
                    raise StoreError("INPUT", "Persentase tidak valid.") from None
                if not decimal.is_finite() or not 0 <= decimal <= 10000 or decimal.as_tuple().exponent < -4:
                    raise StoreError("INPUT", "Persentase 0–10000, maksimal 4 angka desimal.")
                self.store.set_setting("percent", str(decimal), user)
            elif key == "nominal":
                self.store.set_setting("fixed", self.number(value, 0, 10**9), user)
            elif key == "mode" and value in {"persen", "nominal", "kombinasi", "percent", "fixed", "combined"}:
                self.store.set_setting("mode", {"persen": "percent", "nominal": "fixed", "kombinasi": "combined"}.get(value, value), user)
            else:
                raise StoreError("INPUT", "Gunakan markup persen, nominal atau mode.")
            return await self.store.ui.send(message, "✅ Pengaturan markup tersimpan. Quote lama akan divalidasi ulang.")
        if section == "harga" and len(args) >= 2:
            sub = args[1].lower()
            if sub == "round" and len(args) == 3:
                value = self.number(args[2], 0, 1000)
                if value not in {0, 100, 500, 1000}:
                    raise StoreError("INPUT", "Pembulatan: 0, 100, 500 atau 1000.")
                self.store.set_setting("rounding", value, user)
                return await self.store.ui.send(message, "✅ Pembulatan disimpan.")
            if sub == "allow-loss" and len(args) == 3 and args[2] in {"on", "off"}:
                self.store.set_setting("allow_loss", args[2] == "on", user)
                return await self.store.ui.send(message, "✅ Izin jual di bawah modal: "+args[2])
            if sub in {"set", "reset"} and len(args) == (4 if sub == "set" else 3):
                product_id = self.number(args[2], 1, 2**31-1)
                if sub == "reset":
                    self.store.repo.execute("DELETE FROM otp_pricing_rules WHERE scope='product' AND scope_key=?", (str(product_id),))
                else:
                    self.rule(user, "product", str(product_id), {"sale": self.number(args[3], 0, 10**9)})
                return await self.store.ui.send(message, "✅ Harga khusus produk disimpan/dihapus.")
            if sub == "rule":
                # /otp admin harga rule country 7 persen 25
                # /otp admin harga rule country_service 7:3 kombinasi 25 2000
                if len(args) < 5 or args[2] not in {"country", "service", "country_service", "product"}:
                    raise StoreError("INPUT", "harga rule <country|service|country_service|product> <id atau negara:layanan> <persen|nominal|kombinasi|jual|reset> <nilai> [nominal]")
                scope, key, mode = args[2:5]
                if not re.fullmatch(r"[1-9][0-9]{0,9}(?::[1-9][0-9]{0,9})?", key) or (":" in key) != (scope == "country_service"):
                    raise StoreError("INPUT", "ID scope tidak valid.")
                if mode == "reset":
                    self.store.repo.execute("DELETE FROM otp_pricing_rules WHERE scope=? AND scope_key=?", (scope, key))
                elif mode == "jual":
                    if len(args) != 6:
                        raise StoreError("INPUT", "Cantumkan harga jual.")
                    self.rule(user, scope, key, {"sale": self.number(args[5], 0, 10**9)})
                else:
                    if mode not in {"persen", "nominal", "kombinasi"}:
                        raise StoreError("INPUT", "Mode rule tidak valid.")
                    if len(args) != (7 if mode == "kombinasi" else 6):
                        raise StoreError("INPUT", "Cantumkan nilai markup sesuai mode.")
                    try:
                        percent = Decimal(args[5]) if mode in {"persen", "kombinasi"} else Decimal(0)
                    except InvalidOperation:
                        raise StoreError("INPUT", "Persentase tidak valid.") from None
                    if not percent.is_finite() or not 0 <= percent <= 10000 or percent.as_tuple().exponent < -4:
                        raise StoreError("INPUT", "Persentase tidak valid.")
                    fixed = self.number(args[6], 0, 10**9) if mode == "kombinasi" and len(args) == 7 else self.number(args[5], 0, 10**9) if mode == "nominal" else 0
                    self.rule(user, scope, key, {"mode": {"persen": "percent", "nominal": "fixed", "kombinasi": "combined"}[mode], "percent": str(percent), "fixed": fixed})
                return await self.store.ui.send(message, "✅ Aturan harga scope disimpan.")
            if sub in {"provider", "jual"}:
                country = self.number(args[2], 1, 2**31-1) if len(args) >= 4 else None
                platform = self.number(args[3], 1, 2**31-1) if len(args) >= 4 else None
                page = self.number(args[4], 1, 10000) if len(args) >= 5 else 1
                return await self.prices(message, user, sub, page=page, country=country, platform=platform)
        if section == "orders":
            page = self.number(args[1], 0, 10000) if len(args) > 1 else 0
            return await self.store.ui.history(message, user, page=page, admin=True)
        if section in {"limit", "markup"}:
            raise StoreError("INPUT", "Parameter admin belum lengkap. Gunakan /otp admin harga untuk panduan.")
        if section == "webhook":
            data = await self.store.bootstrap_webhook()
            text = ("📩 <b>STATUS WEBHOOK</b>\n"+f"URL: {escape(data.get('webhook_url')) or 'Belum diatur'}\n"
                    f"Secret resmi: {'tersedia' if data.get('webhook_secret') else 'belum tersedia'}\n"
                    f"Nonaktif otomatis: {'ya' if data.get('webhook_disabled_at') else 'tidak'}\n"
                    f"Gagal beruntun: {data.get('webhook_consecutive_failures',0)}\n"
                    "Tombol Hubungkan hanya mengatur URL ini jika webhook kosong atau sudah memakai URL bot. Secret tidak ditampilkan.")
            return await self.store.ui.send(message, text, self.store.ui.admin_keyboard(user, [[("🔗 HUBUNGKAN WEBHOOK", "admin_webhook_connect", {})], [("🧪 TEST WEBHOOK", "admin_webhook_test", {})], [("⬅️ Kembali", "admin", {}), ("🏠 Menu Awal", "home", {})]]))
        if section == "harga":
            example = {"id": -1, "price": 8000}
            sale, _ = self.store.pricing.calculate(example)
            text = ("⚙️ <b>PENGATURAN HARGA OTP</b>\n"
                f"Mode: {escape(settings['mode'])}\nMarkup: {escape(settings['percent'])}%\nTambahan: {money(settings['fixed'])}\n"
                f"Pembulatan: {settings['rounding']}\nContoh modal {money(8000)} → jual {money(sale)}\n"
                "Prioritas: produk → negara+layanan → layanan → negara → global.")
            return await self.store.ui.send(message, text, self.store.ui.admin_keyboard(user, [
                [("📈 ATUR PERSENTASE", "admin_input", {"setting": "percent"}), ("💵 ATUR NOMINAL", "admin_input", {"setting": "fixed"})],
                [("⚙️ PILIH MODE", "admin_modes", {})], [("📋 HARGA PROVIDER & JUAL", "admin_prices", {"kind": "both"})], [("⬅️ Kembali", "admin", {}), ("🏠 Menu Awal", "home", {})]]))
        stats = self.store.repo.one("""SELECT count(*) total,COALESCE(sum(selling_price_idr-refund_idr),0) revenue,
            COALESCE(sum(selling_price_idr-refund_idr-provider_cost_idr+provider_refund_idr),0) profit,
            COALESCE(sum(status='COMPLETED'),0) completed,COALESCE(sum(status IN ('ACTIVE','OTP_RECEIVED')),0) pending,
            COALESCE(sum(status IN ('CANCELED','EXPIRED','FAILED')),0) canceled,
            COALESCE(sum(refund_state IN ('AWAITING_PROVIDER_PROOF','PARTIAL_RECONCILIATION','REVIEW_REQUIRED')),0) refund_review FROM otp_orders""")
        balance, api_status = "Belum diperiksa", "Belum diperiksa"
        if section in {"dashboard", "saldo", "status"}:
            try:
                response = await self.store.api.request("GET", "/balance")
                if not isinstance(response, dict) or response.get("currency") != "IDR":
                    raise StoreError("INVALID_RESPONSE")
                balance, api_status = money(integer(response.get("balance"))), "Terhubung"
            except StoreError as exc:
                balance, api_status = "Tidak tersedia", "Tidak terhubung • "+exc.public
            except Exception as exc:
                logging.warning("OTP provider balance: %s", type(exc).__name__)
                balance, api_status = "Tidak tersedia", "Tidak terhubung"
        attempts = self.store.repo.one("SELECT count(*) n FROM otp_purchase_attempts WHERE state IN ('RESERVED','REQUESTING','PENDING_RECONCILIATION')")["n"]
        notifications = self.store.repo.one("SELECT count(*) n FROM otp_notifications WHERE status IN ('PENDING','SENDING','FAILED')")["n"]
        settings = self.store.settings()
        text = OwnerFormatter.dashboard(stats=stats, settings=settings, balance=balance, api_status=api_status,
            attempts=attempts, notifications=notifications, worker_errors=worker_errors, config_error=self.store.config.error,
            details=section == "status")
        rows = OwnerFormatter.dashboard_rows()
        if section == "status":
            rows = [[("🔄 RETRY NOTIFIKASI GAGAL", "admin_retry", {})], [("⬅️ Kembali", "admin", {}), ("🏠 Menu Awal", "home", {})]]
        elif section != "dashboard":
            rows = [[("⬅️ Kembali", "admin", {}), ("🏠 Menu Awal", "home", {})]]
        keyboard = self.store.ui.admin_keyboard(user, rows)
        if section == "dashboard":
            keyboard.inline_keyboard.append([InlineKeyboardButton(text="⬅️ Kembali", callback_data=self.store.ui.callback(user, "main_menu"))])
        await self.store.ui.send(message, text, keyboard)

    @staticmethod
    def number(value, low, high):
        if not re.fullmatch(r"[0-9]{1,12}", str(value)):
            raise StoreError("INPUT", "Gunakan angka bulat tanpa pemisah.")
        value = int(value)
        if not low <= value <= high:
            raise StoreError("INPUT", f"Masukkan angka antara {low} dan {high}.")
        return value

    def rule(self, user, scope, key, rule):
        self.authorize(user)
        self.store.repo.execute("INSERT INTO otp_pricing_rules VALUES(?,?,?,?) ON CONFLICT(scope,scope_key) DO UPDATE SET rule=excluded.rule,updated_at=excluded.updated_at", (scope, key, encoded(rule), time.time()))


def register(router, store):
    admin = AdminHandler(store)

    async def guard(message, user):
        if not message or str(message.chat.type) != "private" or message.chat.id != user:
            raise StoreError("PRIVATE", "Gunakan /otp melalui chat privat bot.")
        if store.host.security_blocked(user):
            raise StoreError("FORBIDDEN", "Akun kamu dibatasi owner.")
        if not await store.host.is_channel_member(message.bot, user):
            raise StoreError("CHANNEL", "Akses mengikuti verifikasi channel bot. Buka /start dan ikuti petunjuk bergabung dahulu.")
        profile = store.repo.one("SELECT username FROM verified_users WHERE user_id=?", (user,))
        username = profile["username"] if profile else ""
        if message.from_user and message.from_user.id == user:
            username = getattr(message.from_user, "username", "") or username
        store.host.mark_user_verified(user, username)

    async def failure(message, exc, *, user=None, admin_context=False):
        text = (exc.public if admin_context and store.host.is_owner(user) and isinstance(exc, StoreError)
                else UserFormatter.error(exc))
        if not isinstance(exc, StoreError):
            logging.warning("OTP handler: %s", type(exc).__name__)
        await store.ui.send(message, "⚠️ "+escape(text))

    async def dispatch(message, user, action, payload, state, call=None):
        # Apply this before every admin action, including history pagination and
        # previously issued callbacks whose owner's role may have been revoked.
        if action.startswith("admin"):
            admin.authorize(user)
        if action.startswith("topup"):
            if action not in {"topup_back", "topup_cancel", "topup_noop"}:
                await store.topups.exit(user, state)
                await state.clear()
            return await store.topups.handle(message, user, action, payload, state, call)
        await store.topups.exit(user, state)
        if action in {"home", "shop", "help", "balance", "countries", "orders", "history"} or action.startswith("admin") and action != "admin_input":
            await state.clear()
        if action == "main_menu":
            await state.clear()
            if call:
                await store.host.cb_home(TopupCall(call, message, "home", store.topups, user), state, message.bot)
        elif action == "home":
            if store.host.is_owner(user):
                await admin.handle(message, user, [])
            else:
                await store.ui.home(message, user)
        elif action == "shop":
            await store.ui.home(message, user)
        elif action == "help":
            await store.ui.send(message, HELP, store.ui.keyboard(user, [[("📋 DAFTAR COMMAND", "help_commands", {})], [("⬅️ Kembali", "home", {}), ("🏠 Menu Awal", "home", {})]]))
        elif action == "help_commands":
            await store.ui.send(message, COMMAND_HELP, store.ui.keyboard(user, [[("⬅️ Kembali", "help", {})], [("🏠 Menu Awal", "home", {})]]))
        elif action == "balance":
            await store.ui.balance(message, user)
        elif action in {"countries", "services", "operators", "products"}:
            if action == "services" and "country" not in payload:
                await store.ui.selection(message, user, "countries")
            else:
                await store.ui.selection(message, user, action, payload, payload.get("query", ""))
        elif action in {"orders", "history", "admin_orders"}:
            await store.ui.history(message, user, action == "history", int(payload.get("page", 0)), action == "admin_orders")
        elif action == "search":
            await state.set_state(OTPState.search)
            await state.update_data(otp_search=payload)
            await store.ui.send(message, "🔎 Kirim nama negara/layanan untuk dicari.", store.ui.navigation(user, payload['kind'], payload['context']))
            await state.update_data(otp_menu_message_id=message.message_id)
        elif action == "quote":
            quote = await store.purchase.quote(user, payload["product"])
            await store.ui.quote(message, user, quote)
        elif action == "pay_qris":
            payment = await store.payments.create(user, payload["quote"])
            await store.ui.payment(message, user, payment["payment_id"])
        elif action == "pay_manual":
            payment = await store.payments.create_manual(user,payload['quote'])
            await store.ui.payment(message,user,payment['payment_id'])
        elif action in {"payment_status", "payment_cancel"}:
            store.payments.owned(user, payload["payment"])
            if action == "payment_cancel":
                store.payments.cancel(user, payload["payment"])
            else:
                await store.payments.reconcile()
            await store.ui.payment(message, user, payload["payment"])
        elif action == "buy":
            attempt = await store.purchase.buy(user, payload["quote"])
            if attempt["state"] == "CAPTURED":
                order = store.repo.one("SELECT * FROM otp_orders WHERE attempt_id=?", (attempt["attempt_id"],))
                await payment_receipts.notify(store.host, message.bot, "otp_order", order["id"])
            elif attempt["state"] == "FAILED":
                await store.ui.send(message, "❌ Pembelian gagal. Saldo yang ditahan telah dilepas. "+escape(UserFormatter.error(StoreError(attempt["error_code"]))))
            else:
                await store.ui.send(message, "⏳ Pembelian belum terkonfirmasi. Dana untuk transaksi ini ditahan. Jangan membeli ulang; hasil dikirim otomatis.")
        elif action == "check":
            await store.ui.check(message, user, payload["id"])
        elif action == 'read_sms':
            await store.ui.check(message,user,payload['id'],full_sms=True)
        elif action in {"confirm_cancel", "confirm_finish"}:
            order = store.repo.owned(user, payload["id"])
            kind = action.removeprefix("confirm_")
            if kind=='cancel':
                await store.orders.refresh(order)
                order=store.repo.owned(user,payload['id'])
                caps=json.loads(order['capabilities'])
                if order['status'] not in ACTIVE or order['last_sms_revision']>0:
                    return await store.ui.send(message,'Pembatalan tidak tersedia: SMS sudah diterima atau pesanan sudah selesai.',store.ui.navigation(user,'check',{'id':order['id']}))
                if caps.get('can_cancel') is not True:
                    when=payment_receipts.format_wib(caps.get('cancel_available_at'))
                    return await store.ui.send(message,'⏳ Pembatalan belum diizinkan untuk nomor ini.'+(f'\nDapat diperiksa lagi: {when}.' if when!='-' else '\nPeriksa status terbaru sebelum mencoba lagi.'),store.ui.keyboard(user,[[('🔄 Periksa Pembatalan','confirm_cancel',{'id':order['id']})],[('⬅️ Kembali','check',{'id':order['id']}),('🏠 Menu Awal','home',{})]]))
            await store.ui.send(message, "Konfirmasi "+("pembatalan" if kind == "cancel" else "penyelesaian")+f" order #{order['id']}?\n"
                + ("Refund diproses setelah pembatalan dan pengembalian dana terkonfirmasi." if kind == "cancel" else "Order selesai tidak mendapat refund."),
                store.ui.keyboard(user, [[("✅ KONFIRMASI", kind, {"id": order["id"]})], [("⬅️ Kembali", "check", {"id": order["id"]}), ("🏠 Menu Awal", "home", {})]]))
        elif action in {"cancel", "finish", "resend"}:
            current=store.repo.owned(user,payload['id'])
            if (action=='cancel' and current['status']=='CANCELED') or (action=='finish' and current['status']=='COMPLETED'):
                await payment_receipts.notify(store.host,message.bot,'otp_order',payload['id'])
                return
            await store.orders.action(user, payload["id"], action)
            if await payment_receipts.notify(store.host,message.bot,'otp_order',payload['id']):return
            await store.ui.send(message, "✅ "+{"cancel": "Pembatalan diterima. Status refund tersedia di pesanan.", "finish": "Order selesai.", "resend": "Permintaan SMS baru diterima. Tunggu SMS berikutnya; SMS lama tidak dikirim ulang."}[action])
        elif action == "reactivate":
            parent = store.repo.owned(user, payload["id"])
            product = {"id": parent["product_id"], "catalog_product_id": parent["catalog_product_id"], "country_id": parent["country_id"], "platform_id": parent["platform_id"],
                       "operator_id": parent["operator_id"], "operator_name": parent["operator_name"], "country_name": parent["country_name"], "platform_name": parent["platform_name"]}
            await store.ui.quote(message, user, await store.purchase.quote(user, product, parent))
        elif action.startswith("admin"):
            admin.authorize(user)
            sections = {"admin": [], "admin_prices_menu": ["harga"], "admin_balance": ["saldo"], "admin_stats": ["statistik"], "admin_profit": ["profit"], "admin_status": ["status"], "admin_webhook": ["webhook"], "admin_pending": ["pending"]}
            if action in sections:
                await admin.handle(message, user, sections[action])
            elif action == "admin_prices":
                await admin.prices(message, user, payload.get("kind"), page=payload.get("page", 1),
                                   country=payload.get("country"), platform=payload.get("platform"),
                                   view=payload.get("view", "products"), services_page=payload.get("services_page", 1))
            elif action == "admin_toggle":
                await admin.handle(message, user, ["off" if store.settings()["enabled"] else "on"])
            elif action == "admin_modes":
                rows = [[(name, "admin_set_mode", {"mode": mode})] for name, mode in [("Persentase", "persen"), ("Nominal", "nominal"), ("Kombinasi", "kombinasi")]]
                rows.append([("⬅️ Kembali", "admin_prices_menu", {}), ("🏠 Menu Awal", "home", {})])
                await store.ui.send(message, "Pilih mode harga:", store.ui.admin_keyboard(user, rows))
            elif action == "admin_set_mode":
                await admin.handle(message, user, ["markup", "mode", payload["mode"]])
            elif action == "admin_input":
                await state.set_state(OTPState.admin_value)
                await state.update_data(otp_admin_setting=payload["setting"])
                await store.ui.send(message, "Kirim nilai "+("persentase" if payload["setting"] == "percent" else "tambahan nominal rupiah (angka bulat)")+".", store.ui.navigation(user, "admin_prices_menu"))
                await state.update_data(otp_menu_message_id=message.message_id)
            elif action == "admin_webhook_connect":
                await store.configure_webhook(user)
                await store.ui.send(message, "✅ Webhook resmi terhubung. Secret diselaraskan dalam memori; polling tetap aktif.")
            elif action == "admin_webhook_test":
                result = await store.api.request("POST", "/webhook/test")
                await store.ui.send(message, "🧪 Provider menerima permintaan test webhook. Periksa /otp admin webhook dan log HTTP untuk hasil pengiriman.")
            elif action == "admin_retry":
                store.repo.execute("UPDATE otp_notifications SET status='PENDING',attempts=0,next_retry_at=0 WHERE status='FAILED'")
                await store.ui.send(message, "✅ Notifikasi gagal dijadwalkan ulang; notifikasi yang sudah terkirim tetap tersimpan.")

    @router.message(Command("otp"))
    async def otp_command(message, state):
        user, admin_context = None, False
        try:
            user = message.from_user.id
            await guard(message, user)
            store.repo.rate(user, "command", 30, 60)
            text = message.text or ""
            args = text.split()[1:]
            if len(text) > 1024 or len(args) > 10:
                raise StoreError("INPUT", "Command terlalu panjang.")
            admin_context = bool(args and args[0].lower() == "admin")
            if admin_context:
                await store.topups.exit(user, state)
                await state.clear()
                await admin.handle(message, user, args[1:])
                return
            name = args[0].lower() if args else ""
            mapping = {"": "home", "beli": "countries", "negara": "countries", "layanan": "services", "saldo": "balance", "isi": "topup", "topup": "topup", "pesanan": "orders", "cek": "check", "ulang": "resend", "batal": "confirm_cancel", "selesai": "confirm_finish", "riwayat": "history", "aktifkan": "reactivate", "bantuan": "help"}
            if name not in mapping:
                raise StoreError("INPUT", "Command belum dikenal. Gunakan /otp bantuan.")
            action, payload = mapping[name], {}
            admin_context = action == "home" and store.host.is_owner(user)
            if action in {"check", "resend", "confirm_cancel", "confirm_finish", "reactivate"}:
                if len(args) != 2:
                    raise StoreError("INPUT", "Gunakan /otp "+name+" <id order bot>.")
                payload["id"] = admin.number(args[1], 1, 2**31-1)
            await dispatch(message, user, action, payload, state)
        except Exception as exc:
            await failure(message, exc, user=user, admin_context=admin_context)

    @router.callback_query(F.data.startswith(PREFIX))
    async def otp_callback(call, state):
        action, menu, answered = "", None, False
        try:
            user = call.from_user.id
            await guard(call.message, user)
            store.repo.rate(user, "callback", 40, 60)
            action, payload = store.read_token(user, (call.data or "")[len(PREFIX):])
            await call.answer()
            answered = True
            menu = MenuMessage(call.message)
            await dispatch(menu, user, action, payload, state, call)
        except Exception as exc:
            if not answered:
                try:
                    await call.answer("Permintaan OTP belum berhasil.", show_alert=True)
                except Exception:
                    pass
            if call.message and str(call.message.chat.type) == "private" and call.message.chat.id == call.from_user.id:
                await failure(menu or MenuMessage(call.message), exc, user=call.from_user.id, admin_context=action.startswith("admin") or action == "home")

    @router.message(OTPState.search, F.text & ~F.text.startswith("/"))
    async def otp_search(message, state):
        menu = message
        try:
            await guard(message, message.from_user.id)
            store.repo.rate(message.from_user.id, "search", 10, 60)
            values = await state.get_data()
            data = values.get("otp_search", {})
            if values.get("otp_menu_message_id"):
                menu = MenuMessage(message, message_id=values["otp_menu_message_id"])
            await state.clear()
            await store.ui.selection(menu, message.from_user.id, data["kind"], data["context"], (message.text or "")[:80])
        except Exception as exc:
            await failure(menu, exc, user=message.from_user.id)

    @router.message(OTPState.admin_value, F.text & ~F.text.startswith("/"))
    async def otp_admin_input(message, state):
        menu = message
        try:
            await guard(message, message.from_user.id)
            admin.authorize(message.from_user.id)
            values = await state.get_data()
            key = values.get("otp_admin_setting")
            if values.get("otp_menu_message_id"):
                menu = MenuMessage(message, message_id=values["otp_menu_message_id"])
            await admin.handle(menu, message.from_user.id, ["markup", "persen" if key == "percent" else "nominal", (message.text or "").strip()])
            await state.clear()
        except Exception as exc:
            await failure(menu, exc, user=message.from_user.id, admin_context=True)

    @router.message(OTPState.topup_amount, F.text & ~F.text.startswith("/") & ~F.text.in_(TEXT_MENU_ACTIONS))
    async def otp_topup_amount(message, state):
        menu = message
        try:
            await guard(message, message.from_user.id)
            store.repo.rate(message.from_user.id, "topup_amount", 10, 60)
            values = await state.get_data()
            menu = TopupMessage(message, store.topups, message.from_user.id, message_id=values.get("otp_menu_message_id"))
            await store.host.wallet_topup_custom_input(menu, state)
            if await state.get_state() == OTPState.topup_amount.state:
                await state.update_data(otp_menu_message_id=menu.target_id or message.message_id)
        except Exception as exc:
            await failure(menu, exc, user=message.from_user.id)

    @router.message(OTPState.topup_proof, ~F.text.startswith("/") & ~F.text.in_(TEXT_MENU_ACTIONS))
    async def otp_topup_proof(message, state, bot):
        menu = message
        try:
            await guard(message, message.from_user.id)
            store.repo.rate(message.from_user.id, "topup_proof_upload", 6, 60)
            values = await state.get_data()
            entity, entity_id = store.host.payment_proof_data_target(values)
            if entity != "topup" or not store.repo.one("SELECT id FROM topups WHERE id=? AND user_id=?", (entity_id, message.from_user.id)):
                raise StoreError("NOT_FOUND")
            menu = TopupMessage(message, store.topups, message.from_user.id, message_id=values.get("otp_menu_message_id"))
            proxy_state = TopupState(state, store.host)
            if message.photo:
                await store.host.payment_proof_photo(menu, proxy_state, bot)
            elif message.document:
                await store.host.payment_proof_document(menu, proxy_state, bot)
            else:
                await menu.answer("❌ Kirim bukti sebagai foto/screenshot atau file gambar.",
                    reply_markup=store.host.payment_proof_status_keyboard(entity, entity_id), parse_mode="HTML")
            if await state.get_state() == OTPState.topup_proof.state:
                await state.update_data(otp_menu_message_id=menu.target_id or message.message_id)
        except Exception as exc:
            await failure(menu, exc, user=message.from_user.id)

    return store
