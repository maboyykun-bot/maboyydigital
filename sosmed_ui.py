"""Telegram views for the additive social-media store.

The provider client, money movements and order lifecycle live in
``sosmed_buzzerpanel``. This module only validates navigation and collects
documented form fields. It shares the host router, wallet and deposit flow.
"""
import html
import json
import logging
import math
import re
import shlex
import time
from decimal import Decimal, InvalidOperation

from aiogram import F
from aiogram.filters import Command
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, LinkPreviewOptions

import sosmed_buzzerpanel as core
import payment_receipts
from otp_smscode import MenuMessage, TEXT_MENU_ACTIONS

PREFIX = "sosmed:"
PAGE_SIZE = 8
SERVICE_PAGE_SIZE = core.CATALOG_PAGE_SIZE
USER_BRAND = "MABOYY SOSMED STORE"
ADMIN_BRAND = "MABOYY SOSMED ADMIN"
TERMINAL = {"COMPLETED", "PARTIAL", "CANCELED", "FAILED"}
NAVIGATION_ACTIONS = {
    "home", "categories", "services", "detail", "orders", "history", "check",
    "favorites", "favorite", "balance", "help", "search", "admin_menu",
    "admin_balance", "admin_stats", "admin_profit", "admin_status",
    "admin_orders", "admin_services", "admin_categories", "admin_prices",
    "admin_settings", "admin_pricing", "admin_scope", "admin_pending",
    "admin_refunds", "admin_detail",
    "admin_form", "admin_units", "admin_catalog", "popular",
    "admin_price_categories", "admin_price_breakdown", "admin_search",
    "category_search", "admin_category_search",
    "attempt", "admin_attempt",
    "confirm_refill", "refill_check", "admin_refill_check", "admin_refills",
}


def esc(value, limit=1400):
    # Bound escaped fragments without splitting entities or enclosing markup.
    result, size = [], 0
    for character in str(value if value is not None else ""):
        encoded = html.escape(character)
        if size+len(encoded)>limit:
            result.append("…")
            break
        result.append(encoded)
        size += len(encoded)
    return "".join(result)


def number(value, low=0, high=10**12):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,13}", str(value).strip()):
        raise core.StoreError("INPUT", "Kirim angka bulat yang valid.")
    result = int(value)
    if not low <= result <= high:
        raise core.StoreError("INPUT", "Angka di luar batas yang diizinkan.")
    return result


def instant(value):
    return payment_receipts.format_wib(value, compact=True, missing="Belum tersedia")


def refill_label(state):
    return {"PENDING":"Sedang diproses", "REQUESTING":"Sedang diajukan",
            "COMPLETED":"Selesai", "REJECTED":"Ditolak", "FAILED":"Gagal",
            "UNKNOWN":"Menunggu kepastian"}.get(state, "Menunggu kepastian")


def refill_offer_label(service, enabled):
    if not enabled:
        return 'Belum tersedia di toko'
    capability = core.refill_capability(service)
    if capability is None:
        return 'Kelayakan diperiksa saat pengajuan'
    return 'Tersedia sesuai ketentuan layanan' if capability else 'Tidak disediakan layanan'


def provider_money(value):
    """Show the exact API balance, including supported fractional rupiah."""
    value = Decimal(str(value))
    whole, _, fraction = format(value, "f").partition(".")
    text = "Rp"+f"{int(whole):,}".replace(",", ".")
    return text+(","+fraction.rstrip("0") if fraction.rstrip("0") else "")


class SosmedOrderState(StatesGroup):
    field = State()
    search = State()
    category_search = State()
    admin_value = State()


class UserFormatter:
    """White-label only bot-generated catalog text; no raw provider errors."""

    @staticmethod
    def label(value, limit=400, *, secret=""):
        text = str(value or "")
        if secret:
            text = text.replace(secret, "")
        text = re.sub(r"https?://[^\s<>]+", "", text, flags=re.I)
        text = re.sub(r"\b(?:[a-z0-9_-]+\.)*buzzerpanel\s*\.\s*id(?:/[^\s<>]*)?", "", text, flags=re.I)
        text = re.sub(r"\bbuzzer\s*panel\b", "", text, flags=re.I)
        return " ".join(text.split()).strip(" •|·-/")[:limit] or "-"

    @staticmethod
    def kind(value):
        return {"default": "Default", "custom comments": "Custom Comments",
                "comment": "Comment", "mentions custom list": "Mentions Custom List",
                "mentionscustomlist": "Mentions Custom List", "comment replies": "Comment Replies",
                "commentreplies": "Comment Replies",
                "package": "Package", "subscription": "Subscription",
                "subscriptions": "Subscriptions", "mentions": "Mentions",
                "poll": "Poll", "drip-feed": "Drip-feed"}.get(
                    str(value).strip().lower(), "Tipe lain (belum didukung)")

    @staticmethod
    def status(value):
        return {
            "PENDING": "Menunggu proses", "PROCESSING": "Sedang diproses",
            "IN_PROGRESS": "Sedang berjalan", "COMPLETED": "Selesai",
            "PARTIAL": "Selesai sebagian", "CANCELED": "Dibatalkan",
            "FAILED": "Gagal", "UNKNOWN": "Sedang diperiksa",
            "RESERVED": "Pembayaran ditahan", "REQUESTING": "Sedang diproses",
            "RECONCILIATION_REQUIRED": "Menunggu kepastian transaksi",
            "PENDING_RECONCILIATION": "Menunggu kepastian transaksi",
            "CAPTURED": "Pesanan dibuat", "REFILL_PENDING": "Refill sedang diperiksa",
            "SUCCESS": "Pesanan dibuat",
        }.get(str(value).upper().replace(" ", "_"), "Sedang diperiksa")

    @staticmethod
    def error(exc):
        # An API response can contain upstream account details. Select a local
        # message by code instead of reflecting exception strings to buyers.
        return {
            "PRIVATE": "Gunakan /sosmed melalui chat privat bot.",
            "CHANNEL": "Buka /start dan ikuti verifikasi channel dahulu.",
            "FORBIDDEN": "Menu ini tidak dapat diakses oleh akun kamu.",
            "BLOCKED": "Akun kamu dibatasi owner.",
            "INPUT": "Input belum sesuai. Periksa petunjuk pada menu.",
            "VALIDATION": "Input belum sesuai persyaratan layanan.",
            "TOKEN": "Tombol kedaluwarsa atau bukan milik kamu. Buka /sosmed lagi.",
            "NOT_FOUND": "Layanan atau pesanan tidak ditemukan.",
            "DISABLED": "Pembelian baru ditutup owner. Pesanan lama tetap dapat dicek.",
            "CLOSED": "Pembelian baru sedang ditutup. Pesanan lama tetap dapat dicek.",
            "NOT_CONFIGURED": "Pembelian sementara belum tersedia. Hubungi owner.",
            "CONFIG": "Pembelian sementara belum tersedia. Hubungi owner.",
            "UNSUPPORTED": "Tipe layanan ini belum tersedia untuk pembelian.",
            "UNSUPPORTED_TYPE": "Tipe layanan ini belum tersedia untuk pembelian.",
            "TYPE": "Tipe layanan ini belum tersedia untuk pembelian.",
            "CURRENCY": "Layanan ini belum tersedia untuk pembelian.",
            "USER_BALANCE": "Saldo kamu tidak cukup. Pilih Isi Saldo.",
            "INSUFFICIENT_BALANCE": "Pesanan sementara belum dapat diproses.",
            "QUOTE_EXPIRED": "Konfirmasi harga kedaluwarsa. Pilih layanan kembali.",
            "PRICE_CHANGED": "Harga berubah. Pilih layanan kembali untuk menyetujui harga terbaru.",
            "BELOW_COST": "Harga layanan perlu diperbarui owner.",
            "ORDER_LIMIT": "Batas pesanan aktif tercapai. Tunggu pesanan sebelumnya.",
            "ACTIVE_LIMIT": "Batas pesanan aktif tercapai. Tunggu pesanan sebelumnya.",
            "COOLDOWN": "Tunggu sebentar sebelum mengirim permintaan kembali.",
            "RATE_LIMIT": "Terlalu banyak permintaan. Coba kembali setelah jeda.",
            "RATE_LIMIT_EXCEEDED": "Terlalu banyak permintaan. Coba kembali setelah jeda.",
            "MAINTENANCE": "Pembelian sementara ditutup untuk pemeliharaan.",
            "SAFE_MODE": "Pembelian sementara ditunda. Hubungi owner.",
            "REFILL_UNSUPPORTED": "Layanan ini tidak menyediakan refill.",
            "REFILL": "Refill belum tersedia. Periksa ketentuan dan status layanan.",
            "CANCEL_UNSUPPORTED": "Pembatalan tidak tersedia untuk layanan ini.",
            "CANCEL": "Pembatalan belum tersedia. Periksa ketentuan dan status layanan.",
            "CONFLICT": "Tindakan belum tersedia. Periksa status pesanan dahulu.",
            "REFILL_PENDING": "Permintaan refill sebelumnya masih diproses.",
            "NETWORK": "Hasil permintaan belum pasti. Periksa pesanan dan jangan membeli ulang.",
            "UNCERTAIN": "Transaksi sedang diperiksa. Jangan membeli ulang.",
            "LOCAL_DATABASE": "Transaksi sedang diperiksa. Jangan mengulang pembayaran.",
        }.get(getattr(exc, "code", ""), "Layanan mengalami gangguan sementara. Coba kembali nanti.")


def search_input(text):
    """Small bounded search grammar, not SQL or a provider request body."""
    if len(text) > 300:
        raise core.StoreError("INPUT", "Pencarian maksimal 300 karakter.")
    query, filters = [], {}
    for word in text.split():
        if ":" not in word:
            query.append(word)
            continue
        key, value = word.split(":", 1)
        key = key.lower()
        if key in {"refill", "tersedia"}:
            if value.lower() not in {"ya", "tidak", "true", "false", "1", "0"}:
                raise core.StoreError("INPUT", "Filter "+key+":ya atau "+key+":tidak.")
            filters["refill" if key == "refill" else "available"] = value.lower() in {"ya", "true", "1"}
        elif key in {"min", "max", "harga"}:
            filters[{"min": "min_quantity", "max": "max_quantity", "harga": "max_price_idr"}[key]] = number(value, 1, 10**12)
        else:
            query.append(word)
    return " ".join(query).strip(), filters


def category_input(text, *, required=False):
    """Category keywords stay separate from service search and price filters."""
    if not isinstance(text, str) or len(text) > 200:
        raise core.StoreError("INPUT", "Kata kunci kategori maksimal 200 karakter.")
    query = " ".join(text.split())
    if required and not query:
        raise core.StoreError("INPUT", "Ketik nama atau kata kunci kategori.")
    return query


class UIBuilder:
    def __init__(self, store):
        self.store = store

    def provider_label(self, value):
        text = str(value or "")
        for name in ("token", "secret"):
            secret = getattr(self.store.config, name, "")
            if secret:
                text = text.replace(secret, "")
        return text

    def public_label(self, value, limit=400):
        return UserFormatter.label(self.provider_label(value), limit)

    def keyboard(self, user, rows, *, bot_home=False):
        buttons = []
        for row in rows:
            actual = []
            for label, action, payload in row:
                if action.startswith("admin") and not self.store.owner(user):
                    raise core.StoreError("FORBIDDEN", "Menu ini hanya untuk owner.")
                token = self.store.token(user, action, payload or {}, ttl=86400 if action in NAVIGATION_ACTIONS else 300)
                if len(token.encode("utf-8")) > 64:
                    raise core.StoreError("INPUT", "Data tombol terlalu panjang.")
                safe_label = str(label)
                for name in ("token", "secret"):
                    secret = getattr(self.store.config, name, "")
                    if secret:
                        safe_label = safe_label.replace(secret, "[dirahasiakan]")
                actual.append(InlineKeyboardButton(text=safe_label[:64], callback_data=token))
            if actual:
                buttons.append(actual)
        if bot_home:
            buttons.append([InlineKeyboardButton(text="⬅️ Kembali ke Bot", callback_data="home")])
        return InlineKeyboardMarkup(inline_keyboard=buttons)

    def navigation(self, user, back="home", payload=None, *, admin=False):
        home = "admin_menu" if admin else "home"
        rows = []
        if back != home:
            rows.append([("⬅️ Kembali", back, payload or {}), ("🏠 Menu Awal", home, {})])
        else:
            rows.append([("⬅️ Kembali", home, {})])
        return self.keyboard(user, rows)

    async def send(self, message, text, keyboard=None):
        if keyboard is None:
            keyboard = self.navigation(message.chat.id)
        sent = await message.answer(text, reply_markup=keyboard, parse_mode="HTML",
                                    link_preview_options=LinkPreviewOptions(is_disabled=True))
        message_id = getattr(sent, "message_id", None) or getattr(message, "target_id", None) or message.message_id
        if isinstance(message_id, int) and message_id > 0:
            with self.store.repo.connection(True) as conn:
                conn.execute("""INSERT INTO sosmed_ui_sessions(user_id,message_id,payload,updated_at)
                    VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
                    message_id=excluded.message_id,updated_at=excluded.updated_at""",
                    (message.chat.id, message_id, "{}", time.time()))
        return sent

    def input_message(self, message):
        row = self.store.repo.one("SELECT message_id FROM sosmed_ui_sessions WHERE user_id=?", (message.from_user.id,))
        return MenuMessage(message, message_id=row["message_id"]) if row and row["message_id"] else message

    async def home(self, message, user):
        profile = self.store.repo.one("SELECT username FROM verified_users WHERE user_id=?", (user,))
        username = getattr(message.from_user, "username", "") if message.from_user and message.from_user.id == user else ""
        username = username or (profile.get("username", "") if profile else "")
        identity = "@"+username.lstrip("@") if username else "User "+str(user)
        settings = self.store.settings()
        rows = [
            [("🛒 BELI LAYANAN", "categories", {})],
            [("🔎 Cari Layanan", "search", {})],
            [("📂 KATEGORI", "categories", {})],
            [("📦 PESANAN SAYA", "orders", {}), ("⭐ FAVORIT", "favorites", {})],
            [("💰 SALDO SAYA", "balance", {}), ("📜 RIWAYAT", "history", {})],
            [("❓ PANDUAN", "help", {})],
        ]
        # Platform filters, not invented catalogue services. Availability and
        # original categories are read from the API when the shortcut is opened.
        rows.insert(1,[('🎵 TikTok','popular',{'platform':'tiktok'}),
                       ('📸 Instagram','popular',{'platform':'instagram'})])
        if self.store.owner(user):
            rows.append([("👑 PANEL OWNER", "admin_menu", {})])
        status = "Aktif" if settings["enabled"] else "Ditutup owner"
        note = ("Ketersediaan diperiksa saat memilih layanan." if settings["enabled"] else
                "Pembelian baru ditutup. Pesanan lama tetap dapat dicek.")
        if settings["enabled"] and not self.store.purchase_contract_verified():
            status = "Pengaturan belum lengkap"
            note = "Pembelian belum tersedia. Owner perlu melengkapi pengaturan toko."
        await self.send(message, f"🛍️ <b>{USER_BRAND}</b>\n🏠 <b>Menu Awal</b>\n"
                        f"👤 Akun: {esc(identity)}\n💰 Saldo: <b>{core.money(self.store.balance(user))}</b>\n"
                        f"🛍️ Toko: {esc(status)}\n{esc(note)}\n\n⭐ Populer: TikTok • Instagram\nPilih menu di bawah:",
                        self.keyboard(user, rows, bot_home=True))

    async def balance(self, message, user):
        keyboard = self.navigation(user)
        keyboard.inline_keyboard.insert(0, [InlineKeyboardButton(text="➕ Isi Saldo", callback_data="wallet:topup")])
        await self.send(message, "💰 <b>SALDO SAYA</b>\n\n"
                        f"Saldo kamu: <b>{core.money(self.store.balance(user))}</b>\n\n"
                        "Saldo yang sama dipakai untuk belanja, OTP, dan layanan sosmed. "
                        "Isi Saldo menggunakan pembayaran bot yang sudah tersedia.", keyboard)

    def pages(self, user, action, payload, page, total, page_size=PAGE_SIZE):
        count = max(1, math.ceil(total/page_size))
        rows = []
        if page > 0:
            rows.append(("⬅️ Sebelumnya", action, {**payload, "page": page-1}))
        if page+1 < count:
            rows.append(("Berikutnya ➡️", action, {**payload, "page": page+1}))
        return [rows] if rows else []

    async def categories(self, message, user, payload=None, *, admin=False, browse=False):
        payload = payload or {}
        query = category_input(payload.get("category_query", ""))
        await self.store.catalog.sync(return_rows=False)
        categories = ([row["category"] for row in self.store.repo.all("SELECT DISTINCT category FROM sosmed_services ORDER BY category")]
                      if admin else self.store.catalog.categories())
        platform = payload.get('platform')
        if platform is not None:
            if not isinstance(platform,str) or platform not in {'tiktok','instagram'}:
                raise core.StoreError('INPUT')
            categories = [category for category in categories if core.popular_platform(category)==platform]
        if query:
            words = query.casefold().split()
            categories = [category for category in categories if all(
                word in (self.provider_label(category) if admin else self.public_label(category, 2000)).casefold()
                for word in words)]
        page = min(number(payload.get("page", 0), 0, 100000), max(0, math.ceil(len(categories)/PAGE_SIZE)-1))
        action = "admin_price_categories" if browse else "admin_categories" if admin else "categories"
        context = {"category_query": query, **({"platform": platform} if platform else {})}
        rows = [[("🔎 Cari Kategori", "admin_category_search" if admin else "category_search",
                  {**context, "page": page, "browse": browse})]]
        for category in categories[page*PAGE_SIZE:(page+1)*PAGE_SIZE]:
            target = "admin_scope" if admin and not browse else "admin_services" if admin else "services"
            data = {"scope": "category", "key": category} if admin and not browse else {"category": category, "page": 0}
            if not admin or browse:
                data.update(category_query=query, category_page=page)
            if platform:
                data['platform'] = platform
            rows.append([(self.public_label(category, 60) if not admin else self.provider_label(category)[:60], target, data)])
        rows += self.pages(user, action, context, page, len(categories))
        if query:
            rows.append([("✖️ Hapus Pencarian Kategori", action, {**context, "category_query": "", "page": 0})])
        rows.append([("📋 Semua Layanan", "admin_services" if admin else "services", {'platform':platform} if platform else {})])
        rows.append([('🔎 Cari Layanan','admin_search' if admin else 'search',
                      {'platform':platform} if platform else {})])
        rows.append([("⬅️ Kembali", "admin_services" if browse else "admin_pricing" if admin else "home", {})])
        title = "📂 KATEGORI HARGA" if browse else "📂 MARKUP KATEGORI" if admin else "📂 PILIH KATEGORI"
        if platform:
            title = ('🎵 TIKTOK' if platform=='tiktok' else '📸 INSTAGRAM')+' · KATEGORI'
        caption = "\n🔎 "+esc(self.provider_label(query) if admin else self.public_label(query, 200), 500) if query else ""
        empty = "Tidak ada kategori yang cocok. Ubah atau hapus pencarian." if query else "Belum ada kategori tersedia."
        await self.send(message, f"<b>{title}</b>{caption}\nHalaman {page+1}/{max(1, math.ceil(len(categories)/PAGE_SIZE))} • {len(categories)} kategori"
                        + ("\n"+empty if not categories else "\nPilih kategori:"), self.keyboard(user, rows))

    async def services(self, message, user, payload=None, *, admin=False, favorites=False):
        payload = dict(payload or {})
        refresh = payload.pop("refresh", False) is True
        if favorites:
            payload["view"] = "favorites"
        else:
            payload.pop("view", None)
        await self.store.catalog.sync(force=refresh, return_rows=False)
        page_size = SERVICE_PAGE_SIZE
        page = number(payload.get("page", 0), 0, 100000)
        category, query = payload.get("category"), payload.get("query", "")
        options = dict(category=category,query=query,filters=payload.get('filters'),page_size=page_size,
                       admin=admin,platform=payload.get('platform'),favorite_user=user if favorites else None)
        services, total = self.store.catalog.listing(page=page, **options)
        if total and page*page_size >= total:
            page = (total-1)//page_size
            services, total = self.store.catalog.listing(page=page, **options)
        elif not total:
            page = 0
        payload["page"] = page
        rows, lines = [], []
        for index, service in enumerate(services, page*page_size+1):
            sid = service["provider_service_id"]
            try:
                cost, sale = self.store.pricing.rate(service)
                price = f"Modal {provider_money(service['provider_rate'])} • Jual {core.money(sale)}" if admin else core.money(sale)
            except core.StoreError:
                price = (f"Modal {provider_money(service['provider_rate'])} • Jual belum siap"
                         if admin and service.get('currency')=='IDR' and service.get('rate_unit')=='1000'
                         else "Harga belum tersedia")
            name = " ".join(self.provider_label(service['name']).split())[:46] if admin else self.public_label(service["name"], 46)
            lines.append(f"<b>{index}. #{esc(sid)} {esc(name, 180)}</b>\n{esc(price, 120)}"
                         + (" • OFF" if admin and not service.get("enabled") else ""))
            rows.append([(f"{index}. {name}"[:60], "admin_detail" if admin else "detail", {"id": sid, "back": payload})])
        action = "admin_services" if admin else "favorites" if favorites else "services"
        rows += self.pages(user, action, payload, page, total, page_size)
        rows.append([("🔄 Refresh Layanan", action, {**payload, "refresh": True})])
        category_back = {key:payload[key] for key in ("platform", "category_query") if key in payload}
        if "category_page" in payload:
            category_back["page"] = payload["category_page"]
        if admin:
            rows.append([('📂 Pilih Kategori','admin_price_categories',category_back)])
        rows.append([('🔎 Cari Layanan','admin_search' if admin else 'search',payload)])
        if payload.get('query') or payload.get('filters'):
            cleared = {key:value for key,value in payload.items() if key not in {'query','filters'}}
            rows.append([('✖️ Hapus Pencarian',action,{**cleared,'page':0})])
        rows.append([("⬅️ Kembali", "admin_menu" if admin else "home" if favorites else "categories",
                      category_back if not admin and not favorites else {})])
        title = "📋 HARGA MODAL & JUAL" if admin else "⭐ FAVORIT SAYA" if favorites else "📱 PILIH LAYANAN"
        group = category or {'tiktok':'TikTok','instagram':'Instagram'}.get(payload.get('platform'),'')
        caption = "" if not group else "\n"+esc(self.provider_label(group)[:70] if admin else self.public_label(group,70))
        await self.send(message, f"<b>{title}</b>{caption}\nHalaman {page+1}/{max(1, math.ceil(total/page_size))} • {total} layanan\n"
                        "Tarif per 1.000 • termurah dulu\n\n"
                        + ("\n".join(lines) if lines else "Belum ada layanan sesuai pilihan."), self.keyboard(user, rows))

    async def detail(self, message, user, service_id, back=None, *, admin=False, refresh=False):
        await self.store.catalog.sync(force=refresh, return_rows=False)
        service = self.store.catalog.service(service_id, active=not admin and not refresh)
        name = self.provider_label(service["name"])[:220] if admin else self.public_label(service["name"], 220)
        category = self.provider_label(service["category"])[:180] if admin else self.public_label(service["category"], 180)
        description = service.get("description") or "Deskripsi rinci belum tersedia."
        description = self.provider_label(description)[:1000] if admin else self.public_label(description, 1000)
        try:
            cost, sale = self.store.pricing.rate(service)
            price_ready = True
        except core.StoreError:
            cost, sale, price_ready = None, None, False
        unit = "1.000" if str(service.get("rate_unit")) == "1000" else "unit belum dikonfirmasi"
        text = (f"📱 <b>DETAIL LAYANAN</b>\n#{esc(service_id)} • {esc(category, 300)}\n"
                f"<b>{esc(name, 600)}</b>\n\n📌 {esc(description, 1000)}\n\n"
                f"Tipe: {esc(UserFormatter.kind(service['type']) if not admin else self.provider_label(service['type']))}\n"
                f"Min: {esc(service['min_quantity'])} • Max: {esc(service['max_quantity'])}\n"
                f"Status: {'Tersedia' if service.get('enabled') else 'Tidak tersedia'}\n"
                f"💰 Harga jual / {unit}: <b>{core.money(sale) if price_ready else 'Belum tersedia'}</b>\n"
                "Total sesuai jumlah ditampilkan sebelum pembayaran.\n"
                f"🔄 Refill: {refill_offer_label(service,self.store.refill_contract_verified())}\n"
                "❌ Pembatalan: Belum tersedia di toko\n\n"
                f"📋 Input:\n{esc(core.FormAdapter.instructions(service), 400)}")
        rows = []
        if price_ready and service.get('order_supported'):
            try:
                _,minimum_sale,_ = self.store.pricing.calculate(service,int(service['min_quantity']))
                text += f"\n\nPembelian mulai <b>{core.money(minimum_sale)}</b> untuk {service['min_quantity']} jumlah."
            except core.StoreError:
                text += '\n\nPesanan minimum perlu diperiksa owner sebelum dibeli.'
        if admin:
            text += f"\n\nModal / {unit}: {provider_money(service['provider_rate']) if price_ready else 'Belum tersedia'}\nMata uang: {esc(service['currency'] or 'Belum dikonfirmasi')}\n"
            text += f"Sumber metadata: {esc(service.get('metadata_source') or 'API')}\nSync: {instant(service['last_synced_at'])}"
            rows.append([("🏷️ Atur Harga", "admin_scope", {"scope": "service", "key": str(service_id)})])
            rows.append([('💡 Rincian Harga','admin_price_breakdown',{'id':service_id,'back':back or {}})])
            rows.append([("🟢 ON / OFF", "admin_service_toggle", {"id": service_id, "enabled": not bool(service.get("enabled"))})])
            rows.append([("📝 Metadata", "admin_input", {"kind": "metadata", "id": service_id})])
            rows.append([("📋 Tipe/Input", "admin_form", {"id": service_id})])
        else:
            if (price_ready and service.get("order_supported", False) and core.FormAdapter.supported(service) and service.get("enabled", True)
                    and self.store.purchase_contract_verified()):
                rows.append([("🛒 PESAN SEKARANG", "buy", {"id": service_id, "drip": False})])
                if service.get("dripfeed_supported"):
                    rows.append([("⏱️ PESAN DRIP-FEED", "buy", {"id": service_id, "drip": True})])
            else:
                text += "\n\nPembelian layanan ini belum tersedia di toko."
            rows.append([("⭐ Tambah / Hapus Favorit", "favorite", {"id": service_id, "back": back or {}})])
        rows.append([("🔄 Refresh Layanan", "admin_detail" if admin else "detail", {"id": service_id, "back": back or {}, "refresh": True})])
        back_action = "admin_services" if admin else "favorites" if (back or {}).get("view") == "favorites" else "services"
        rows.append([("⬅️ Kembali", back_action, back or {}),
                     ("🏠 Menu Awal", "admin_menu" if admin else "home", {})])
        await self.send(message, text, self.keyboard(user, rows))

    async def quote(self, message, user, quote):
        service = quote["service"]
        parameters = quote.get("parameters", {})
        balance, sale = self.store.balance(user), quote["sale"]
        text = (f"🛒 <b>KONFIRMASI PESANAN</b>\n{esc(self.public_label(service['name'], 220), 600)}\n"
                f"🔗 Target: <code>{esc(quote['target'], 1000)}</code>\n🔢 Jumlah: {esc(quote['quantity'])}\n")
        if parameters.get("comments"):
            comments = str(parameters["comments"])
            preview = comments if len(comments) <= 500 else comments[:500]+"…"
            text += "💬 Pratinjau komentar (input asli tetap utuh):\n<pre>"+esc(preview, 700)+"</pre>\n"
        if parameters.get("usernames"):
            text += "👥 Pratinjau username:\n<pre>"+esc(str(parameters["usernames"]), 700)+"</pre>\n"
        if parameters.get("runs"):
            text += f"⏱️ {esc(parameters['runs'])} run • interval {esc(parameters.get('interval'))} menit\n"
        text += (f"\n💰 Harga: <b>{core.money(sale)}</b>\n💳 Saldo: {core.money(balance)}\n"
                 f"Sisa saldo: {core.money(balance-sale) if balance >= sale else 'Saldo belum cukup'}\n"
                 f"⏳ Konfirmasi hingga: {instant(quote['expires_at'])}\n\n"
                 "Pilih saldo bot atau QRIS manual. Periksa target dan input sebelum konfirmasi.")
        rows = [[("✅ BAYAR SALDO", "pay", {"quote": quote["quote_id"]})],
                *([[('📱 QRIS MANUAL','pay_manual',{'quote':quote['quote_id']})]] if self.store.payments.manual_ready() else []),
                [("✏️ Ubah Input", "buy", {"id": service["provider_service_id"], "drip": bool(parameters.get("runs"))}),
                 ("❌ Batal", "detail", {"id": service["provider_service_id"]})]]
        if balance < sale:
            keyboard = self.keyboard(user, rows)
            keyboard.inline_keyboard.insert(1, [InlineKeyboardButton(text="➕ Isi Saldo", callback_data="wallet:topup")])
        else:
            keyboard = self.keyboard(user, rows)
        await self.send(message, text, keyboard)

    async def payment(self, message, user, payment_id):
        return await core.otp_smscode.UIBuilder.payment(self,message,user,payment_id)

    def order_text(self, order, *, admin=False):
        name = self.provider_label(order["service_name_snapshot"])[:220] if admin else self.public_label(order["service_name_snapshot"], 220)
        oid = order.get("id", order.get("internal_order_id"))
        text = (f"📦 <b>STATUS PESANAN SOSMED</b>\n🆔 Order bot: #{esc(oid)}\n"
                f"📱 {esc(name, 600)}\n🔗 Target: <code>{esc(order['target'], 1000)}</code>\n"
                f"🔢 Jumlah: {esc(order['quantity'])}\n📊 Status: {esc(UserFormatter.status(order['status']))}\n"
                f"💰 Harga: {core.money(order['selling_price'])}\n🕒 Beli: {instant(order['created_at'])}\n")
        if order.get("start_count") is not None:
            text += f"📈 Start count: {esc(order['start_count'])}\n"
        if order.get("remains") is not None:
            text += f"📉 Belum terpenuhi: {esc(order['remains'])}\n"
        if order.get("refund_amount"):
            text += f"↩️ Refund masuk saldo: {core.money(order['refund_amount'])}\n"
        elif order.get("refund_state") == "AWAITING_PROVIDER_PROOF":
            text += "↩️ Refund sedang diperiksa; saldo belum dikreditkan.\n"
        if order.get("refund_state") == "AWAITING_REMAINS":
            text += "↩️ Jumlah yang belum terpenuhi masih diperiksa untuk menghitung refund.\n"
        if admin:
            text += (f"\nUser: {esc(order['user_id'])}\nProvider order: {esc(order.get('provider_order_id') or '-')}\n"
                     f"Modal: {core.money(order['provider_cost'])}\nProfit kotor: {core.money(order['gross_profit'])}\n"
                     f"Status asli: {esc(order.get('raw_provider_status') or '-')}\n")
        return text

    def receipt_view(self, order, data):
        name=esc(self.public_label(order['service_name_snapshot'],80))
        target=esc(str(order['target'])[:100])+('…' if len(str(order['target']))>100 else '')
        text=(f"✅ <b>PESANAN BERHASIL DIBUAT!</b>\n🧾 Invoice: <b>{esc(data['reference'])}</b>\n"
            +f"🆔 Order: #{order['id']}\n📱 {name}\n🔗 Target: <code>{target}</code>\n"
            +f"🔢 Jumlah: {order['quantity']}\n💰 Total: <b>{core.money(data['amount'])}</b>\n"
            +f"📊 Status: {esc(UserFormatter.status(order['status']))}\n🕒 Beli: {instant(order['created_at'])}\n")
        if order.get('remains') is not None:text+=f"📉 Belum terpenuhi: {order['remains']}\n"
        if order.get('refund_amount'):text+=f"↩️ Refund ke saldo: {core.money(order['refund_amount'])}\n"
        refill=self.store.repo.one('SELECT * FROM sosmed_refills WHERE order_id=? ORDER BY id DESC LIMIT 1',(order['id'],))
        if refill:
            text+='🔄 Refill: '+esc(refill_label(refill['status']))+'\n'
            if refill.get('last_checked_at'):text+='🕒 Refill diperiksa: '+instant(refill['last_checked_at'])+'\n'
            if refill.get('last_error'):text+='⚠️ Pemeriksaan belum berhasil; status terakhir dipertahankan.\n'
            if refill['status']=='UNKNOWN' and not refill.get('provider_refill_id'):text+='Jangan mengajukan ulang; hubungi owner.\n'
        return text,self.order_keyboard(order['user_id'],order)

    def order_keyboard(self, user, order, *, admin=False):
        oid = order.get("id", order.get("internal_order_id"))
        rows = [[("🔄 REFRESH STATUS", "admin_check" if admin else "check", {"id": oid})]]
        # Admin views do not grant ownership of buyers' order actions.
        refill = self.store.repo.one('SELECT status FROM sosmed_refills WHERE order_id=? ORDER BY id DESC LIMIT 1',(oid,))
        if refill:
            rows.append([('🔎 CEK STATUS REFILL','admin_refill_check' if admin else 'refill_check',{'id':oid})])
        if not admin:
            if self.store.config.cancel_verified and order['status'] in {'PENDING','PROCESSING','IN_PROGRESS'}:
                rows.append([('❌ Batalkan Pesanan','confirm_cancel',{'id':oid})])
            if self.store.orders.refill_capability(order) is not False and order["status"] == "COMPLETED" and not order.get('refund_amount') and self.store.refill_contract_verified() and (not refill or refill['status'] in {'COMPLETED','REJECTED','FAILED'}):
                rows.append([("🔄 REQUEST REFILL", "confirm_refill", {"id": oid})])
        rows.append([("⬅️ Kembali", "admin_orders" if admin else "orders", {}),
                     ("🏠 Menu Awal", "admin_menu" if admin else "home", {})])
        return self.keyboard(user, rows)

    def refill_text(self, refill, *, admin=False):
        text = '\n\n🔄 <b>REFILL</b>\nStatus: '+esc(refill_label(refill['status']))
        text += '\nDiajukan: '+instant(refill['created_at'])
        if refill.get('last_checked_at'):
            text += '\nDiperiksa: '+instant(refill['last_checked_at'])
        if refill.get('last_error'):
            text += '\n⚠️ Pemeriksaan belum berhasil; status terakhir dipertahankan.'
        if refill['status']=='UNKNOWN' and not refill.get('provider_refill_id'):
            text += '\nHasil pengajuan belum pasti. Jangan mengajukan ulang; hubungi owner.'
        if admin:
            text += '\nID refill provider: '+esc(refill.get('provider_refill_id') or 'Belum diterima')
            text += '\nStatus asli: '+esc(self.provider_label(refill.get('raw_provider_status') or '-'),80)
            if refill.get('last_error'):
                text += '\nKode pemeriksaan: '+esc(refill['last_error'],40)
        return text

    async def check(self, message, user, order_id, *, admin=False, refresh=True, refresh_refill=False):
        if refresh:
            order = await self.store.orders.refresh(user, order_id, admin=admin)
        elif admin:
            self.store.require_owner(user)
            order = self.store.repo.one('SELECT * FROM sosmed_orders WHERE id=?',(order_id,))
            if not order:
                raise core.StoreError('NOT_FOUND')
        else:
            order = self.store.repo.order(user, order_id)
        text = self.order_text(order, admin=admin)
        refill = self.store.repo.one("SELECT * FROM sosmed_refills WHERE order_id=? ORDER BY id DESC LIMIT 1", (order_id,))
        if refill and (refresh or refresh_refill):
            try:
                refill = await self.store.orders.refill_status(user,order_id,admin=admin)
            except core.StoreError:
                refill = self.store.repo.one('SELECT * FROM sosmed_refills WHERE id=?',(refill['id'],))
        if refill:
            text += self.refill_text(refill,admin=admin)
        if not admin and await self.store.host.PAYMENT_RECEIPTS.present(message.bot,'sosmed',order_id,user=user,force=True):
            await self.store.host.PAYMENT_RECEIPTS.retire_source(message,user,'sosmed',order_id)
            return
        await self.send(message, text, self.order_keyboard(user, order, admin=admin))

    async def orders(self, message, user, payload=None, *, history=False, admin=False):
        payload = payload or {}
        page = number(payload.get("page", 0), 0, 100000)
        orders, total = self.store.repo.transactions(user, page=page, history=history or admin, admin=admin)
        if total and page*PAGE_SIZE >= total:
            page = (total-1)//PAGE_SIZE
            orders, total = self.store.repo.transactions(user, page=page, history=history or admin, admin=admin)
        action = "admin_orders" if admin else "history" if history else "orders"
        rows, lines = [], []
        for order in orders:
            if order["kind"] == "ATTEMPT":
                label = "T-"+order["attempt_id"][:12]
                name = self.provider_label(order["service_name_snapshot"])[:90] if admin else self.public_label(order["service_name_snapshot"],90)
                settled = order["state"] in {"FAILED","CANCELED"}
                amount = order["released_amount"] if settled else order["hold_amount"]
                funds = "Saldo dikembalikan" if settled and amount else "Dana transaksi" if settled else "Saldo ditahan"
                lines.append(f"<b>#{esc(label)} {esc(name,200)}</b>\n{esc(UserFormatter.status(order['state']))} • {funds}: {core.money(amount)}\n"
                             f"🕒 {instant(order['created_at'])}")
                rows.append([(f"#{label} {name}"[:60],"admin_attempt" if admin else "attempt",
                              {"id":order["attempt_id"],"history":history})])
                continue
            oid = order.get("id", order.get("internal_order_id"))
            name = self.provider_label(order["service_name_snapshot"])[:100] if admin else self.public_label(order["service_name_snapshot"], 100)
            summary = f"<b>#{esc(oid)} {esc(name,200)}</b>\n{esc(UserFormatter.status(order['status']))} • {core.money(order['selling_price'])}"
            if order.get("refund_amount"):
                summary += "\n↩️ Refund saldo: "+core.money(order["refund_amount"])
            lines.append(summary)
            rows.append([(f"#{oid} {name}"[:60], "admin_check" if admin else "check", {"id": oid})])
        if any(order["kind"] == "ATTEMPT" and order["state"] not in {"FAILED","CANCELED"} for order in orders):
            lines.append("Dana transaksi yang belum pasti tetap ditahan. Jangan membeli ulang; owner akan memeriksanya.")
        rows += self.pages(user, action, {}, page, total)
        if not admin:
            payments = self.store.repo.all("SELECT * FROM sosmed_payments WHERE user_id=? AND state IN ('PENDING','PAID','BUYING') ORDER BY created_at DESC LIMIT 5",(user,))
            for payment in payments:
                lines.append(f"🧾 QRIS {esc(payment['partner_reference'])} • {core.money(payment['payment_total_idr'])}\n"
                             +('Menunggu pembayaran / konfirmasi owner.' if payment['state']=='PENDING' else 'Pembayaran diterima, pesanan sedang diproses.'))
                rows.append([('🧾 '+payment['partner_reference'],'payment_status',{'payment':payment['payment_id']})])
        rows.append([("⬅️ Kembali", "admin_menu" if admin else "home", {})])
        title = "SEMUA PESANAN" if admin else "RIWAYAT PEMBELIAN" if history else "PESANAN SAYA"
        await self.send(message, f"📦 <b>{title}</b>\nHalaman {page+1}/{max(1, math.ceil(total/PAGE_SIZE))}\n\n"
                        + ("\n\n".join(lines) if lines else "Belum ada pesanan."), self.keyboard(user, rows))

    async def attempt(self, message, user, ident, payload=None, *, admin=False):
        if admin:
            self.store.require_owner(user)
            self.store.purchase.recover()
        item = self.store.repo.attempt(user,ident,admin=admin)
        order = self.store.repo.one("SELECT * FROM sosmed_orders WHERE attempt_id=?", (ident,))
        if order:
            return await self.check(message,user,order["id"],admin=admin)
        name = self.provider_label(item["service_name_snapshot"]) if admin else self.public_label(item["service_name_snapshot"],220)
        text = ("📦 <b>TRANSAKSI SOSMED</b>\n🆔 T-"+esc(ident[:12])+"\n"
                f"📱 {esc(name,600)}\n🔗 Target: <code>{esc(item['target'],1000)}</code>\n"
                f"🔢 Jumlah: {item['quantity']}\n📊 Status: {esc(UserFormatter.status(item['state']))}\n"
                f"💰 Harga: {core.money(item['sale'])}\n🕒 Beli: {instant(item['created_at'])}\n")
        if item["state"] in {"FAILED","CANCELED"}:
            text += f"↩️ Saldo dikembalikan: {core.money(item['released_amount'])}\n"
            if item["state"] == "CANCELED":
                text += "🔒 Transaksi ditutup. Bot tidak memproses ulang pesanan ini.\n"
        else:
            text += f"⏳ Saldo ditahan: {core.money(item['hold_amount'])}\nHasil pembelian belum pasti. Jangan membeli ulang; owner akan memeriksanya.\n"
        if admin:
            text += f"\nUser: {item['user_id']}\nAttempt: <code>{esc(ident)}</code>\nModal: {core.money(item['cost'])}\n"
        action = "admin_attempt" if admin else "attempt"
        history = (payload or {}).get("history") is True
        rows = [[("🔄 Refresh Transaksi",action,{"id":ident,"history":history})]]
        if admin and item['state'] in {'RECONCILIATION_REQUIRED','PENDING_RECONCILIATION'}:
            try:
                self.store.hold_refund_preview(user,ident)
            except core.StoreError:
                pass
            else:
                rows.append([("❌ Batalkan & Refund Saldo","admin_cancel_hold",{"id":ident})])
        rows.append([("⬅️ Kembali","admin_orders" if admin else "history" if history else "orders",{}),
                     ("🏠 Menu Awal","admin_menu" if admin else "home",{})])
        await self.send(message,text,self.keyboard(user,rows))


class AdminHandler:
    def __init__(self, store):
        self.store, self.ui = store, store.ui

    def authorize(self, user):
        if not self.store.owner(user):
            raise core.StoreError("FORBIDDEN", "Menu ini hanya untuk owner.")

    async def cancel_hold(self, message, user, payload):
        self.authorize(user)
        item = self.store.hold_refund_preview(user,payload['id'])
        if item['state']=='CANCELED':
            return await self.ui.attempt(message,user,item['attempt_id'],admin=True)
        text = ("❌ <b>KONFIRMASI BATALKAN &amp; REFUND</b>\n"
                f"Transaksi: T-{esc(item['attempt_id'][:12])}\nUser: {item['user_id']}\n"
                f"↩️ Refund saldo: <b>{core.money(item['hold_amount'])}</b>\n\n"
                "Saldo dikembalikan penuh ke wallet user dan transaksi ditutup. Bot tidak memproses ulang pesanan ini.\n\n"
                "Pembatalan berlaku di bot. Pesanan yang sudah terkirim dapat tetap diproses oleh provider; biayanya menjadi tanggungan toko.")
        rows = [[('✅ Batalkan & Refund','admin_cancel_hold_confirm',{'id':item['attempt_id'],
                  'buyer':item['user_id'],'amount':item['hold_amount']})],
                [('⬅️ Kembali','admin_attempt',{'id':item['attempt_id']}),('🏠 Menu Awal','admin_menu',{})]]
        await self.ui.send(message,text,self.ui.keyboard(user,rows))

    async def form(self, message, user, payload):
        self.authorize(user)
        ident=number(payload['id'],1)
        service=self.store.catalog.service(ident,active=False)
        raw=json.loads(service['raw_catalog'])
        text=("📋 <b>TIPE / INPUT LAYANAN</b>\n"+esc(self.ui.provider_label(service['name']),500)+
              f"\nTipe saat ini: {esc(service['type'])}\nSumber: {esc(raw.get('_form_source','API'))}\n\n"
              "Pilih sesuai dokumentasi layanan. Default memakai target + jumlah; komentar/mentions memakai daftar per baris. "
              "Package, subscription, dan tipe khusus lain tetap memerlukan kontrak harga/input yang benar.")
        rows=[[(label,'admin_form_choose',{'id':ident,'type':kind})] for label,kind in (
            ('Target + Jumlah','Default'),('Komentar Custom','Comment'),
            ('Mentions Custom List','Mentions Custom List'),('Comment Replies','Comment Replies'))]
        rows.append([('🔄 Ikuti API','admin_form_choose',{'id':ident,'type':None})])
        rows.append([('⬅️ Kembali','admin_detail',{'id':ident})])
        await self.ui.send(message,text,self.ui.keyboard(user,rows))

    async def dashboard(self, message, user, *, balance_only=False):
        self.authorize(user)
        balance = "Saldo provider tidak tersedia"
        status = "Belum terhubung"
        try:
            data = await self.store.provider_balance()
            currency = str(data.get("currency", ""))
            balance = provider_money(data["balance"]) if currency == "IDR" else f"{data['balance']} {currency or '(mata uang belum dikonfirmasi)'} (pembelian IDR belum tersedia)"
            status = "Terhubung"
        except Exception as exc:
            if not isinstance(exc, core.StoreError):
                logging.warning("SOSMED balance error: %s", type(exc).__name__)
            elif exc.code == "CURRENCY":
                balance += " (mata uang API belum didukung)"
        settings, stats = self.store.settings(), self.store.stats(user)
        text = f"👑 <b>{ADMIN_BRAND}</b>\nProvider: BuzzerPanel.id\n🔌 API: {status}\n💰 {esc(balance)}\n"
        if not balance_only:
            text += (f"\n🛍️ Toko: {'ON' if settings['enabled'] else 'OFF'}\n"
                     f"📦 Total order: {stats.get('total', 0)}\n"
                     f"⏳ Transaksi hold: {stats.get('held_count',0)} • {core.money(stats.get('held_amount',0))}\n"
                     f"⏳ Pending: {stats.get('pending', 0)} • 🔄 Diproses: {stats.get('processing', 0)}\n"
                     f"✅ Selesai: {stats.get('completed', 0)} • ⚠️ Partial: {stats.get('partial', 0)}\n"
                     f"❌ Dibatalkan: {stats.get('canceled', 0)} • Gagal: {stats.get('failed', 0)}\n"
                     f"💵 Omzet: {core.money(stats.get('revenue', 0))}\n"
                     f"📈 Profit kotor sementara: {core.money(stats.get('gross_profit', 0))}")
        rows = [[("💰 Saldo Provider", "admin_balance", {}), ("📊 Statistik", "admin_stats", {})],
                [("📋 Modal & Jual", "admin_services", {}), ("🏷️ Atur Harga", "admin_pricing", {})],
                [('🔎 Cari Layanan','admin_search',{})],
                [("📦 Semua Order", "admin_orders", {}), ("⏳ Rekonsiliasi", "admin_pending", {})],
                [("↩️ Refund Pending", "admin_refunds", {}), ("🔌 Status API", "admin_status", {})],
                [("🔄 Sync Katalog", "admin_sync", {}), ("⚙️ Pengaturan", "admin_settings", {})],
                [("🔴 Tutup Toko" if settings["enabled"] else "🟢 Periksa & Buka Toko", "admin_toggle",
                  {"enabled": not bool(settings["enabled"]), "back": "admin_menu"})],
                [("🛍️ Menu Pembeli", "home", {})]]
        await self.ui.send(message, text, self.ui.keyboard(user, rows, bot_home=True))

    async def statistics(self, message, user, *, profit=False):
        self.authorize(user)
        stats = self.store.stats(user)
        text = ("📈 <b>LAPORAN PROFIT</b>" if profit else "📊 <b>STATISTIK SOSMED</b>") + "\n\n"
        text += (f"Total: {stats.get('total', 0)}\nPending: {stats.get('pending', 0)}\n"
                 f"Processing: {stats.get('processing', 0)}\nCompleted: {stats.get('completed', 0)}\n"
                 f"Partial: {stats.get('partial', 0)}\nCanceled: {stats.get('canceled', 0)} • Failed: {stats.get('failed', 0)}\n"
                 f"Omzet setelah refund: {core.money(stats.get('revenue', 0))}\n"
                 f"Profit kotor sementara: {core.money(stats.get('gross_profit', 0))}\n\n"
                 f"Transaksi hold: {stats.get('held_count',0)} • {core.money(stats.get('held_amount',0))}\n"
                 f"Notifikasi refund menunggu/gagal: {stats.get('refund_notifications_pending',0)}/{stats.get('refund_notifications_failed',0)}\n\n"
                 "Transaksi yang belum pasti tidak dianggap penjualan selesai. "
                 "Refund yang belum terkonfirmasi perlu rekonsiliasi.")
        await self.ui.send(message, text, self.ui.navigation(user, "admin_menu", admin=True))

    async def pricing(self, message, user):
        self.authorize(user)
        settings = self.store.settings()
        text = ("🏷️ <b>PENGATURAN HARGA SOSMED</b>\nProvider: BuzzerPanel.id\n\n"
                f"Mode: {esc(settings['mode'])}\nMarkup: {esc(settings['percent'])}%\n"
                f"Tambahan: {core.money(settings['fixed'])}\nPembulatan: {esc(settings['rounding'])}\n"
                f"Minimum transaksi: {core.money(settings['min_sale'])}\n\n"
                f"Jual di bawah modal: {'Diizinkan owner' if settings['allow_loss'] else 'Ditolak'}\n"
                "Prioritas: harga/aturan layanan → kategori → global. Harga lama tetap tersimpan pada order.")
        rows = [[("📈 Persentase", "admin_input", {"setting": "percent"}), ("💵 Nominal", "admin_input", {"setting": "fixed"})],
                [("⚙️ Mode", "admin_modes", {}), ("🔢 Pembulatan", "admin_input", {"setting": "rounding"})],
                [("📂 Markup Kategori", "admin_categories", {}), ("📦 Markup Layanan", "admin_services", {})],
                [("💰 Minimum Harga", "admin_input", {"setting": "min_sale"}), ("📋 Modal & Jual", "admin_services", {})],
                [("⬅️ Kembali", "admin_menu", {})]]
        await self.ui.send(message, text, self.ui.keyboard(user, rows))

    async def price_breakdown(self, message, user, payload):
        self.authorize(user)
        await self.store.catalog.sync(return_rows=False)
        ident = number(payload.get('id'),1)
        service = self.store.catalog.service(ident,active=False)
        cost,sale,snapshot = self.store.pricing.calculate(service,1000)
        rule,settings = snapshot['rule'],self.store.settings()
        if 'sale_rate' in rule:
            policy = 'Harga khusus / 1.000: '+provider_money(rule['sale_rate'])
        else:
            labels = {'percent':'Persentase','fixed':'Nominal','combined':'Kombinasi'}
            policy = 'Mode: '+labels.get(rule['mode'],rule['mode'])
            if rule['mode'] in {'percent','combined'}:
                policy += ' • '+str(rule.get('percent','0'))+'%'
            if rule['mode'] in {'fixed','combined'}:
                policy += '\nTambahan per transaksi: '+core.money(rule.get('fixed',0))
        text = ('💡 <b>RINCIAN HARGA</b>\n'+esc(self.ui.provider_label(service['name']),180)+
                f"\n\nModal API / 1.000: <b>{provider_money(service['provider_rate'])}</b>\n"
                f"Jual / 1.000: <b>{core.money(sale)}</b>\n"+esc(policy)+
                f"\nMinimum harga transaksi: {core.money(settings['min_sale'])}\n"
                f"Pembulatan ke atas: {core.money(settings['rounding'])}\n")
        try:
            low = int(service['min_quantity'])
            low_cost,low_sale,_ = self.store.pricing.calculate(service,low)
            text += f"\nPesanan minimum {low} jumlah:\nModal {core.money(low_cost)} • Jual {core.money(low_sale)}\n"
        except core.StoreError:
            text += '\nPesanan minimum belum memenuhi batas harga toko.\n'
        text += '\nModal = tarif API × jumlah ÷ 1.000.\nMarkup, minimum transaksi dan pembulatan berlaku pada harga jual.'
        rows = [[('🏷️ Atur Harga Layanan','admin_scope',{'scope':'service','key':str(ident)})],
                [('⚙️ Pengaturan Harga','admin_pricing',{})],
                [('⬅️ Kembali','admin_detail',{'id':ident,'back':payload.get('back',{})})]]
        await self.ui.send(message,text,self.ui.keyboard(user,rows))

    async def scope(self, message, user, payload):
        self.authorize(user)
        scope, key = payload.get("scope"), str(payload.get("key", ""))
        if scope not in {"service", "category"} or not key or len(key) > 500:
            raise core.StoreError("INPUT", "Aturan harga tidak valid.")
        saved = self.store.repo.one("SELECT rule FROM sosmed_pricing_rules WHERE scope=? AND scope_key=?", (scope, key))
        settings = self.store.settings()
        rule = json.loads(saved["rule"]) if saved else {"mode": settings["mode"], "percent": settings["percent"], "fixed": settings["fixed"]}
        text = f"🏷️ <b>ATUR HARGA {esc(scope.upper())}</b>\n{esc(key)}\n\n"
        if "sale_rate" in rule:
            text += f"Harga jual tetap / 1.000: {provider_money(rule['sale_rate'])}\n"
        else:
            text += f"Mode: {esc(rule.get('mode', 'percent'))}\nMarkup: {esc(rule.get('percent', '0'))}%\nTambahan: {core.money(rule.get('fixed', 0))}\n"
        text += "\nMode Persentase memakai persen; Nominal memakai tambahan; Kombinasi memakai keduanya. Pilih nilai untuk aturan khusus."
        rows = [[("📈 Persentase", "admin_input", {**payload, "setting": "percent"}),
                 ("💵 Nominal", "admin_input", {**payload, "setting": "fixed"})],
                [("⚙️ Mode", "admin_modes", payload)],
                [("🧹 Reset Aturan", "admin_rule_reset", payload)]]
        if scope == "service":
            rows.insert(2, [("🏷️ Harga Tetap / 1.000", "admin_input", {**payload, "setting": "sale_rate"})])
        if scope == "category":
            rows.append([("🟢 Aktifkan Kategori", "admin_category_toggle", {"key": key, "enabled": True}),
                         ("🔴 Matikan Kategori", "admin_category_toggle", {"key": key, "enabled": False})])
        rows.append([("⬅️ Kembali", "admin_pricing", {})])
        await self.ui.send(message, text, self.ui.keyboard(user, rows))

    async def settings(self, message, user):
        self.authorize(user)
        settings = self.store.settings()
        text = ("⚙️ <b>PENGATURAN TOKO SOSMED</b>\n\n"
                f"Toko: {'ON' if settings['enabled'] else 'OFF'}\n"
                f"Limit order aktif: {esc(settings['max_active'])}/user\n"
                f"Limit jumlah: {esc(settings['max_quantity'])}\nPolling: {esc(settings['poll_seconds'])} detik\n\n"
                f"Pembelian: {'Terverifikasi' if self.store.purchase_contract_verified() else 'Perlu pemeriksaan'}\n"
                f"Refill API: {'Aktif' if self.store.refill_contract_verified() else 'Nonaktif; periksa Status API'} • "
                "Cancel API: Tidak didokumentasikan; dinonaktifkan\n\n"
                "Buka Toko memeriksa profil, katalog, mata uang, dan harga tanpa membeli layanan. "
                "Hasil pemeriksaan tersimpan; flag verifikasi manual tidak wajib.\n"
                "Mematikan toko hanya menghentikan pembelian baru. Pesanan lama tetap dipantau.")
        rows = [[("🔴 Tutup Toko" if settings["enabled"] else "🟢 Periksa & Buka Toko", "admin_toggle", {"enabled": not bool(settings["enabled"])})],
                [("📦 Limit Order", "admin_input", {"setting": "max_active"}),
                 ("🔢 Limit Jumlah", "admin_input", {"setting": "max_quantity"})],
                [("⏱️ Polling", "admin_input", {"setting": "poll_seconds"}),
                 ("📂 Kategori", "admin_categories", {})],
                [("💱 Mata Uang & Satuan", "admin_units", {})],
                [("🔄 Status Refill", "admin_refills", {})],
                [("⏸ Jeda Refill" if self.store.refill_contract_verified() else "▶️ Aktifkan Refill", "admin_refill_toggle", {"enabled": not self.store.refill_contract_verified()})],
                [("⬅️ Kembali", "admin_menu", {})]]
        await self.ui.send(message, text, self.ui.keyboard(user, rows))

    async def units(self, message, user):
        self.authorize(user)
        units = self.store.provider_units()
        labels = {"VARIABLE": "Variables", "OWNER": "Konfirmasi owner", "UNAVAILABLE": "Belum dikonfirmasi"}
        currency = units["currency"] or "Belum dikonfirmasi"
        rate = "per 1.000" if units["rate_unit"] == "1000" else "Belum dikonfirmasi"
        text = ("💱 <b>MATA UANG & SATUAN HARGA</b>\n\n"
                f"Mata uang cadangan: {esc(currency)} • {labels[units['currency_source']]}\n"
                f"Satuan cadangan: {rate} • {labels[units['unit_source']]}\n\n"
                "Jika API tidak menyebutnya, cocokkan dashboard akun dan kolom harga layanan sebelum konfirmasi. "
                "Saldo bertanda Rp berarti IDR. Pilih per 1.000 hanya jika tarif memang berlaku untuk 1.000 jumlah.\n\n"
                "Data eksplisit dari API tetap diperiksa. Setelah perubahan, gunakan Status API → Periksa & Buka Toko.")
        rows = [[("💵 Konfirmasi IDR", "admin_units_choose", {"field": "currency", "value": "IDR"}),
                 ("🔢 Konfirmasi / 1.000", "admin_units_choose", {"field": "rate_unit", "value": "1000"})],
                [("🔄 Hapus Konfirmasi Owner", "admin_units_choose", {"field": "reset", "value": None})],
                [("🔌 Status API", "admin_status", {})],
                [("⬅️ Kembali", "admin_settings", {})]]
        await self.ui.send(message, text, self.ui.keyboard(user, rows))

    async def health(self, message, user):
        self.authorize(user)
        issues, result = [], None
        try:
            # A status button must perform a real read-only check, rather than
            # displaying an uninitialized last_ok value forever.
            result = await self.store.check_provider(user)
            issues.extend(self.store.catalogue_issues(result["services"], result["profile"]))
        except core.StoreError as exc:
            issues.append(exc.public)
        latest = self.store.repo.one('SELECT order_id FROM sosmed_refills WHERE provider_refill_id IS NOT NULL ORDER BY id DESC LIMIT 1')
        if latest:
            try:
                await self.store.orders.refill_status(user,latest['order_id'],admin=True)
            except core.StoreError:
                pass  # Refill health is separate from the profile/catalog check.
        refill_health = self.store.refill_health()
        last_refill = refill_health['last']
        refill_check = ('Belum ada pengajuan' if not last_refill else
                        'Belum ada ID refill; perlu pemeriksaan owner' if not last_refill['provider_refill_id'] else
                        'Pemeriksaan belum berhasil; lihat Status Refill' if last_refill['last_error'] else
                        'Status terakhir '+refill_label(last_refill['status']))
        health = self.store.health()
        verified = health.get("contract_verified", False)
        if not verified:
            issues.append("Tekan tombol Periksa & Buka Toko untuk memverifikasi pembelian")
        if not self.store.settings()["enabled"]:
            issues.append("Pembelian baru masih OFF")
        if issues:
            explanation = "\n".join("• "+esc(item) for item in issues)
        else:
            explanation = "✅ Pemeriksaan berhasil. Toko siap menerima konfirmasi pembelian."
        current_status = "Terhubung" if result else "Pemeriksaan belum berhasil"
        stage = health.get('stage', '')
        profile_status = ('Terbaca' if stage=='complete' or stage.startswith('services')
                          else 'Gagal' if stage=='profile' else 'Belum diperiksa')
        catalog_status = ('Terbaca' if stage=='complete' else 'Gagal' if stage.startswith('services')
                          else 'Belum diperiksa')
        verification = ('Flag operator aktif' if self.store.config.contract_verified else 'Tersimpan') if verified else 'Belum selesai'
        if verified and not result:
            verification += '; pemeriksaan API belum lulus'
        http = health.get('http_status')
        report = self.store.catalog.diagnostics()
        catalog_summary = ''
        if report:
            catalog_summary = (f"Layanan: {report['valid_unique']}/{report['received']} unik valid • "
                               f"Dapat dibeli: {report['purchasable']}\n"
                               f"Dilewati: {report['rejected_rows']} • Duplikat identik: {report['identical_duplicates']} • "
                               f"ID konflik: {report['conflicting_ids']}\n")
        provider_balance = "Tidak tersedia"
        profile = result["profile"] if result else (
            self.store.catalog.last_profile if self.store.catalog.last_profile_fingerprint == self.store.contract_fingerprint() and stage.startswith('services') else None)
        if profile:
            provider_balance = provider_money(profile["balance"]) if profile["currency"] == "IDR" else esc(profile["balance"])+" "+esc(profile["currency"] or "(mata uang belum dikonfirmasi)")
        text = ("🔌 <b>STATUS INTEGRASI SOSMED</b>\nProvider: BuzzerPanel.id\n\n"
                f"Versi bot: {esc(getattr(self.store.host,'BOT_VERSION','-'),40)}\n"
                f"Konfigurasi: {'Tersedia' if health.get('configured') else 'Belum lengkap'}\n"
                f"API: {current_status}\n"
                f"Profil: {profile_status} • Katalog: {catalog_status}\n"
                f"Saldo provider: {provider_balance}\n"
                f"HTTP: {http if type(http) is int else '-'}\n"
                f"Diperiksa: {instant(health.get('checked_at'))}\n"
                f"Sync katalog: {instant(health.get('catalog_synced_at'))}\n"
                f"{catalog_summary}"
                f"Kode gangguan: {esc(health.get('error') or '-')}\n\n"
                f"Verifikasi pembelian: {verification}\n"
                f"{explanation}\n\n"
                f"Refill API: {'Aktif' if refill_health['enabled'] else 'Nonaktif'} • Kontrak refill/status_refill tersedia\n"
                f"Refill: {refill_health['total']} • Menunggu: {refill_health['pending']} • Selesai: {refill_health['completed']}\n"
                f"Cek refill: {refill_check}\n"
                "Kelayakan refill mengikuti layanan/pesanan. Cancel belum didokumentasikan.\n"
                "Timeout pembelian tidak dikirim ulang otomatis. Periksa menu Rekonsiliasi untuk transaksi yang belum pasti.")
        keyboard = self.ui.navigation(user, "admin_menu", admin=True)
        keyboard.inline_keyboard.insert(0, [InlineKeyboardButton(text="📋 Rincian Katalog", callback_data=self.store.token(user,"admin_catalog",ttl=86400))])
        keyboard.inline_keyboard.insert(0, [InlineKeyboardButton(text="🔄 Status Refill", callback_data=self.store.token(user,'admin_refills'))])
        keyboard.inline_keyboard.insert(0, [InlineKeyboardButton(text="💱 Mata Uang & Satuan", callback_data=self.store.token(user, "admin_units", ttl=86400))])
        if not verified or not self.store.settings()["enabled"]:
            keyboard.inline_keyboard.insert(0, [InlineKeyboardButton(text="🟢 Periksa & Buka Toko", callback_data=self.store.token(user, "admin_toggle", {"enabled": True, "back": "admin_menu"}))])
        await self.ui.send(message, text, keyboard)

    async def refills(self, message, user, payload=None):
        self.authorize(user)
        payload = payload or {}
        health = self.store.refill_health()
        size = 4
        page = min(number(payload.get('page',0),0,100000),max(0,math.ceil(health['total']/size)-1))
        rows = self.store.repo.all('''SELECT r.*,o.service_name_snapshot FROM sosmed_refills r
            JOIN sosmed_orders o ON o.id=r.order_id ORDER BY r.id DESC LIMIT ? OFFSET ?''',(size,page*size))
        text = ('🔄 <b>STATUS REFILL SOSMED</b>\n\n'
                f"Pengajuan: {'Aktif' if health['enabled'] else 'Nonaktif'} • Kontrak API tersedia\n"
                f"Total: {health['total']} • Menunggu: {health['pending']} • Selesai: {health['completed']}\n"
                f"Halaman {page+1}/{max(1,math.ceil(health['total']/size))}\n\n")
        controls = []
        for refill in rows:
            text += f"#{refill['order_id']} • "+esc(self.ui.provider_label(refill['service_name_snapshot']),140)
            text += self.ui.refill_text(refill,admin=True)+'\n\n'
            controls.append([(f"🔎 Order #{refill['order_id']}",'admin_refill_check',{'id':refill['order_id']})])
        if not rows:
            text += 'Belum ada pengajuan refill. Pemeriksaan ini tidak membuat refill percobaan.\n'
        nav=[]
        if page:nav.append(('⬅️ Sebelumnya','admin_refills',{'page':page-1}))
        if (page+1)*size<health['total']:nav.append(('Berikutnya ➡️','admin_refills',{'page':page+1}))
        if nav:controls.append(nav)
        controls.append([('⏸ Jeda Refill' if health['enabled'] else '▶️ Aktifkan Refill','admin_refill_toggle',{'enabled':not health['enabled']})])
        controls.append([('⬅️ Kembali','admin_status',{}),('🏠 Menu Awal','admin_menu',{})])
        await self.ui.send(message,text,self.ui.keyboard(user,controls))

    async def catalog_report(self, message, user, payload=None):
        self.authorize(user)
        report = self.store.catalog.diagnostics()
        if not report:
            return await self.ui.send(message,'📋 <b>RINCIAN KATALOG</b>\n\nBelum ada rincian untuk konfigurasi akun ini. Buka Status API untuk memeriksa.',
                                      self.ui.navigation(user,'admin_status',admin=True))
        examples = report.get('examples',[])
        count = len(examples)
        page = min(number((payload or {}).get('page',0),0,100000),max(0,math.ceil(count/PAGE_SIZE)-1))
        text = ("📋 <b>RINCIAN VALIDASI KATALOG</b>\n"
                f"Diperiksa: {instant(report['checked_at'])}\n"
                f"Masuk: {report['received']} • Unik valid: {report['valid_unique']} • Dapat dibeli: {report['purchasable']}\n"
                f"Ditolak: {report['rejected_rows']} • Identik digabung: {report['identical_duplicates']}\n"
                f"ID konflik: {report['conflicting_ids']} • Status: {esc(report['state'])}\n\n")
        for example in examples[page*PAGE_SIZE:(page+1)*PAGE_SIZE]:
            ident = '#'+str(example['id']) if example['id'] is not None else 'ID tidak valid'
            text += (f"<b>Entri {example['row']} • {ident}</b>\n"
                     f"Kolom: {esc(example['field'],80)} • Min: {esc(example['min'],90)} • Max: {esc(example['max'],90)}\n"
                     f"{esc(self.ui.provider_label(example['reason']),230)}\n\n")
        if not examples:
            text += '✅ Tidak ada entri yang ditolak.\n\n'
        elif report['rejected_rows']>count:
            text += f"Ditampilkan {count} contoh pertama dari {report['rejected_rows']} penolakan.\n\n"
        text += (f"Halaman {page+1}/{max(1,math.ceil(count/PAGE_SIZE))}\n"
                 "Entri invalid/ID konflik tidak dijual; layanan valid tetap dapat diproses. "
                 "Bilangan bulat JSON/100.0 dapat dibaca; pecahan, min/max terbalik, dan pemisah ambigu perlu diperbaiki pada sumber.")
        rows = self.ui.pages(user,'admin_catalog',{},page,count)+[
            [('🔄 Periksa Lagi','admin_status',{})],[('⬅️ Kembali','admin_menu',{})]]
        return await self.ui.send(message,text,self.ui.keyboard(user,rows))

    async def pending(self, message, user, payload=None, *, refunds=False):
        self.authorize(user)
        page = number((payload or {}).get("page", 0), 0, 100000)
        if refunds:
            rows = self.store.repo.all("SELECT * FROM sosmed_orders WHERE refund_state IN ('AWAITING_PROVIDER_PROOF','AWAITING_REMAINS') ORDER BY id DESC LIMIT 8 OFFSET ?", (page*PAGE_SIZE,))
            count = self.store.repo.one("SELECT COUNT(*) n FROM sosmed_orders WHERE refund_state IN ('AWAITING_PROVIDER_PROOF','AWAITING_REMAINS')")["n"]
            lines = [f"Order #{row['id']} • {esc(row['refund_state'])}" for row in rows]
            note = ("Gagal: refund saldo penuh. Partial: proporsional jumlah belum terpenuhi; jumlah yang belum tersedia perlu diperiksa.\n"
                    "Refund saldo toko tidak menunggu kredit provider. Bukti kredit provider dicatat terpisah untuk profit, tanpa kredit saldo ganda.\n"
                    "Command: /sosmed admin refund &lt;order&gt; &lt;refund_modal_idr&gt; &lt;referensi_bukti&gt;")
        else:
            self.store.purchase.recover()
            rows = self.store.repo.all("""SELECT * FROM sosmed_purchase_attempts
                WHERE state IN ('RESERVED','REQUESTING','RECONCILIATION_REQUIRED','PENDING_RECONCILIATION')
                AND NOT EXISTS (SELECT 1 FROM sosmed_orders o WHERE o.attempt_id=sosmed_purchase_attempts.attempt_id)
                ORDER BY created_at DESC LIMIT 8 OFFSET ?""", (page*PAGE_SIZE,))
            count = self.store.repo.one("""SELECT COUNT(*) n FROM sosmed_purchase_attempts
                WHERE state IN ('RESERVED','REQUESTING','RECONCILIATION_REQUIRED','PENDING_RECONCILIATION')
                AND NOT EXISTS (SELECT 1 FROM sosmed_orders o WHERE o.attempt_id=sosmed_purchase_attempts.attempt_id)""")["n"]
            lines = [f"<code>{esc(row['attempt_id'])}</code>\nUser {row['user_id']} • {esc(row['state'])}" for row in rows]
            note = ("Pilih transaksi untuk memeriksa saldo ditahan atau memakai Batalkan &amp; Refund Saldo.\n"
                    "Pembatalan menutup transaksi di bot; bot tidak membeli atau memprosesnya ulang.\n"
                    "Periksa pesanan yang mungkin sudah diterima pada dashboard provider.")
        action = "admin_refunds" if refunds else "admin_pending"
        keyboard_rows = ([[(f"T-{row['attempt_id'][:12]} • {core.money(row['hold_amount'])}",
                           'admin_attempt',{'id':row['attempt_id']})] for row in rows] if not refunds else [])
        keyboard_rows += self.ui.pages(user, action, {}, page, count)+[[('⬅️ Kembali', 'admin_menu', {})]]
        await self.ui.send(message, ("↩️ <b>REFUND PERLU DIPERIKSA</b>\n\n" if refunds else "⏳ <b>REKONSILIASI PEMBELIAN</b>\n\n")
                           + ("\n\n".join(lines) if lines else "Tidak ada transaksi menunggu.")+"\n\n"+note,
                           self.ui.keyboard(user, keyboard_rows))

    async def command(self, message, user, args):
        self.authorize(user)
        name = args[0].lower() if args else ""
        if name in {"", "saldo"}:
            return await self.dashboard(message, user, balance_only=name == "saldo")
        if name in {"statistik", "profit"}:
            return await self.statistics(message, user, profit=name == "profit")
        if name == "layanan" and len(args) == 3 and args[1].lower() in {"on", "off"}:
            self.store.catalog.toggle(user, "service", str(number(args[2], 1)), args[1].lower() == "on")
            return await self.settings(message, user)
        if name in {"layanan", "harga"}:
            if name == "layanan" or len(args) > 1 and args[1].lower() in {"provider", "jual"}:
                return await self.ui.services(message, user, admin=True)
            if len(args) == 1:
                return await self.pricing(message, user)
            if len(args) == 4 and args[1] == "set":
                self.store.pricing.set_rule(user, "service", str(number(args[2], 1)), {"sale_rate": str(number(args[3], 0))})
            elif len(args) == 3 and args[1] == "reset":
                self.store.pricing.reset_rule(user, "service", str(number(args[2], 1)))
            else:
                raise core.StoreError("INPUT", "Format harga: /sosmed admin harga set <service_id> <harga_unit> atau harga reset <service_id>.")
            return await self.pricing(message, user)
        if name == "markup" and len(args) == 3:
            key = {"persen": "percent", "nominal": "fixed", "mode": "mode"}.get(args[1].lower())
            if not key:
                raise core.StoreError("INPUT", "Markup: persen, nominal, atau mode.")
            value = args[2]
            if key == "mode":
                value = {"persen": "percent", "nominal": "fixed", "kombinasi": "combined"}.get(value.lower(), value.lower())
            elif key == "fixed":
                value = number(value)
            self.store.set_setting(key, value, user)
            return await self.pricing(message, user)
        if name in {"kategori", "layanan"} and len(args) >= 3:
            # Quoted category names are handled by shlex in the command router.
            if args[1].lower() in {"on", "off"} and len(args) == 3:
                self.store.catalog.toggle(user, "category" if name == "kategori" else "service", args[2], args[1].lower() == "on")
                return await self.settings(message, user)
        if name in {"rule", "aturan"} and len(args) == 5:
            scope, key, component, value = args[1:]
            component = {"persen": "percent", "nominal": "fixed", "harga": "sale_rate", "mode": "mode"}.get(component.lower())
            if scope not in {"service", "category"} or not component:
                raise core.StoreError("INPUT", "Aturan: service/category, lalu persen/nominal/harga/mode.")
            if component == "mode":
                value = {"persen": "percent", "nominal": "fixed", "kombinasi": "combined"}.get(value, value)
            self.store.pricing.set_rule(user, scope, key, {component: value})
            return await self.scope(message, user, {"scope": scope, "key": key})
        if name in {"orders", "pesanan"}:
            return await self.ui.orders(message, user, admin=True)
        if name in {"pending", "rekonsiliasi", "refunds"}:
            return await self.pending(message, user, refunds=name == "refunds")
        if name == "sync":
            services = await self.store.catalog.sync(force=True)
            await self.ui.send(message, f"✅ Sinkronisasi selesai: {len(services)} layanan dari API.", self.ui.navigation(user, "admin_menu", admin=True))
            return
        if name in {"on", "off"}:
            if name == "on":
                await self.store.enable_from_provider(user)
            else:
                self.store.set_setting("enabled", False, user)
            return await self.settings(message, user)
        if name == "rugi" and len(args) == 2 and args[1].lower() in {"on", "off"}:
            self.store.set_setting("allow_loss", args[1].lower() == "on", user)
            return await self.pricing(message, user)
        if name in {"limit", "jumlah", "polling", "pembulatan", "minimum"} and len(args) == 2:
            key = {"limit": "max_active", "jumlah": "max_quantity", "polling": "poll_seconds", "pembulatan": "rounding", "minimum": "min_sale"}[name]
            self.store.set_setting(key, number(args[1]), user)
            return await self.settings(message, user)
        if name == "status":
            return await self.health(message, user)
        if name == "metadata" and len(args) >= 4:
            self.store.catalog.metadata(user, number(args[1], 1), " ".join(args[3:]), args[2])
            return await self.ui.detail(message, user, number(args[1], 1), admin=True)
        if name == "reconcile" and len(args) == 4:
            await self.store.admin_reconcile(user, args[1], number(args[2], 1), args[3])
            return await self.pending(message, user)
        if name == "release" and len(args) == 3:
            self.store.admin_release(user, args[1], args[2])
            return await self.pending(message, user)
        if name == "refund" and len(args) == 4:
            await self.store.admin_refund(user, number(args[1], 1), number(args[2], 1), args[3])
            return await self.pending(message, user, refunds=True)
        raise core.StoreError("INPUT", "Gunakan /sosmed admin, saldo, harga, markup, orders, statistik, profit, sync, status, on/off, limit, atau pending.")


FIELD_LABELS = {
    "link": "🔗 Kirim link atau username target sesuai layanan. Bot tidak membuka link ini.",
    "quantity": "🔢 Kirim jumlah pembelian (angka bulat).",
    "comments": "💬 Kirim komentar asli, satu komentar per baris. Komentar dikirim sesuai input kamu.",
    "runs": "⏱️ Kirim jumlah run drip-feed (angka bulat).",
    "interval": "⏱️ Kirim interval antar-run dalam menit (angka bulat).",
    "username": "👤 Kirim username target sesuai layanan.",
    "usernames": "👥 Kirim daftar username sesuai petunjuk, satu username per baris.",
    "answer_number": "📊 Kirim nomor pilihan polling (angka bulat).",
    "hashtag": "#️⃣ Kirim hashtag sesuai layanan.",
    "media": "🔗 Kirim link media sesuai layanan.",
    "keywords": "🔎 Kirim kata kunci sesuai persyaratan layanan.",
}


async def register_dispatch(store, ui, admin, message, user, action, payload, state):
    """Public dispatch helper; role and ownership checks are repeated here."""
    if action.startswith("admin"):
        admin.authorize(user)
    if action not in {"field", "admin_value"}:
        await store.host.shopping_navigation_exit(user, state)
        await state.clear()
    if action == "home":
        return await ui.home(message, user)
    if action == "balance":
        return await ui.balance(message, user)
    if action == "categories":
        return await ui.categories(message, user, payload)
    if action == 'popular':
        return await ui.categories(message,user,payload)
    if action in {"services", "favorites"}:
        return await ui.services(message, user, payload, favorites=action == "favorites")
    if action == "detail":
        return await ui.detail(message, user, number(payload["id"], 1), payload.get("back"), refresh=payload.get("refresh") is True)
    if action == "favorite":
        store.repo.favorite(user, number(payload["id"], 1))
        return await ui.detail(message, user, number(payload["id"], 1), payload.get("back"))
    if action in {"orders", "history"}:
        return await ui.orders(message, user, payload, history=action == "history")
    if action == "check":
        return await ui.check(message, user, number(payload["id"], 1))
    if action in {'refill_check','admin_refill_check'}:
        return await ui.check(message,user,number(payload['id'],1),admin=action=='admin_refill_check',refresh=False,refresh_refill=True)
    if action == 'confirm_refill':
        order=store.repo.order(user,number(payload['id'],1))
        if not store.refill_contract_verified() or order['status']!='COMPLETED' or store.orders.refill_capability(order) is False:
            raise core.StoreError('REFILL')
        text=('🔄 <b>KONFIRMASI PENGAJUAN REFILL</b>\n'
              f"Order #{order['id']}\n\nKelayakan dan hasil mengikuti ketentuan layanan/pesanan. "
              'Pengajuan refill tidak memotong saldo bot. Jangan mengajukan ulang bila hasil belum pasti.')
        return await ui.send(message,text,ui.keyboard(user,[[('✅ Ajukan Refill','refill',{'id':order['id']})],
            [('⬅️ Kembali','check',{'id':order['id']})]]))
    if action in {"attempt","admin_attempt"}:
        return await ui.attempt(message,user,payload["id"],payload,admin=action=="admin_attempt")
    if action == 'admin_cancel_hold':
        return await admin.cancel_hold(message,user,payload)
    if action == 'admin_cancel_hold_confirm':
        store.admin_cancel_hold(user,payload['id'],payload['buyer'],payload['amount'])
        return await ui.attempt(message,user,payload['id'],admin=True)
    if action in {'search','admin_search'}:
        is_admin_search = action=='admin_search'
        context = {key:payload[key] for key in ('category','platform','query','filters','view','page','category_query','category_page') if key in payload}
        await state.set_state(SosmedOrderState.search)
        await state.update_data(sosmed_search_context={**context,'_admin_search':is_admin_search})
        back = 'admin_services' if is_admin_search else 'favorites' if context.get('view')=='favorites' else 'services'
        scope = context.get('category') or {'tiktok':'TikTok','instagram':'Instagram'}.get(context.get('platform'),'Semua layanan')
        scope = ui.provider_label(scope) if is_admin_search else ui.public_label(scope,180)
        return await ui.send(message, "🔎 <b>CARI LAYANAN</b>\n"+esc(scope,180)+"\n\nKirim kata kunci, misalnya: followers atau likes.\n"
                             "Filter opsional: refill:ya tersedia:ya min:100 max:10000 harga:20000\n"
                             "Harga memakai tarif per 1.000.", ui.navigation(user,back,context,admin=is_admin_search))
    if action in {"category_search", "admin_category_search"}:
        admin_search = action == "admin_category_search"
        browse = admin_search and payload.get("browse") is True
        context = {key:payload[key] for key in ("platform", "category_query", "page") if key in payload}
        await state.set_state(SosmedOrderState.category_search)
        await state.update_data(sosmed_category_search_context={
            **context, "_admin_category_search": admin_search, "_category_browse": browse})
        back = "admin_price_categories" if browse else "admin_categories" if admin_search else "categories"
        scope = {"tiktok": "TikTok", "instagram": "Instagram"}.get(context.get("platform"), "Semua kategori")
        return await ui.send(message, "🔎 <b>CARI KATEGORI</b>\n"+esc(scope)+"\n\n"
                             "Ketik nama atau kata kunci kategori, misalnya: follower, likes, atau livestream.\n"
                             "Hasil menampilkan pilihan kategori yang cocok.",
                             ui.navigation(user, back, context, admin=admin_search))
    if action == "help":
        text = ("❓ <b>PANDUAN SOSMED</b>\n\nPilih kategori dan layanan, baca detail, isi parameter, lalu pilih pembayaran saldo atau QRIS Manual jika tersedia.\n"
                "Saldo dipakai bersama fitur belanja dan OTP. Isi Saldo memakai pembayaran bot yang sudah tersedia.\n"
                "Jika hasil pembelian belum pasti, jangan membeli ulang. Cek Pesanan Saya dan hubungi owner.\n"
                "Gagal terkonfirmasi: harga dibayar kembali penuh ke saldo. Partial: harga dibayar × jumlah belum terpenuhi ÷ jumlah pesanan, dibulatkan ke bawah.\n"
                "Jumlah partial yang belum tersedia diperiksa dahulu. Pembelian yang hasilnya belum pasti tetap terlihat di Pesanan dan Riwayat dengan saldo ditahan.\n\n"
                "/sosmed beli • kategori • layanan • cari &lt;nama&gt;\n"
                "/sosmed detail &lt;id layanan&gt;\n/sosmed saldo • pesanan • riwayat • favorit\n"
                "/sosmed cek &lt;id order bot&gt;\n/sosmed refill &lt;id order bot&gt;\n/sosmed batal &lt;id order bot&gt;\n\n"
                "Gunakan layanan sesuai ketentuan platform. Jangan mengirim spam, ancaman, atau pelecehan.")
        return await ui.send(message, text, ui.navigation(user))
    if action == "buy":
        store.purchase_guard(user)
        service = await store.catalog.live(number(payload["id"], 1))
        if not service.get("order_supported", False):
            raise core.StoreError("TYPE")
        fields = core.FormAdapter.fields(service, drip=bool(payload.get("drip")))
        if not core.FormAdapter.supported(service) or not fields or any(field not in FIELD_LABELS for field in fields):
            raise core.StoreError("UNSUPPORTED_TYPE", "Form layanan belum didukung.")
        if not store.owner(user) and (store.host.safe_mode_enabled() or store.host.maintenance_enabled()):
            raise core.StoreError("MAINTENANCE", "Pembelian sementara ditutup.")
        await state.set_state(SosmedOrderState.field)
        await state.update_data(sosmed_service_id=service["provider_service_id"], sosmed_fields=fields,
                                sosmed_index=0, sosmed_parameters={})
        return await ui.send(message, "🛒 <b>ISI PESANAN</b>\n"+esc(ui.public_label(service['name'], 220))+"\n\n"
                             +(core.FormAdapter.target_prompt(service) if fields[0]=='link' else FIELD_LABELS[fields[0]])+f"\nMin {service['min_quantity']} • Max {service['max_quantity']}",
                             ui.navigation(user, "detail", {"id": service["provider_service_id"]}))
    if action == 'pay_manual':
        payment = await store.payments.create_manual(user,str(payload['quote']))
        return await ui.payment(message,user,payment['payment_id'])
    if action in {'payment_status','payment_cancel'}:
        store.payments.owned(user,payload['payment'])
        if action=='payment_cancel':
            store.payments.cancel(user,payload['payment'])
        else:
            await store.payments.reconcile()
        return await ui.payment(message,user,payload['payment'])
    if action == "pay":
        result = await store.purchase.buy(user, str(payload["quote"]))
        if result.get("state") in {"CAPTURED", "SUCCESS"} and result.get("order"):
            order = result["order"]
            await payment_receipts.notify(store.host, message.bot, "sosmed", order["id"])
            return
        if result.get("state") in {"FAILED", "RELEASED"}:
            return await ui.send(message, "❌ Pesanan tidak berhasil dibuat. Dana transaksi yang ditahan telah dilepas.", ui.navigation(user))
        if result.get('state')=='CANCELED':
            return await ui.attempt(message,user,result['attempt_id'],{'history':True})
        return await ui.send(message, "⏳ Hasil pesanan belum pasti. Dana transaksi ini tetap ditahan. "
                             "Jangan membeli ulang; periksa Pesanan Saya atau hubungi owner.",
                             ui.keyboard(user, [[("📦 Pesanan Saya", "orders", {})], [("🏠 Menu Awal", "home", {})]]))
    if action == "refill":
        result = await store.orders.refill(user, number(payload["id"], 1))
        status = str(result.get("status", "PENDING")).upper()
        text = "Permintaan refill tercatat. Hasil mengikuti ketentuan layanan."
        if status in {"UNKNOWN", "RECONCILIATION_REQUIRED"}:
            text = "Hasil permintaan refill belum pasti. Jangan mengirim refill ulang; owner akan memeriksanya."
        elif status in {"REJECTED", "FAILED"}:
            text = "Permintaan refill ditolak. Periksa ketentuan layanan atau hubungi owner."
        return await ui.send(message, "🔄 "+text, ui.navigation(user, "check", {"id": payload["id"]}))
    if action == "confirm_cancel":
        if not getattr(store.config, "cancel_verified", False):
            raise core.StoreError("CANCEL_UNSUPPORTED", "Pembatalan belum tersedia di toko.")
        order = await store.orders.refresh(user, number(payload["id"], 1))
        if not order.get("cancel_supported"):
            raise core.StoreError("CANCEL_UNSUPPORTED", "Pembatalan tidak tersedia.")
        return await ui.send(message, f"❌ <b>KONFIRMASI PEMBATALAN</b>\nOrder #{esc(payload['id'])}\n\n"
                             "Pembatalan mengikuti ketentuan layanan. Refund hanya dikreditkan setelah pengembalian dana resmi terkonfirmasi.",
                             ui.keyboard(user, [[("✅ Ajukan Pembatalan", "cancel", {"id": payload["id"]})],
                                                [("⬅️ Kembali", "check", {"id": payload["id"]})]]))
    if action == "cancel":
        order = await store.orders.cancel(user, number(payload["id"], 1), confirmed=True)
        note = {"REJECTED": "Permintaan pembatalan ditolak. Pesanan tetap mengikuti status terakhir.",
                "UNKNOWN": "Hasil pembatalan belum pasti. Jangan mengulang; owner akan memeriksanya.",
                "ACCEPTED": "Permintaan pembatalan diterima. Refund menunggu bukti pengembalian dana terkonfirmasi."}.get(order.get("cancel_state"), "Permintaan pembatalan sedang diperiksa.")
        return await ui.send(message, "❌ "+note+"\n\n"
                             +ui.order_text(order), ui.order_keyboard(user, order))
    if action == "admin_menu":
        return await admin.dashboard(message, user)
    if action == "admin_balance":
        return await admin.dashboard(message, user, balance_only=True)
    if action in {"admin_stats", "admin_profit"}:
        return await admin.statistics(message, user, profit=action == "admin_profit")
    if action == "admin_status":
        return await admin.health(message, user)
    if action == 'admin_refills':
        return await admin.refills(message,user,payload)
    if action == 'admin_refill_toggle':
        if type(payload.get('enabled')) is not bool:
            raise core.StoreError('INPUT')
        if payload['enabled']:
            await store.check_provider(user)
        store.set_refill_contract(user,payload['enabled'])
        return await admin.refills(message,user)
    if action == "admin_catalog":
        return await admin.catalog_report(message,user,payload)
    if action == "admin_units":
        return await admin.units(message, user)
    if action == "admin_units_choose":
        field, value = payload.get("field"), payload.get("value")
        if field not in {"currency", "rate_unit", "reset"} or value != {"currency": "IDR", "rate_unit": "1000", "reset": None}[field]:
            raise core.StoreError("INPUT")
        units = store.provider_units()
        if field == "reset":
            old = (units["currency"] or "Belum diketahui")+" / "+(units["rate_unit"] or "Belum diketahui")
            new = "Konfirmasi owner dihapus; nilai API/Variables tetap berlaku"
        else:
            old, new = units[field] or "Belum dikonfirmasi", "IDR (rupiah)" if field == "currency" else "Harga untuk 1.000 jumlah"
        text = ("💱 <b>KONFIRMASI MATA UANG / SATUAN</b>\n\n"
                f"Lama: {esc(old)}\nBaru: {esc(new)}\n\n"
                "Simpan setelah cocok dengan dashboard dan tarif layanan. Pembelian baru perlu diperiksa kembali; quote yang belum dibayar harus dibuat ulang.")
        rows = [[("✅ Simpan", "admin_units_confirm", {"field": field, "value": value, "account": store.account_fingerprint()})],
                [("❌ Batal", "admin_units", {})]]
        return await ui.send(message, text, ui.keyboard(user, rows))
    if action == "admin_units_confirm":
        store.set_provider_unit(user, payload.get("field"), payload.get("value"), payload.get("account"))
        return await admin.units(message, user)
    if action == "admin_orders":
        return await ui.orders(message, user, payload, admin=True)
    if action == "admin_check":
        return await ui.check(message, user, number(payload["id"], 1), admin=True)
    if action == "admin_services":
        return await ui.services(message, user, payload, admin=True)
    if action == 'admin_price_categories':
        return await ui.categories(message,user,payload,admin=True,browse=True)
    if action == 'admin_price_breakdown':
        return await admin.price_breakdown(message,user,payload)
    if action == "admin_detail":
        return await ui.detail(message, user, number(payload["id"], 1), payload.get("back"), admin=True, refresh=payload.get("refresh") is True)
    if action == 'admin_form':
        return await admin.form(message,user,payload)
    if action == 'admin_form_choose':
        ident=number(payload['id'],1)
        service=store.catalog.service(ident,active=False)
        kind=payload.get('type')
        if kind not in {None,'Default','Comment','Mentions Custom List','Comment Replies'}:
            raise core.StoreError('TYPE')
        raw=json.loads(service['raw_catalog'])
        before=service['type']
        after=core.FormAdapter.catalogue_type(raw)[0] if kind is None else kind
        text=("📋 <b>KONFIRMASI TIPE INPUT</b>\n"+esc(ui.provider_label(service['name']),500)+
              f"\nLama: {esc(before)}\nBaru: {esc(after)}\n\n"
              "Konfirmasi sesuai dokumentasi provider. Quote yang belum dibayar harus dikonfirmasi ulang.")
        rows=[[('✅ Simpan','admin_form_confirm',{'id':ident,'type':kind})],
              [('❌ Batal','admin_form',{'id':ident})]]
        return await ui.send(message,text,ui.keyboard(user,rows))
    if action == 'admin_form_confirm':
        ident=number(payload['id'],1)
        store.catalog.set_form(user,ident,payload.get('type'))
        await store.catalog.sync(force=True)
        return await ui.detail(message,user,ident,admin=True)
    if action == "admin_categories":
        return await ui.categories(message, user, payload, admin=True)
    if action == "admin_pricing":
        return await admin.pricing(message, user)
    if action == "admin_settings":
        return await admin.settings(message, user)
    if action == "admin_scope":
        return await admin.scope(message, user, payload)
    if action == "admin_toggle":
        if type(payload.get("enabled")) is not bool:
            raise core.StoreError("INPUT", "Pengaturan toko tidak valid.")
        if payload["enabled"]:
            await store.enable_from_provider(user)
        else:
            store.set_setting("enabled", False, user)
        if payload.get("back") == "admin_menu":
            return await admin.dashboard(message, user)
        return await admin.settings(message, user)
    if action in {"admin_category_toggle", "admin_service_toggle"}:
        store.catalog.toggle(user, "category" if action == "admin_category_toggle" else "service",
                             payload.get("key") if action == "admin_category_toggle" else str(number(payload["id"], 1)), bool(payload["enabled"]))
        return await admin.settings(message, user)
    if action == "admin_rule_reset":
        store.pricing.reset_rule(user, payload["scope"], payload["key"])
        return await admin.scope(message, user, payload)
    if action == "admin_sync":
        return await admin.command(message, user, ["sync"])
    if action in {"admin_pending", "admin_refunds"}:
        return await admin.pending(message, user, payload, refunds=action == "admin_refunds")
    if action == "admin_modes":
        rows = [[(label, "admin_mode", {**payload, "mode": mode})] for label, mode in
                [("Persentase", "percent"), ("Nominal", "fixed"), ("Kombinasi", "combined")]]
        rows.append([("⬅️ Kembali", "admin_scope" if payload.get("scope") else "admin_pricing", payload)])
        return await ui.send(message, "⚙️ Pilih mode harga:", ui.keyboard(user, rows))
    if action == "admin_mode":
        if payload.get("scope"):
            store.pricing.set_rule(user, payload["scope"], payload["key"], {"mode": payload["mode"]})
            return await admin.scope(message, user, payload)
        store.set_setting("mode", payload["mode"], user)
        return await admin.pricing(message, user)
    if action == "admin_input":
        await state.set_state(SosmedOrderState.admin_value)
        await state.update_data(sosmed_admin_input=payload)
        prompt = "📝 Kirim sumber metadata dan deskripsi dengan format: sumber deskripsi lengkap." if payload.get("kind") == "metadata" else "Kirim nilai untuk "+str(payload.get("setting"))+"."
        if payload.get("setting") == "rounding":
            prompt += " Pilihan: 0, 100, 500, atau 1000."
        return await ui.send(message, esc(prompt), ui.navigation(user, "admin_scope" if payload.get("scope") else "admin_pricing", payload, admin=True))
    raise core.StoreError("INPUT", "Menu belum dikenal.")


def register(router, store):
    """Register once on the existing router before its generic fallback."""
    store.ui = UIBuilder(store)
    admin, ui = AdminHandler(store), store.ui

    async def guard(message, user):
        if not message or str(message.chat.type) != "private" or message.chat.id != user:
            raise core.StoreError("PRIVATE", "Gunakan /sosmed melalui chat privat bot.")
        if store.host.security_blocked(user):
            raise core.StoreError("BLOCKED", "Akun kamu dibatasi owner.")
        if not await store.host.is_channel_member(message.bot, user):
            raise core.StoreError("CHANNEL", "Buka /start dan verifikasi channel dahulu.")
        profile = store.repo.one("SELECT username FROM verified_users WHERE user_id=?", (user,))
        username = profile.get("username", "") if profile else ""
        if message.from_user and message.from_user.id == user:
            username = getattr(message.from_user, "username", "") or username
        store.host.mark_user_verified(user, username)

    async def failure(message, exc, user, admin_context=False):
        if not isinstance(exc, core.StoreError):
            logging.warning("SOSMED handler error: %s", type(exc).__name__)
        if admin_context and store.owner(user) and isinstance(exc, core.StoreError):
            # core.public is curated; raw API messages are never included.
            text = exc.public
        else:
            text = UserFormatter.error(exc)
        if message and str(message.chat.type) == "private" and message.chat.id == user:
            await ui.send(message, "⚠️ "+esc(text), ui.navigation(user, "admin_menu" if admin_context and store.owner(user) else "home", admin=admin_context and store.owner(user)))

    @router.message(Command("sosmed"))
    async def sosmed_command(message, state):
        user, admin_context = message.from_user.id, False
        try:
            await guard(message, user)
            store.repo.rate(user, "command", 30, 60)
            text = message.text or ""
            if len(text) > 1500:
                raise core.StoreError("INPUT", "Command terlalu panjang.")
            try:
                args = shlex.split(text)[1:]
            except ValueError:
                raise core.StoreError("INPUT", "Tanda kutip command belum lengkap.") from None
            if len(args) > 40:
                raise core.StoreError("INPUT", "Command terlalu panjang.")
            await store.host.shopping_navigation_exit(user, state)
            await state.clear()
            if not args and store.owner(user):
                admin_context = True
                return await admin.dashboard(message, user)
            if args and args[0].lower() == "admin":
                admin_context = True
                return await admin.command(message, user, args[1:])
            name = args[0].lower() if args else ""
            mapping = {"": "home", "beli": "categories", "kategori": "categories", "layanan": "services",
                       "cari": "search", "detail": "detail", "saldo": "balance", "pesanan": "orders",
                       "cek": "check", "refill": "refill", "batal": "confirm_cancel", "riwayat": "history",
                       "favorit": "favorites", "bantuan": "help"}
            action = mapping.get(name)
            if not action:
                raise core.StoreError("INPUT", "Command belum dikenal. Gunakan /sosmed bantuan.")
            payload = {}
            if action in {"detail", "check", "refill", "confirm_cancel"}:
                if len(args) != 2:
                    raise core.StoreError("INPUT", "Gunakan /sosmed "+name+" <id>.")
                payload["id"] = number(args[1], 1, 2**63-1)
            elif name == "cari" and len(args) > 1:
                query, filters = search_input(" ".join(args[1:]))
                action, payload = "services", {"query": query, "filters": filters}
            elif len(args) > 1:
                raise core.StoreError("INPUT", "Parameter command tidak sesuai.")
            await register_dispatch(store, ui, admin, message, user, action, payload, state)
        except Exception as exc:
            await failure(message, exc, user, admin_context)

    @router.callback_query(F.data.startswith(PREFIX))
    async def sosmed_callback(call, state):
        user, action, menu, answered = call.from_user.id, "", None, False
        try:
            await guard(call.message, user)
            store.repo.rate(user, "callback", 40, 60)
            action, payload = store.resolve(user, call.data)
            if action.startswith("admin"):
                admin.authorize(user)
            await call.answer()
            answered = True
            menu = MenuMessage(call.message)
            await register_dispatch(store, ui, admin, menu, user, action, payload, state)
        except Exception as exc:
            if not answered:
                try:
                    await call.answer("Permintaan belum berhasil.", show_alert=True)
                except Exception:
                    pass
            await failure(menu or (MenuMessage(call.message) if call.message else None), exc, user, action.startswith("admin"))

    @router.message(SosmedOrderState.category_search, F.text & ~F.text.startswith("/") & ~F.text.in_(TEXT_MENU_ACTIONS))
    async def sosmed_category_search(message, state):
        user, menu = message.from_user.id, message
        admin_context = False
        try:
            await guard(message, user)
            store.repo.rate(user, "category_search", 10, 60)
            menu = ui.input_message(message)
            values = await state.get_data()
            context = values.get("sosmed_category_search_context", {})
            if not isinstance(context, dict):
                raise core.StoreError("INPUT", "Sesi pencarian tidak tersedia. Buka Cari Kategori lagi.")
            context = dict(context)
            admin_context = context.pop("_admin_category_search", False) is True
            if admin_context:
                admin.authorize(user)
            browse = context.pop("_category_browse", False) is True and admin_context
            query = category_input(message.text or "", required=True)
            await state.clear()
            await ui.categories(menu, user, {**context, "category_query": query, "page": 0},
                                admin=admin_context, browse=browse)
        except Exception as exc:
            await failure(menu, exc, user, admin_context)

    @router.message(SosmedOrderState.search, F.text & ~F.text.startswith("/") & ~F.text.in_(TEXT_MENU_ACTIONS))
    async def sosmed_search(message, state):
        user, menu = message.from_user.id, message
        admin_context = False
        try:
            await guard(message, user)
            store.repo.rate(user, "search", 10, 60)
            menu = ui.input_message(message)
            values = await state.get_data()
            context = values.get("sosmed_search_context", {})
            if not isinstance(context,dict):
                raise core.StoreError('INPUT','Sesi pencarian tidak tersedia. Buka Cari Layanan lagi.')
            context = dict(context)
            admin_context = context.pop('_admin_search',False) is True
            if admin_context:
                admin.authorize(user)
            query, filters = search_input(message.text or "")
            if len(query)>200:
                raise core.StoreError('INPUT','Kata kunci maksimal 200 karakter.')
            previous_filters = context.get('filters') or {}
            if not isinstance(previous_filters,dict):
                raise core.StoreError('INPUT')
            filters = {**previous_filters,**filters}
            await state.clear()
            await ui.services(menu,user,{**context,'query':query,'filters':filters,'page':0},
                              admin=admin_context,favorites=context.get('view')=='favorites' and not admin_context)
        except Exception as exc:
            await failure(menu, exc, user,admin_context)

    @router.message(SosmedOrderState.field, F.text & ~F.text.startswith("/") & ~F.text.in_(TEXT_MENU_ACTIONS))
    async def sosmed_field(message, state):
        user, menu = message.from_user.id, message
        try:
            await guard(message, user)
            store.repo.rate(user, "field", 30, 60)
            menu = ui.input_message(message)
            values = await state.get_data()
            service_id, fields = values.get("sosmed_service_id"), values.get("sosmed_fields", [])
            index, parameters = values.get("sosmed_index", 0), values.get("sosmed_parameters", {})
            if not isinstance(fields, list) or not 0 <= index < len(fields) or fields[index] not in FIELD_LABELS:
                raise core.StoreError("INPUT", "Sesi input tidak tersedia. Pilih layanan lagi.")
            field = fields[index]
            text = message.text or ""
            if len(text) > 12000:
                raise core.StoreError("INPUT", "Input terlalu panjang.")
            value = number(text.strip(), 1, 10**12) if field in {"quantity", "runs", "interval", "answer_number"} else text if field == "comments" else text.strip()
            if field == "link":
                value = core.FormAdapter.target_for(store.catalog.service(number(service_id,1)),value)
            parameters = {**parameters, field: value}
            index += 1
            if index < len(fields):
                await state.update_data(sosmed_index=index, sosmed_parameters=parameters)
                await ui.send(menu, FIELD_LABELS[fields[index]], ui.navigation(user, "detail", {"id": service_id}))
            else:
                quote = await store.purchase.quote(user, service_id, parameters)
                await state.clear()
                await ui.quote(menu, user, quote)
        except Exception as exc:
            await failure(menu, exc, user)

    @router.message(SosmedOrderState.admin_value, F.text & ~F.text.startswith("/") & ~F.text.in_(TEXT_MENU_ACTIONS))
    async def sosmed_admin_value(message, state):
        user, menu = message.from_user.id, message
        try:
            await guard(message, user)
            admin.authorize(user)
            store.repo.rate(user, "admin_input", 20, 60)
            menu = ui.input_message(message)
            payload = (await state.get_data()).get("sosmed_admin_input", {})
            text = (message.text or "").strip()
            if len(text) > 2000:
                raise core.StoreError("INPUT", "Input terlalu panjang.")
            if payload.get("kind") == "metadata":
                parts = text.split(maxsplit=1)
                if len(parts) != 2:
                    raise core.StoreError("INPUT", "Kirim sumber metadata lalu deskripsi.")
                store.catalog.metadata(user, number(payload["id"], 1), parts[1], parts[0])
                await state.clear()
                return await ui.detail(menu, user, payload["id"], admin=True)
            key = payload.get("setting")
            if key not in {"percent", "fixed", "rounding", "min_sale", "max_active", "max_quantity", "poll_seconds", "sale_rate"}:
                raise core.StoreError("INPUT", "Pengaturan tidak valid.")
            value = text if key in {"percent", "sale_rate"} else number(text)
            if payload.get("scope"):
                store.pricing.set_rule(user, payload["scope"], payload["key"], {key: value})
                await state.clear()
                return await admin.scope(menu, user, payload)
            store.set_setting(key, value, user)
            await state.clear()
            await admin.pricing(menu, user) if key in {"percent", "fixed", "rounding", "min_sale"} else await admin.settings(menu, user)
        except Exception as exc:
            await failure(menu, exc, user, True)

    return store
