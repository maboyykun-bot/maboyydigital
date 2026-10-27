"""Multi-bank management and immutable invoices on the existing SQLite store."""
import hashlib
import html
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from aiogram import F
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from otp_smscode import MenuMessage
from sosmed_ui import TEXT_MENU_ACTIONS

PREFIX = "bankacct:"
FIELDS = ("bank_name", "account_number", "holder_name", "note")
LABELS = {"bank_name": "Nama bank", "account_number": "Nomor rekening",
          "holder_name": "Nama pemilik", "note": "Catatan untuk user (kirim - jika kosong)"}


class BankError(Exception):
    pass


class BankState(StatesGroup):
    field = State()


def dumped(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fragment(value, limit):
    value = str(value or "")
    original = value
    while len(html.escape(value).encode('utf-16-le'))//2 > limit:
        value = value[:-1]
    return html.escape(value)+("…" if value != original else "")


def account_text(row):
    if not row:
        return "Rekening belum tersedia. Hubungi owner."
    text = (f"🏦 Bank: <b>{fragment(row.get('bank_name'), 200)}</b>\n"
            f"👤 Atas Nama: <b>{fragment(row.get('holder_name'), 300)}</b>\n"
            f"💳 Nomor Rekening: <code>{fragment(row.get('account_number'), 100)}</code>")
    if row.get("note"):
        text += "\n📝 "+fragment(row["note"], 600)
    return text


def validate(values):
    if not isinstance(values, dict) or set(values) - set(FIELDS):
        raise BankError("Data rekening tidak valid.")
    result = {}
    for name, maximum in (("bank_name", 60), ("account_number", 40), ("holder_name", 100), ("note", 200)):
        value = values.get(name, "")
        if not isinstance(value, str) or "\x00" in value or "\r" in value or "\n" in value:
            raise BankError("Masukkan satu baris untuk setiap data rekening.")
        value = value.strip()
        if name == "account_number":
            value = value.replace(" ", "")
            if not re.fullmatch(r"[0-9]{4,40}", value):
                raise BankError("Nomor rekening harus 4–40 digit; angka nol di awal tetap disimpan.")
        if len(value) > maximum or (name != "note" and not value):
            raise BankError(f"{LABELS[name]} wajib diisi dan maksimal {maximum} karakter.")
        result[name] = value
    return result


def _legacy(conn):
    if conn.execute("SELECT 1 FROM bank_accounts LIMIT 1").fetchone():
        return
    legacy = {r["key"]: str(r["value"] or "") for r in conn.execute("SELECT key,value FROM settings WHERE key IN ('bank_name','bank_account','bank_holder','bank_note')")}
    data = {"bank_name": legacy.get("bank_name", ""), "account_number": legacy.get("bank_account", ""),
            "holder_name": legacy.get("bank_holder", ""), "note": legacy.get("bank_note", "")}
    if not any(data.values()):
        return
    active = int(all(data[k].strip() for k in FIELDS[:3]))
    now = stamp()
    cur = conn.execute("""INSERT INTO bank_accounts(bank_name,account_number,holder_name,note,active,is_default,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?)""", (*[data[k] for k in FIELDS], active, active, now, now))
    conn.execute("INSERT INTO bank_account_history(actor_id,action,account_id,before_json,after_json,created_at,draft_token) VALUES(0,'migrate',?,'null',?,?,'legacy-migration')",
                 (cur.lastrowid, dumped(data), now))


def init_schema(conn):
    schema = """
        CREATE TABLE IF NOT EXISTS bank_accounts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,bank_name TEXT NOT NULL,account_number TEXT NOT NULL,
          holder_name TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',active INTEGER NOT NULL DEFAULT 1 CHECK(active IN(0,1)),
          is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN(0,1)),deleted_at TEXT NOT NULL DEFAULT '',
          revision INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
          CHECK(is_default=0 OR (active=1 AND deleted_at='')));
        CREATE UNIQUE INDEX IF NOT EXISTS bank_one_default ON bank_accounts(is_default) WHERE is_default=1;
        CREATE UNIQUE INDEX IF NOT EXISTS bank_unique_live ON bank_accounts(bank_name COLLATE NOCASE,account_number) WHERE deleted_at='';
        CREATE TABLE IF NOT EXISTS bank_account_history(
          id INTEGER PRIMARY KEY AUTOINCREMENT,actor_id INTEGER NOT NULL,action TEXT NOT NULL,
          account_id INTEGER NOT NULL,before_json TEXT NOT NULL,after_json TEXT NOT NULL,created_at TEXT NOT NULL,
          draft_token TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS bank_change_drafts(
          token TEXT PRIMARY KEY,owner_id INTEGER NOT NULL,action TEXT NOT NULL,account_id INTEGER,
          before_json TEXT NOT NULL,after_json TEXT NOT NULL,base_hash TEXT NOT NULL,
          expires_at REAL NOT NULL,state TEXT NOT NULL DEFAULT 'PENDING',result_id INTEGER);
        CREATE TABLE IF NOT EXISTS bank_invoice_snapshots(
          entity TEXT NOT NULL CHECK(entity IN('order','topup')),entity_id INTEGER NOT NULL,
          bank_id INTEGER REFERENCES bank_accounts(id),bank_name TEXT NOT NULL,account_number TEXT NOT NULL,
          holder_name TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,source TEXT NOT NULL,
          PRIMARY KEY(entity,entity_id));
        CREATE TRIGGER IF NOT EXISTS bank_snapshot_immutable_update BEFORE UPDATE ON bank_invoice_snapshots
          BEGIN SELECT RAISE(ABORT,'Bank invoice snapshot is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS bank_snapshot_immutable_delete BEFORE DELETE ON bank_invoice_snapshots
          BEGIN SELECT RAISE(ABORT,'Bank invoice snapshot is immutable'); END;
        CREATE TABLE IF NOT EXISTS bank_selection_tokens(
          token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,payload TEXT NOT NULL,expires_at REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS bank_history_recent ON bank_account_history(id DESC);
    """
    statement = ""
    for line in schema.splitlines():
        statement += line+"\n"
        if sqlite3.complete_statement(statement):
            conn.execute(statement)
            statement = ""
    _legacy(conn)
    # No earlier per-invoice bank data existed. Freeze the deployment-time
    # legacy values, label their provenance, and never rewrite them later.
    legacy = {r["key"]: str(r["value"] or "") for r in conn.execute("SELECT key,value FROM settings WHERE key IN ('bank_name','bank_account','bank_holder','bank_note')")}
    bank = conn.execute("SELECT id FROM bank_accounts ORDER BY is_default DESC,id LIMIT 1").fetchone()
    for entity, table in (("order", "orders"), ("topup", "topups")):
        conn.execute(f"""INSERT OR IGNORE INTO bank_invoice_snapshots
          (entity,entity_id,bank_id,bank_name,account_number,holder_name,note,created_at,source)
          SELECT ?,id,?,?,?,?,?,?,? FROM {table} WHERE payment_method='BANK_TRANSFER'""",
          (entity, bank["id"] if bank else None, legacy.get("bank_name", ""), legacy.get("bank_account", ""),
           legacy.get("bank_holder", ""), legacy.get("bank_note", ""), stamp(), "legacy-at-migration"))


class Manager:
    def __init__(self, host):
        self.host = host

    @contextmanager
    def connection(self, write=False):
        conn = self.host.db()
        try:
            if write:
                self.host.begin_immediate_retry(conn)
            yield conn
            if write:
                conn.commit()
        finally:
            if conn.in_transaction:
                conn.rollback()
            conn.close()

    def owner(self, actor):
        if not self.host.is_owner(actor):
            raise BankError("Akses ditolak. Menu ini hanya untuk owner.")

    def active(self):
        with self.connection(True) as conn:
            _legacy(conn)
            return [dict(r) for r in conn.execute("SELECT * FROM bank_accounts WHERE active=1 AND deleted_at='' ORDER BY is_default DESC,id")]

    def account(self, ident=None, *, active=True, conn=None):
        if conn is None:
            with self.connection(True) as opened:
                return self.account(ident, active=active, conn=opened)
        _legacy(conn)
        query = "SELECT * FROM bank_accounts WHERE deleted_at=''"
        parameters = []
        if ident is not None:
            if isinstance(ident, bool) or not isinstance(ident, int) or ident < 1:
                raise BankError("Rekening tidak valid.")
            query += " AND id=?"
            parameters.append(ident)
        if active:
            query += " AND active=1"
        row = conn.execute(query+" ORDER BY is_default DESC,id LIMIT 1", parameters).fetchone()
        if not row:
            raise BankError("Rekening tidak aktif atau sudah dihapus. Pilih rekening lain.")
        return dict(row)

    def snapshot(self, entity, ident):
        if entity not in {"order", "topup"}:
            raise BankError("Invoice tidak valid.")
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM bank_invoice_snapshots WHERE entity=? AND entity_id=?", (entity, ident)).fetchone()
            return dict(row) if row else None

    def capture(self, conn, entity, ident, bank_id):
        if entity not in {"order", "topup"}:
            raise BankError("Invoice tidak valid.")
        table = "orders" if entity == "order" else "topups"
        if not conn.execute(f"SELECT 1 FROM {table} WHERE id=? AND payment_method='BANK_TRANSFER'", (ident,)).fetchone():
            raise BankError("Snapshot hanya untuk invoice transfer yang benar-benar tersimpan.")
        row = self.account(bank_id, conn=conn)
        conn.execute("""INSERT INTO bank_invoice_snapshots(entity,entity_id,bank_id,bank_name,account_number,holder_name,note,created_at,source)
            VALUES(?,?,?,?,?,?,?,?,?)""", (entity, ident, row["id"], *[row[k] for k in FIELDS], stamp(), "invoice-created"))
        return row

    def fingerprint(self, conn):
        return hashlib.sha256(dumped([dict(r) for r in conn.execute("SELECT * FROM bank_accounts ORDER BY id")]).encode()).hexdigest()

    def prepare(self, actor, action, ident=None, values=None):
        self.owner(actor)
        if action not in {"add", "edit", "toggle", "default", "delete"}:
            raise BankError("Tindakan tidak valid.")
        with self.connection(True) as conn:
            _legacy(conn)
            before = None if action == "add" else self.account(ident, active=False, conn=conn)
            after = dict(before or {})
            if action in {"add", "edit"}:
                after.update(validate(values))
            if action == "add":
                has_default = conn.execute("SELECT 1 FROM bank_accounts WHERE is_default=1").fetchone()
                after.update(active=1, is_default=int(not has_default), deleted_at="")
            elif action == "toggle":
                after["active"] = 1-int(before["active"])
                if not after["active"]:
                    after["is_default"] = 0
                else:
                    validate({key:after[key] for key in FIELDS})
                    if not conn.execute("SELECT 1 FROM bank_accounts WHERE is_default=1").fetchone():
                        after["is_default"] = 1
            elif action == "default":
                if not before["active"]:
                    raise BankError("Aktifkan rekening sebelum menjadikannya rekening utama.")
                after["is_default"] = 1
            elif action == "delete":
                after.update(active=0, is_default=0, deleted_at=stamp())
            token = secrets.token_urlsafe(12)
            conn.execute("INSERT INTO bank_change_drafts(token,owner_id,action,account_id,before_json,after_json,base_hash,expires_at) VALUES(?,?,?,?,?,?,?,?)",
                         (token, actor, action, ident, dumped(before), dumped(after), self.fingerprint(conn), time.time()+900))
        return {"token": token, "action": action, "before": before, "after": after}

    def confirm(self, actor, token):
        self.owner(actor)
        with self.connection(True) as conn:
            self.owner(actor)
            draft = conn.execute("SELECT * FROM bank_change_drafts WHERE token=? AND owner_id=?", (token, actor)).fetchone()
            if not draft:
                raise BankError("Konfirmasi bukan milik Anda atau tidak ditemukan.")
            if draft["state"] == "CONFIRMED":
                return draft["result_id"], False
            if draft["state"] != "PENDING" or draft["expires_at"] < time.time():
                raise BankError("Konfirmasi kedaluwarsa atau dibatalkan. Buka menu rekening kembali.")
            if draft["base_hash"] != self.fingerprint(conn):
                raise BankError("Data rekening berubah setelah preview. Buka ulang dan konfirmasi data terbaru.")
            before, after = json.loads(draft["before_json"]), json.loads(draft["after_json"])
            action, ident, now = draft["action"], draft["account_id"], stamp()
            related_before = [dict(r) for r in conn.execute("SELECT * FROM bank_accounts WHERE is_default=1")]
            if action == "default":
                conn.execute("UPDATE bank_accounts SET is_default=0,revision=revision+1,updated_at=? WHERE is_default=1 AND id!=?", (now, ident))
            if action == "add":
                values = validate({k: after[k] for k in FIELDS})
                ident = conn.execute("INSERT INTO bank_accounts(bank_name,account_number,holder_name,note,active,created_at,updated_at) VALUES(?,?,?,?,1,?,?)",
                                     (*[values[k] for k in FIELDS], now, now)).lastrowid
            else:
                conn.execute("UPDATE bank_accounts SET bank_name=?,account_number=?,holder_name=?,note=?,active=?,is_default=?,deleted_at=?,revision=revision+1,updated_at=? WHERE id=?",
                             (*[after[k] for k in FIELDS], after["active"], after["is_default"], after["deleted_at"], now, ident))
            default = conn.execute("SELECT * FROM bank_accounts WHERE active=1 AND deleted_at='' ORDER BY is_default DESC,id LIMIT 1").fetchone()
            if default and not default["is_default"]:
                conn.execute("UPDATE bank_accounts SET is_default=1,revision=revision+1,updated_at=? WHERE id=?", (now, default["id"]))
                default = conn.execute("SELECT * FROM bank_accounts WHERE id=?", (default["id"],)).fetchone()
            for key, field in (("bank_name", "bank_name"), ("bank_account", "account_number"), ("bank_holder", "holder_name"), ("bank_note", "note")):
                conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, default[field] if default else ""))
            saved = dict(conn.execute("SELECT * FROM bank_accounts WHERE id=?", (ident,)).fetchone())
            history_after = {**saved, "default_before": related_before,
                             "default_after": dict(default) if default else None}
            conn.execute("INSERT INTO bank_account_history(actor_id,action,account_id,before_json,after_json,created_at,draft_token) VALUES(?,?,?,?,?,?,?)",
                         (actor, action, ident, dumped(before), dumped(history_after), now, token))
            conn.execute("UPDATE bank_change_drafts SET state='CONFIRMED',result_id=? WHERE token=?", (ident, token))
            return ident, True

    def menu(self):
        return InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=label, callback_data=action) for label, action in row]
            for row in (
                (("➕ Tambah", PREFIX+"add"), ("📋 Daftar", PREFIX+"list:0")),
                (("✏️ Edit", PREFIX+"select:edit:0"), ("🟢 Aktif/Nonaktif", PREFIX+"select:toggle:0")),
                (("⭐ Utama", PREFIX+"select:default:0"), ("🗑 Hapus", PREFIX+"select:delete:0")),
                (("📜 Riwayat", PREFIX+"history:0"), ("⬅️ Kembali", "owner:qris_settings")),
            )])

    async def show(self, target, text="🏦 <b>MANAJEMEN REKENING</b>\n\nPilih tindakan. Perubahan perlu konfirmasi.", keyboard=None):
        keyboard = keyboard or self.menu()
        if hasattr(target, "message") and hasattr(target, "data"):
            return await self.host.safe_edit_or_answer(target, text, reply_markup=keyboard, parse_mode="HTML")
        return await target.answer(text, reply_markup=keyboard, parse_mode="HTML")

    async def listing(self, target, actor, action="edit", page=0):
        self.owner(actor)
        with self.connection(True) as conn:
            _legacy(conn)
            rows = [dict(r) for r in conn.execute("SELECT * FROM bank_accounts WHERE deleted_at='' ORDER BY is_default DESC,id")]
        page = min(max(0, page), max(0, (len(rows)-1)//8))
        buttons, lines = [], []
        for row in rows[page*8:(page+1)*8]:
            label = f"#{row['id']} {row['bank_name']}"[:40]+(" ⭐" if row["is_default"] else "")+(" 🟢" if row["active"] else " 🔴")
            buttons.append([InlineKeyboardButton(text=label, callback_data=PREFIX+f"pick:{action}:{row['id']}")])
            lines.append(f"#{row['id']} {fragment(row['bank_name'],150)} • {fragment(row['account_number'],100)} • {'AKTIF' if row['active'] else 'NONAKTIF'}"+(" • UTAMA" if row["is_default"] else ""))
        pages = []
        if page:
            pages.append(InlineKeyboardButton(text="⬅️", callback_data=PREFIX+f"select:{action}:{page-1}"))
        if (page+1)*8 < len(rows):
            pages.append(InlineKeyboardButton(text="➡️", callback_data=PREFIX+f"select:{action}:{page+1}"))
        if pages: buttons.append(pages)
        buttons.append([InlineKeyboardButton(text="🔙 Kembali", callback_data="owner:bank_settings")])
        await self.show(target, "🏦 <b>DAFTAR REKENING</b>\n"+f"Halaman {page+1}\n\n"+("\n".join(lines) or "Belum ada rekening. Pilih Tambah Rekening."), InlineKeyboardMarkup(inline_keyboard=buttons))

    async def start_edit(self, target, actor, state, ident=None, field=None):
        self.owner(actor)
        if field is not None and field not in FIELDS:
            raise BankError("Kolom rekening tidak valid.")
        values = {k: "" for k in FIELDS}
        if ident is not None:
            values = {k: self.account(ident, active=False)[k] for k in FIELDS}
        fields = [field] if field else list(FIELDS)
        await state.clear()
        await state.set_state(BankState.field)
        message = target.message if hasattr(target, "message") else target
        await state.set_data({"bank_id": ident, "bank_values": values, "bank_fields": fields,
                              "bank_index": 0, "bank_menu_id": message.message_id})
        await self.form(target, actor, state)

    def form_data(self, data):
        fields, index, values = data.get('bank_fields'), data.get('bank_index'), data.get('bank_values')
        if (not isinstance(fields, list) or not fields or any(field not in FIELDS for field in fields)
                or type(index) is not int or not 0 <= index < len(fields)
                or not isinstance(values, dict) or set(values) != set(FIELDS)
                or any(not isinstance(value, str) for value in values.values())):
            raise BankError("Sesi rekening tidak tersedia. Buka Rekening Transfer kembali.")
        return fields, index, values

    async def form(self, target, actor, state, warning=None):
        self.owner(actor)
        data = await state.get_data()
        fields, index, values = self.form_data(data)
        field = fields[index]
        title = "✏️ EDIT REKENING" if data.get('bank_id') else "➕ TAMBAH REKENING"
        text = f"<b>{title}</b>\nLangkah {index+1}/{len(fields)}\n\nKirim {html.escape(LABELS[field])}."
        if values[field]:
            text += "\nSaat ini: <code>"+fragment(values[field], 300)+"</code>"
        if warning:
            text += "\n\n⚠️ "+html.escape(warning)
        keyboard = InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="⬅️ Kembali", callback_data=PREFIX+"form_back"),
            InlineKeyboardButton(text="❌ Batal", callback_data=PREFIX+"form_cancel"),
        ]])
        # Only the input form uses the strict existing menu renderer. Remember
        # a replacement message if Telegram reports the previous one deleted.
        render = MenuMessage(target.message) if hasattr(target, 'message') and hasattr(target, 'data') else target
        sent = await self.show(render, text, keyboard)
        menu_id = getattr(render, 'target_id', None) or getattr(sent, 'message_id', None)
        if type(menu_id) is int and menu_id > 0:
            await state.update_data(bank_menu_id=menu_id)

    async def edit_menu(self, target, actor, ident):
        self.owner(actor)
        row = self.account(ident, active=False)
        fields = [InlineKeyboardButton(text=LABELS[field].split(' (')[0],callback_data=PREFIX+f"field:{ident}:{field}") for field in FIELDS]
        buttons = [fields[:2],fields[2:],[
            InlineKeyboardButton(text="✏️ Edit Semua",callback_data=PREFIX+f"editall:{ident}"),
            InlineKeyboardButton(text="⬅️ Daftar",callback_data=PREFIX+"list:0")]]
        await self.show(target,"✏️ <b>EDIT REKENING</b>\n\n"+account_text(row)+"\n\nPilih data yang ingin diubah.",InlineKeyboardMarkup(inline_keyboard=buttons))

    async def preview(self, target, actor, action, ident=None, values=None):
        draft = self.prepare(actor, action, ident, values)
        before, after = draft["before"], draft["after"]
        text = f"🏦 <b>KONFIRMASI {action.upper()}</b>\n\n<b>DATA LAMA</b>\n"+account_text(before)
        if before:
            text += f"\nStatus lama: {'AKTIF' if before['active'] else 'NONAKTIF'} • Utama: {'YA' if before['is_default'] else 'TIDAK'}"
        text += "\n\n<b>DATA BARU</b>\n"+account_text(after)
        text += f"\nStatus: {'AKTIF' if after['active'] else 'NONAKTIF'} • Utama: {'YA' if after['is_default'] else 'TIDAK'}"
        if action == "delete": text += "\nDihapus dari daftar baru; invoice dan riwayat tetap tersimpan."
        if before and before["is_default"] and not after["is_default"]:
            with self.connection() as conn:
                other = conn.execute("SELECT * FROM bank_accounts WHERE active=1 AND deleted_at='' AND id!=? ORDER BY id LIMIT 1", (ident,)).fetchone()
            text += "\nRekening utama berikutnya: "+(fragment(other["bank_name"],120)+f" #{other['id']}" if other else "Tidak ada; transfer baru ditutup.")
        elif action == "default":
            current = next((r for r in self.active() if r["is_default"]), None)
            text += "\nMenggantikan rekening utama: "+(fragment(current["bank_name"],120)+" • "+fragment(current["account_number"],100) if current else "Belum ada")
        keyboard = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ SIMPAN PERUBAHAN", callback_data=PREFIX+"confirm:"+draft["token"])],
            [InlineKeyboardButton(text="❌ BATAL", callback_data=PREFIX+"cancel:"+draft["token"])]] )
        await self.show(target, text, keyboard)

    async def choices(self, call, payload, state=None, page=0):
        rows = self.active()
        if not rows: raise BankError("Tidak ada rekening aktif. Pilih metode pembayaran lain.")
        page = min(max(0, page), (len(rows)-1)//8)
        buttons = []
        if state and payload["flow"] == "order":
            data = await state.get_data()
            payload = {**payload, "context": dumped({k:v for k,v in data.items() if k.startswith('checkout_') or k in {'family_gmail','voucher_code'}})}
        with self.connection(True) as conn:
            conn.execute("DELETE FROM bank_selection_tokens WHERE expires_at<?", (time.time(),))
            for row in rows[page*8:(page+1)*8]:
                token = secrets.token_urlsafe(10)
                conn.execute("INSERT INTO bank_selection_tokens VALUES(?,?,?,?)", (token,call.from_user.id,dumped({**payload,"bank_id":row['id']}),time.time()+600))
                buttons.append([InlineKeyboardButton(text=("⭐ " if row['is_default'] else "")+f"{row['bank_name']} • {row['account_number']}"[:55], callback_data=PREFIX+"user:"+token)])
            pages=[]
            for label,new_page in (("⬅️",page-1),("➡️",page+1)):
                if 0<=new_page*8<len(rows):
                    token=secrets.token_urlsafe(10)
                    conn.execute("INSERT INTO bank_selection_tokens VALUES(?,?,?,?)", (token,call.from_user.id,dumped({**payload,"page":new_page}),time.time()+600))
                    pages.append(InlineKeyboardButton(text=label,callback_data=PREFIX+"user:"+token))
            if pages:buttons.append(pages)
        back = f"topup:pay:{payload['amount']}" if payload['flow']=='topup' else "home"
        buttons.append([InlineKeyboardButton(text="⬅️ Kembali",callback_data=back)])
        await self.show(call,"🏦 <b>PILIH REKENING TRANSFER</b>\n\nPilih tujuan transfer. Rekening akan dikunci pada invoice.\n"+f"Halaman {page+1}",InlineKeyboardMarkup(inline_keyboard=buttons))


def register(router, manager):
    async def private(call):
        if not call.message or str(call.message.chat.type) != "private" or call.message.chat.id != call.from_user.id:
            raise BankError("Gunakan menu ini di chat privat bot.")

    @router.callback_query(F.data.startswith(PREFIX))
    async def callback(call, state):
        answered = False
        try:
            await private(call)
            parts = call.data[len(PREFIX):].split(":")
            if parts[0] == "user" and len(parts)==2:
                if manager.host.security_blocked(call.from_user.id): raise BankError("Akun dibatasi owner.")
                if not await manager.host.is_channel_member(call.bot,call.from_user.id): raise BankError("Buka /start dan verifikasi channel dahulu.")
                with manager.connection() as conn:
                    token = conn.execute("SELECT * FROM bank_selection_tokens WHERE token=? AND user_id=?",(parts[1],call.from_user.id)).fetchone()
                if not token or token['expires_at']<time.time():raise BankError("Pilihan rekening kedaluwarsa atau bukan milik Anda.")
                payload=json.loads(token['payload'])
                if payload.get('flow')=='order':
                    current=await state.get_data()
                    context=dumped({k:v for k,v in current.items() if k.startswith('checkout_') or k in {'family_gmail','voucher_code'}})
                    if payload.get('context')!=context:raise BankError("Checkout berubah. Pilih rekening kembali dari checkout terbaru.")
                if 'page' in payload:
                    await call.answer();answered=True
                    return await manager.choices(call,{k:v for k,v in payload.items() if k!='page'},state,payload['page'])
                if payload['flow']=='topup':
                    proxy=call.model_copy(update={'data':f"topupmethod:bank:{payload['amount']}"})
                    return await manager.host.wallet_topup_method_bank(proxy,bank_account_id=payload['bank_id'])
                if payload['flow']=='order':
                    current=await state.get_data()
                    context=dumped({k:v for k,v in current.items() if k.startswith('checkout_') or k in {'family_gmail','voucher_code'}})
                    if payload.get('context')!=context:raise BankError("Checkout berubah. Pilih rekening kembali dari checkout terbaru.")
                    proxy=call.model_copy(update={'data':f"processbank:{payload['variant_id']}:{payload['qty']}"})
                    return await manager.host.process_bank_order(proxy,call.bot,state,bank_account_id=payload['bank_id'])
                raise BankError("Pilihan pembayaran tidak valid.")
            manager.owner(call.from_user.id)
            await call.answer();answered=True
            action=parts[0]
            if action=='add':return await manager.start_edit(call,call.from_user.id,state)
            if action in {'form_back', 'form_cancel'} and len(parts)==1:
                if await state.get_state() != BankState.field.state:
                    raise BankError("Form rekening sudah tidak aktif. Buka Rekening Transfer kembali.")
                data = await state.get_data()
                fields, index, values = manager.form_data(data)
                if action=='form_cancel' or index==0:
                    await state.clear()
                    if action=='form_back' and data.get('bank_id'):
                        return await manager.edit_menu(call,call.from_user.id,data['bank_id'])
                    return await manager.show(call)
                await state.update_data(bank_index=index-1)
                return await manager.form(call,call.from_user.id,state)
            if (action=='list' and len(parts)==2) or (action=='select' and len(parts)==3):
                kind,page=('detail',int(parts[1])) if action=='list' else (parts[1],int(parts[2]))
                return await manager.listing(call,call.from_user.id,kind,page)
            if action=='pick' and len(parts)==3:
                kind,ident=parts[1],int(parts[2])
                if kind=='edit':return await manager.edit_menu(call,call.from_user.id,ident)
                if kind=='detail':
                    row=manager.account(ident,active=False)
                    actions=[InlineKeyboardButton(text=label,callback_data=PREFIX+f"pick:{kind}:{ident}") for label,kind in (("✏️ Edit","edit"),("🟢 Aktif/Nonaktif","toggle"),("⭐ Utama","default"),("🗑 Hapus","delete"))]
                    buttons=[actions[:2],actions[2:]]
                    buttons.append([InlineKeyboardButton(text="🔙 Daftar",callback_data=PREFIX+"list:0")])
                    return await manager.show(call,account_text(row)+f"\nStatus: {'AKTIF' if row['active'] else 'NONAKTIF'} • Utama: {'YA' if row['is_default'] else 'TIDAK'}",InlineKeyboardMarkup(inline_keyboard=buttons))
                return await manager.preview(call,call.from_user.id,kind,ident)
            if action=='field' and len(parts)==3:
                return await manager.start_edit(call,call.from_user.id,state,int(parts[1]),parts[2])
            if action=='editall' and len(parts)==2:
                return await manager.start_edit(call,call.from_user.id,state,int(parts[1]))
            if action=='confirm' and len(parts)==2:
                ident,created=manager.confirm(call.from_user.id,parts[1])
                await state.clear()
                return await manager.show(call,f"✅ Rekening #{ident}: "+("perubahan tersimpan." if created else "konfirmasi ini sudah diproses."))
            if action=='cancel' and len(parts)==2:
                with manager.connection(True) as conn:
                    changed=conn.execute("UPDATE bank_change_drafts SET state='CANCELED' WHERE token=? AND owner_id=? AND state='PENDING'",(parts[1],call.from_user.id)).rowcount
                await state.clear();return await manager.show(call,"Perubahan dibatalkan." if changed else "Konfirmasi ini sudah diproses atau tidak ditemukan.")
            if action=='history' and len(parts)==2:
                page=min(100000,max(0,int(parts[1])))
                with manager.connection() as conn:
                    rows=conn.execute("SELECT * FROM bank_account_history ORDER BY id DESC LIMIT 9 OFFSET ?",(page*8,)).fetchall()
                buttons=[[InlineKeyboardButton(text=f"#{r['id']} • {r['action']} • Rekening #{r['account_id']}",callback_data=PREFIX+f"audit:{r['id']}")] for r in rows[:8]]
                if page:buttons.append([InlineKeyboardButton(text="⬅️",callback_data=PREFIX+f"history:{page-1}")])
                if len(rows)>8:buttons.append([InlineKeyboardButton(text="➡️",callback_data=PREFIX+f"history:{page+1}")])
                buttons.append([InlineKeyboardButton(text="🔙 Kembali",callback_data="owner:bank_settings")])
                return await manager.show(call,"📜 <b>RIWAYAT REKENING</b>\n\n"+("Pilih perubahan untuk data lama dan baru." if rows else "Belum ada perubahan."),InlineKeyboardMarkup(inline_keyboard=buttons))
            if action=='audit' and len(parts)==2:
                with manager.connection() as conn:row=conn.execute("SELECT * FROM bank_account_history WHERE id=?",(int(parts[1]),)).fetchone()
                if not row:raise BankError("Riwayat tidak ditemukan.")
                before,after=json.loads(row['before_json']),json.loads(row['after_json'])
                def status(data):
                    return "\nStatus: "+('AKTIF' if data.get('active') else 'NONAKTIF')+" • Utama: "+('YA' if data.get('is_default') else 'TIDAK')+(" • DIHAPUS" if data.get('deleted_at') else "") if data else ""
                text=f"📜 <b>PERUBAHAN #{row['id']}</b>\n{html.escape(row['action'])} • Owner {row['actor_id']}\n{html.escape(manager.host.format_wib_datetime(row['created_at']))}\n\n<b>LAMA</b>\n"+account_text(before)+status(before)+"\n\n<b>BARU</b>\n"+account_text(after)+status(after)
                return await manager.show(call,text,InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text="🔙 Riwayat",callback_data=PREFIX+"history:0")]]))
            raise BankError("Menu rekening tidak valid.")
        except (BankError,ValueError,TypeError,KeyError,IndexError,OverflowError,sqlite3.Error) as exc:
            message = str(exc) if isinstance(exc,BankError) else "Data rekening tidak valid, berubah, atau sudah ada. Buka menu kembali."
            if not answered:return await call.answer(message[:190],show_alert=True)
            await manager.show(call,"⚠️ "+html.escape(message))

    @router.message(BankState.field, F.text & ~F.text.startswith('/') & ~F.text.in_(TEXT_MENU_ACTIONS))
    async def field_input(message,state):
        try:
            manager.owner(message.from_user.id)
            if str(message.chat.type)!='private' or message.chat.id!=message.from_user.id:raise BankError("Gunakan chat privat.")
            data=await state.get_data();fields,index,previous=manager.form_data(data)
            field=fields[index];value=message.text.strip()
            if field=='note' and value=='-':value=''
            values={**previous,field:value}
            # Validate the current field before advancing; the complete form
            # is validated again before creating a persistent confirmation.
            placeholder={"bank_name":"QA", "account_number":"1234", "holder_name":"QA", "note":""}
            validate({**placeholder,field:value})
            menu=MenuMessage(message,message_id=data.get('bank_menu_id'))
            if index+1<len(fields):
                await state.update_data(bank_values=values,bank_index=index+1)
                return await manager.form(menu,message.from_user.id,state)
            await manager.preview(menu,message.from_user.id,'edit' if data.get('bank_id') else 'add',data.get('bank_id'),values)
            await state.clear()
        except BankError as exc:
            if manager.host.is_owner(message.from_user.id) and str(message.chat.type)=='private' and message.chat.id==message.from_user.id:
                try:
                    data=await state.get_data()
                    manager.form_data(data)
                except BankError:
                    await state.clear()
                else:
                    return await manager.form(MenuMessage(message,message_id=data.get('bank_menu_id')),
                                              message.from_user.id,state,str(exc))
            await message.answer("⚠️ "+html.escape(str(exc)),parse_mode="HTML")
        except (ValueError,TypeError,KeyError,IndexError,sqlite3.Error):
            await state.clear()
            await message.answer("⚠️ Sesi rekening belum dapat diproses. Buka Rekening Transfer kembali.")
    return manager
