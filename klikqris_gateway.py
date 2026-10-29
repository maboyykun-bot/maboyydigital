"""KlikQRIS adapter: documented QRIS APIs, existing wallet and host checkout.

No session/cookies, no replay of create after an uncertain response. Webhooks
match the transaction signature, then authenticate a fresh status API read.
Only that API evidence can authorize host credit/fulfillment. Sandbox cannot
credit the real wallet or deliver stock. All customer text is white-label.
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
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from email.utils import parsedate_to_datetime
from io import BytesIO
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import aiohttp
from aiohttp import web
from Crypto.Cipher import AES
from PIL import Image
from aiogram import F
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import BufferedInputFile, InlineKeyboardButton, InlineKeyboardMarkup, InputMediaPhoto
from types import SimpleNamespace
from otp_smscode import TEXT_MENU_ACTIONS

LABEL = '⚡ QRIS Otomatis'
METHOD = 'KLIKQRIS_AUTO'
PREFIX = 'aqris:'
MAX_AMOUNT = 10**12
WIB = ZoneInfo('Asia/Jakarta')
QR_LIMIT = 2*1024*1024
BODY_LIMIT = 4*1024*1024
SUCCESS_RECEIPT_TTL = 3600
FINAL = {'SETTLED','SETTLED_BALANCE','FAILED','SANDBOX_PAID'}


def managed(row):
    try:return row['payment_method']==METHOD
    except (KeyError,IndexError,TypeError):return False


def money(value, *, positive=False):
    if isinstance(value, bool) or not isinstance(value, (str,int,Decimal)):
        raise GatewayError('SCHEMA')
    try:
        number = Decimal(str(value))
        if not number.is_finite() or number != number.to_integral_value() or not (1 if positive else 0) <= number <= MAX_AMOUNT:
            raise ValueError
        return int(number)
    except (ValueError, InvalidOperation):
        raise GatewayError('SCHEMA') from None


def reference(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,96}',value):
        raise GatewayError('SCHEMA')
    return value


def expiry(value):
    if not isinstance(value,str) or len(value)>64:
        raise GatewayError('SCHEMA')
    try:
        stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
        return (stamp.replace(tzinfo=WIB) if stamp.tzinfo is None else stamp).timestamp()
    except (ValueError,OverflowError):
        raise GatewayError('SCHEMA') from None


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)


def environment_value(name,default=''):
    """Accept a single pasted NAME=value without treating it as a credential/URL."""
    raw=os.getenv(name,default).strip()
    value=raw
    for _ in range(2):
        if len(value)>=2 and value[0]==value[-1] and value[0] in {'"',"'"}:
            value=value[1:-1].strip()
        if value.startswith(name+'='):
            value=value[len(name)+1:].strip()
    return value,value!=raw


class GatewayError(Exception):
    def __init__(self, code, *, uncertain=False, retry_after=0,http_status=0,endpoint='',transaction_missing=False,credential='current'):
        super().__init__(code)
        self.code,self.uncertain,self.retry_after=code,uncertain,retry_after
        self.http_status,self.endpoint=http_status,endpoint
        self.transaction_missing=transaction_missing
        self.credential=credential
        self.history_http_status=0
        self.correlation_id=secrets.token_hex(8)
        self.public='QRIS Otomatis belum dapat diproses. Cek status atau hubungi owner.'


def buyer_error(exc):
    if getattr(exc,'code','')=='STOCK':return 'Stok tidak mencukupi.'
    if getattr(exc,'code','')=='AUTH':return 'API pembayaran menolak kredensial aktif. Hubungi owner; tagihan pengganti belum dibuat.'
    if getattr(exc,'code','')=='ACCOUNT_CHANGED':return 'Invoice lama perlu diperiksa owner setelah pengaturan pembayaran berubah. Tagihan baru belum dibuat agar tidak ganda.'
    if getattr(exc,'code','') in {'NOT_FOUND','ENDPOINT_NOT_FOUND'}:return 'Invoice lama masih diperiksa. Tagihan baru belum dibuat; gunakan Cek Status atau hubungi owner.'
    if getattr(exc,'code','')=='BUSY':return 'Invoice sedang diproses. Tunggu lalu Cek Status; jangan membuat tagihan pengganti.'
    return 'QRIS Otomatis belum dapat diproses. Cek status atau hubungi owner.'


@dataclass
class Config:
    key: str = ''
    merchant: str = ''
    enabled: bool = False
    mode: str = 'gateway'
    sandbox: bool = False
    webhook_url: str = ''
    timeout: int = 15
    poll_seconds: int = 15
    error: str = ''
    issues: tuple = ()
    normalized: tuple = ()
    previous_key: str = ''

    def problems(self):
        problems=[]
        for value,name in [(self.key,'KLIKQRIS_API_KEY'),(self.merchant,'KLIKQRIS_MERCHANT_ID')]:
            if not value:problems.append(name+' belum diisi.')
        problems.extend(self.issues)
        if self.error and not self.issues:problems.append('Konfigurasi KlikQRIS tidak valid; periksa environment hosting.')
        return problems

    @classmethod
    def environment(cls,host):
        c=cls()
        issues=[];normalized=[]
        def read(name,default=''):
            value,changed=environment_value(name,default)
            if changed:normalized.append(name)
            return value
        c.key=read('KLIKQRIS_API_KEY')
        c.previous_key=read('KLIKQRIS_PREVIOUS_API_KEY')
        c.merchant=read('KLIKQRIS_MERCHANT_ID')
        for value,name in [(c.key,'KLIKQRIS_API_KEY'),(c.previous_key,'KLIKQRIS_PREVIOUS_API_KEY')]:
            if value and (len(value)>4096 or any(x in value for x in '\r\n')):
                issues.append(name+' harus satu nilai tanpa baris baru.')
        try:
            if c.merchant:reference(c.merchant)
        except GatewayError:issues.append('KLIKQRIS_MERCHANT_ID tidak valid; isi Merchant ID saja.')
        for field,name in [('enabled','KLIKQRIS_ENABLED'),('sandbox','KLIKQRIS_SANDBOX')]:
            raw=read(name,'false').lower()
            if raw not in {'true','false','1','0'}:issues.append(name+' harus true atau false.')
            else:setattr(c,field,raw in {'true','1'})
        c.mode=read('KLIKQRIS_MODE','gateway').lower()
        if c.mode not in {'gateway','my_pg'}:issues.append('KLIKQRIS_MODE harus gateway atau my_pg.')
        c.webhook_url=read('KLIKQRIS_WEBHOOK_URL') or (str(getattr(host,'PUBLIC_BASE_URL','') or '').rstrip('/')+'/webhooks/klikqris' if getattr(host,'PUBLIC_BASE_URL','') else '')
        if c.webhook_url:
            try:
                url=urlparse(c.webhook_url)
                if url.scheme!='https' or not url.hostname or url.username or url.password or url.fragment or url.query or url.port not in {None,443} or any(x.isspace() for x in c.webhook_url):raise ValueError
            except ValueError:issues.append('KLIKQRIS_WEBHOOK_URL harus URL HTTPS saja, tanpa nama variabel atau tanda sama dengan.')
        for field,name,low,high in [('timeout','KLIKQRIS_HTTP_TIMEOUT_SECONDS',3,60),('poll_seconds','KLIKQRIS_POLL_INTERVAL_SECONDS',10,300)]:
            value=read(name,str(getattr(c,field)))
            if not re.fullmatch(r'[0-9]{1,3}',value) or not low<=int(value)<=high:
                issues.append(name+f' harus angka {low}–{high}.')
            else:setattr(c,field,int(value))
        c.issues=tuple(issues);c.normalized=tuple(normalized)
        if issues:c.error='CONFIG'
        return c


def init_schema(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS klikqris_settings(
        key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at REAL NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS klikqris_transactions(
        id TEXT PRIMARY KEY,purpose TEXT NOT NULL CHECK(purpose IN ('order','topup')),
        entity_id INTEGER NOT NULL,user_id INTEGER NOT NULL,reference TEXT NOT NULL UNIQUE,
        mode TEXT NOT NULL,sandbox INTEGER NOT NULL,fingerprint TEXT NOT NULL,
        amount INTEGER NOT NULL CHECK(amount>0),total_amount INTEGER,
        signature BLOB,qr_image BLOB,state TEXT NOT NULL,provider_status TEXT NOT NULL DEFAULT '',
        expires_at REAL,created_at REAL NOT NULL,checked_at REAL NOT NULL DEFAULT 0,
        next_poll_at REAL NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',
        api_verified_at REAL NOT NULL DEFAULT 0,verified_total INTEGER,
        lease_owner TEXT,lease_until REAL NOT NULL DEFAULT 0,
        delivery_owner TEXT,delivery_until REAL NOT NULL DEFAULT 0,
        review_ledger_id INTEGER,UNIQUE(purpose,entity_id))''')
    conn.execute('''CREATE TABLE IF NOT EXISTS klikqris_notifications(
        id TEXT PRIMARY KEY,transaction_id TEXT NOT NULL,event TEXT NOT NULL,status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,next_retry_at REAL NOT NULL DEFAULT 0,
        lease_owner TEXT,lease_until REAL NOT NULL DEFAULT 0,sent_at REAL,
        FOREIGN KEY(transaction_id) REFERENCES klikqris_transactions(id))''')
    conn.execute('''CREATE TABLE IF NOT EXISTS klikqris_audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT,actor INTEGER NOT NULL,action TEXT NOT NULL,
        transaction_id TEXT NOT NULL DEFAULT '',detail TEXT NOT NULL,created_at REAL NOT NULL)''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_klikqris_due ON klikqris_transactions(state,next_poll_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_klikqris_buyer ON klikqris_transactions(user_id,created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_klikqris_notice ON klikqris_notifications(status,next_retry_at)')
    conn.execute('''CREATE TABLE IF NOT EXISTS klikqris_payment_messages(
        transaction_id TEXT NOT NULL,chat_id INTEGER NOT NULL,message_id INTEGER NOT NULL,
        kind TEXT NOT NULL DEFAULT 'QR',attempts INTEGER NOT NULL DEFAULT 0,
        next_retry_at REAL NOT NULL DEFAULT 0,created_at REAL NOT NULL,
        PRIMARY KEY(transaction_id,message_id),
        FOREIGN KEY(transaction_id) REFERENCES klikqris_transactions(id))''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_klikqris_message_cleanup ON klikqris_payment_messages(kind,next_retry_at)')
    # Earlier topups already saved QR message IDs; preserve them on upgrade.
    for transaction_id,user_id,saved_messages in conn.execute('''SELECT t.id,t.user_id,n.payment_message_ids FROM klikqris_transactions t
        JOIN topups n ON t.purpose='topup' AND n.id=t.entity_id AND n.user_id=t.user_id
        WHERE n.payment_method=?''',(METHOD,)).fetchall():
        try:ids=json.loads(saved_messages or '[]')
        except (TypeError,ValueError):continue
        if not isinstance(ids,list):continue
        for ident in ids:
            if isinstance(ident,int) and not isinstance(ident,bool) and 0<ident<=9223372036854775807:
                conn.execute('''INSERT OR IGNORE INTO klikqris_payment_messages
                    (transaction_id,chat_id,message_id,created_at) VALUES(?,?,?,?)''',
                    (transaction_id,user_id,ident,time.time()))


class Client:
    def __init__(self,config):
        self.config=config
        self.session=None
        self.cooldown_until=0

    def path(self,mode,action,ref=''):
        if mode not in {'gateway','my_pg'}:raise GatewayError('CONFIG')
        if self.config.sandbox:
            if mode!='gateway':raise GatewayError('CONFIG')
            prefix='/sandbox/qris'
        else:prefix='/qrisv2' if mode=='my_pg' else '/qris'
        if action=='status':
            return prefix+'/status/'+(reference(self.config.merchant)+'/' if mode=='my_pg' else '')+reference(ref)
        if action=='history' and mode!='gateway':raise GatewayError('CONFIG')
        return prefix+'/'+action

    @staticmethod
    def endpoint_label(path):
        if '/status/' in path:
            return 'GET '+path.split('/status/',1)[0]+'/status/'+('{id_merchant}/' if path.startswith('/qrisv2/') else '')+'{order_id}'
        return ('POST ' if path.endswith('/create') else 'GET ')+path

    async def request(self,verb,path,body=None,*,credential='current'):
        if self.config.error or not self.config.key or not self.config.merchant:raise GatewayError('CONFIG')
        # Revoked API keys remain useful for local decryption, never for HTTP.
        if credential!='current':raise GatewayError('CONFIG')
        if self.cooldown_until>time.time():raise GatewayError('RATE_LIMIT',retry_after=int(self.cooldown_until-time.time())+1)
        if not re.fullmatch(r'/(?:sandbox/)?qris(?:v2)?/(?:create|history|status/[A-Za-z0-9_/-]+)',path):raise GatewayError('CONFIG')
        write=verb=='POST'
        endpoint=self.endpoint_label(path)
        try:
            if self.session is None or self.session.closed:
                self.session=aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.config.timeout),trust_env=True)
            headers={'x-api-key':self.config.key,'id_merchant':self.config.merchant,'Accept':'application/json'}
            options={'headers':headers,'allow_redirects':False}
            if body is not None:options['json']=body
            async with self.session.request(verb,'https://klikqris.com/api'+path,**options) as response:
                def problem(code,**details):
                    return GatewayError(code,uncertain=write,http_status=response.status,endpoint=endpoint,credential=credential,**details)
                if response.status==429:
                    raw=response.headers.get('Retry-After','60')
                    try:delay=int(raw)
                    except (ValueError,TypeError):
                        try:delay=int(parsedate_to_datetime(raw).timestamp()-time.time())
                        except (ValueError,TypeError,OverflowError):delay=60
                    delay=min(86400,max(1,delay));self.cooldown_until=time.time()+delay
                    raise problem('RATE_LIMIT',retry_after=delay)
                if response.status>=500:raise problem('UPSTREAM')
                if response.status in {401,403}:raise problem('AUTH')
                if response.status==404 and path.endswith('/history'):raise problem('HISTORY_UNAVAILABLE')
                if response.status not in {200,404}:raise problem('HTTP')
                raw=bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    raw.extend(chunk)
                    if len(raw)>(BODY_LIMIT if response.status==200 else 8192):raise problem('SCHEMA')
                try:data=json.loads(raw.decode('utf-8'),parse_float=Decimal)
                except (ValueError,UnicodeError):raise problem('JSON_INVALID' if response.status==200 else 'ENDPOINT_NOT_FOUND') from None
                missing=False
                if '/status/' in path and isinstance(data,dict) and data.get('status') is not True:
                    nested=data.get('data') if isinstance(data.get('data'),dict) else {}
                    message=data.get('message',nested.get('msg',nested.get('message',data.get('error',''))))
                    missing=isinstance(message,str) and message.strip().casefold().rstrip('.!') in {
                        'transaction not found','order not found','transaksi tidak ditemukan',
                        'transaksi belum ditemukan','data transaksi tidak ditemukan','pesanan tidak ditemukan'}
                if response.status==404 or missing:
                    raise problem('NOT_FOUND' if '/status/' in path and missing else 'ENDPOINT_NOT_FOUND',transaction_missing=missing)
                if not isinstance(data,dict) or not isinstance(data.get('status'),bool):raise problem('SCHEMA')
                if data['status'] is not True:raise problem('REJECTED')
                if not isinstance(data.get('data'),dict):raise problem('SCHEMA')
                return data['data']
        except aiohttp.ClientSSLError:
            raise GatewayError('TLS',uncertain=write,endpoint=endpoint,credential=credential) from None
        except aiohttp.ClientConnectorDNSError:
            raise GatewayError('DNS',uncertain=write,endpoint=endpoint,credential=credential) from None
        except asyncio.TimeoutError:
            raise GatewayError('TIMEOUT',uncertain=write,endpoint=endpoint,credential=credential) from None
        except aiohttp.ClientError:
            raise GatewayError('NETWORK',uncertain=write,endpoint=endpoint,credential=credential) from None

    async def create(self,ref,amount,mode):
        body={'order_id':reference(ref),'id_merchant':self.config.merchant,'amount':money(amount,positive=True),'keterangan':'Pembayaran Maboyy Digital'}
        if mode=='gateway' and self.config.webhook_url:body['callback_url']=self.config.webhook_url
        return await self.request('POST',self.path(mode,'create'),body)

    async def status(self,ref,mode):
        return await self.request('GET',self.path(mode,'status',ref))

    async def history(self):
        result=await self.request('GET',self.path('gateway','history'))
        if not isinstance(result.get('data'),list):raise GatewayError('SCHEMA')
        return result

    async def connection_evidence(self):
        """Read-only evidence: history 404 is a failed probe, never an empty history."""
        await self.history()
        return {'verified':True,'source':'history','http_status':200,'endpoint':self.endpoint_label(self.path('gateway','history'))}

    @staticmethod
    def image_valid(raw):
        if not isinstance(raw,bytes) or not 1<=len(raw)<=QR_LIMIT:raise GatewayError('IMAGE')
        try:
            with Image.open(BytesIO(raw)) as picture:
                if picture.format not in {'PNG','JPEG','WEBP'} or max(picture.size)>4096:raise ValueError
                picture.verify()
        except Exception:
            raise GatewayError('IMAGE') from None
        return raw  # Preserve the official QR and legally required data byte-for-byte.

    async def image(self,data):
        inline=data.get('qris_image')
        if isinstance(inline,str) and inline.startswith(('data:image/png;base64,','data:image/jpeg;base64,','data:image/webp;base64,')):
            try:return self.image_valid(base64.b64decode(inline.split(',',1)[1],validate=True))
            except (ValueError,TypeError):raise GatewayError('IMAGE') from None
        url=data.get('qris_url')
        if not isinstance(url,str):raise GatewayError('IMAGE')
        parsed=urlparse(url)
        if parsed.scheme!='https' or parsed.hostname!='klikqris.com' or parsed.port not in {None,443} or not parsed.path.startswith('/storage/') or parsed.username or parsed.password or parsed.fragment:
            raise GatewayError('IMAGE')
        if self.session is None or self.session.closed:
            self.session=aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.config.timeout),trust_env=True)
        try:
            async with self.session.request('GET',url,allow_redirects=False) as response:
                if response.status!=200:raise GatewayError('IMAGE')
                raw=bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    raw.extend(chunk)
                    if len(raw)>QR_LIMIT:raise GatewayError('IMAGE')
                return self.image_valid(bytes(raw))
        except (aiohttp.ClientError,asyncio.TimeoutError):raise GatewayError('IMAGE') from None

    async def close(self):
        if self.session is not None and not self.session.closed:await self.session.close()


class AutoQRISAdminState(StatesGroup):
    merchant_reference=State()


class Gateway:
    def __init__(self,host,config=None):
        self.host=host
        self.config=config or Config.environment(host)
        self.api=Client(self.config)
        self.bot=None
        self.task=None
        self.cleanup_task=None
        self.delivery_locks={}

    @contextmanager
    def connection(self,write=False):
        conn=self.host.db()
        try:
            if write:self.host.begin_immediate_retry(conn)
            yield conn
            if write:conn.commit()
        except BaseException:
            if write:conn.rollback()
            raise
        finally:conn.close()

    def one(self,sql,args=()):
        with self.connection() as conn:
            row=conn.execute(sql,args).fetchone()
            return dict(row) if row else None

    def require_owner(self,user):
        if not self.host.is_owner(user):raise GatewayError('FORBIDDEN')

    def fingerprint(self,key=None):
        return hashlib.sha256(encoded({'merchant':self.config.merchant,'key':self.config.key if key is None else key,'sandbox':self.config.sandbox}).encode()).hexdigest()

    def crypt(self,value,*,decrypt=False):
        def key_for(api_key):
            return hmac.new(str(self.host.BOT_TOKEN).encode(),('maboyy-klikqris-v1|'+api_key+'|'+self.config.merchant).encode(),hashlib.sha256).digest()
        if decrypt:
            if not isinstance(value,bytes) or len(value)<28:raise GatewayError('STORAGE')
            # Try the current and original encryption keys without changing config.
            keys=[self.config.key]
            if self.config.previous_key and self.config.previous_key not in keys:keys.append(self.config.previous_key)
            for api_key in keys:
                try:return AES.new(key_for(api_key),AES.MODE_GCM,nonce=value[:12]).decrypt_and_verify(value[28:],value[12:28])
                except ValueError:continue
            raise GatewayError('STORAGE') from None
        cipher=AES.new(key_for(self.config.key),AES.MODE_GCM,nonce=secrets.token_bytes(12))
        data,tag=cipher.encrypt_and_digest(value)
        return cipher.nonce+tag+data

    def can_recover_account(self,row):
        return (not self.config.sandbox and not row['sandbox'] and bool(self.config.previous_key)
                and row['fingerprint']==self.fingerprint(self.config.previous_key))

    def history_archived(self,ident,conn=None):
        if conn is not None:
            return conn.execute('SELECT 1 FROM klikqris_settings WHERE key=?',('archived_'+ident,)).fetchone() is not None
        return bool(self.one('SELECT 1 FROM klikqris_settings WHERE key=?',('archived_'+ident,)))

    def reset_snapshot(self,conn):
        cutoff=conn.execute('SELECT COALESCE(MAX(rowid),0) FROM klikqris_transactions').fetchone()[0]
        rows=[dict(row) for row in conn.execute('''SELECT id,purpose,entity_id,user_id,state,fingerprint,
            amount,total_amount,api_verified_at,verified_total,lease_until,delivery_until
            FROM klikqris_transactions t WHERE NOT EXISTS(
                SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||t.id) ORDER BY t.rowid''')]
        digest=hashlib.sha256(encoded(rows).encode()).hexdigest()
        return cutoff,rows,digest

    def reset_check_idle(self,conn,rows):
        now=time.time()
        for row in rows:
            if row['lease_until']>now or row['delivery_until']>now or row['state'] in {'PAID_VERIFIED','REVIEW'}:
                raise GatewayError('BUSY')
            if conn.execute('''SELECT 1 FROM payment_receipts WHERE lease_until>? AND user_id=?
                AND ((source=? AND entity_id=?) OR (source='qris_review' AND entity_id=?))''',
                (now,row['user_id'],row['purpose'],str(row['entity_id']),row['id'])).fetchone():raise GatewayError('BUSY')

    def prepare_history_reset(self,actor):
        self.require_owner(actor)
        if not self.configured() or self.config.mode!='gateway':raise GatewayError('CONFIG')
        if self.config.sandbox:raise GatewayError('SANDBOX')
        with self.connection(True) as conn:
            cutoff,rows,digest=self.reset_snapshot(conn)
            self.reset_check_idle(conn,rows)
            plan={'token':secrets.token_hex(8),'actor':actor,'fingerprint':self.fingerprint(),
                  'cutoff':cutoff,'digest':digest,'count':len(rows),
                  'open':sum(row['state'] in {'NEW','REQUESTING','CREATE_UNKNOWN','PENDING','CANCELLED_LOCAL'} for row in rows),
                  'expires_at':time.time()+600}
            conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',('history_reset_plan',encoded(plan),time.time()))
        return plan

    def apply_history_reset(self,actor,token):
        self.require_owner(actor)
        with self.connection(True) as conn:
            saved=conn.execute("SELECT value FROM klikqris_settings WHERE key='history_reset_plan'").fetchone()
            try:plan=json.loads(saved['value']) if saved else {}
            except (ValueError,TypeError):plan={}
            if (not isinstance(token,str) or not re.fullmatch(r'[0-9a-f]{16}',token) or plan.get('token')!=token
                    or plan.get('actor')!=actor or plan.get('fingerprint')!=self.fingerprint()):raise GatewayError('RESET_CHANGED')
            if plan.get('result') is not None:return plan['result']
            if plan.get('expires_at',0)<=time.time():raise GatewayError('RESET_CHANGED')
            cutoff,rows,digest=self.reset_snapshot(conn)
            if cutoff!=plan['cutoff'] or digest!=plan['digest']:raise GatewayError('RESET_CHANGED')
            self.reset_check_idle(conn,rows)
            now=time.time();stamp=datetime.now().isoformat(timespec='seconds')
            for row in rows:
                table='topups' if row['purpose']=='topup' else 'orders'
                native=conn.execute('SELECT * FROM '+table+' WHERE id=? AND user_id=? AND payment_method=?',
                                    (row['entity_id'],row['user_id'],METHOD)).fetchone()
                if native:
                    paid=native['status']=='completed' if row['purpose']=='topup' else native['payment_status']=='paid'
                    if native['status']=='processing' or (paid and row['state'] not in {'SETTLED','SETTLED_BALANCE'}):raise GatewayError('BUSY')
                    if not paid:
                        if row['purpose']=='order':
                            self.host.release_order_reservation(conn,native)
                            conn.execute("UPDATE orders SET status='cancelled',payment_status='cancelled',reserved_until='' WHERE id=? AND status NOT IN ('cancelled','expired','completed')",
                                         (row['entity_id'],))
                        else:
                            credited=conn.execute("SELECT 1 FROM wallet_ledger WHERE user_id=? AND type='TOPUP' AND reference=?",(row['user_id'],self.host.topup_invoice(row['entity_id']))).fetchone()
                            if credited:raise GatewayError('BUSY')
                            conn.execute("UPDATE topups SET status='cancelled',updated_at=? WHERE id=? AND status='pending'",(stamp,row['entity_id']))
                conn.execute('INSERT INTO klikqris_settings VALUES(?,?,?)',('archived_'+row['id'],encoded({
                    'reset':token,'actor':actor,'archived_at':now,'previous_state':row['state'],'provider_cancelled':False}),now))
                conn.execute('''UPDATE klikqris_transactions SET qr_image=NULL,
                    state=CASE WHEN state IN ('NEW','REQUESTING','CREATE_UNKNOWN','PENDING') THEN 'CANCELLED_LOCAL' ELSE state END
                    WHERE id=?''',(row['id'],))
                conn.execute("UPDATE klikqris_payment_messages SET kind='RESET',next_retry_at=0 WHERE transaction_id=? AND kind='QR'",(row['id'],))
                for prefix in ('status_diagnostic_','status_account_'):
                    conn.execute('DELETE FROM klikqris_settings WHERE key=?',(prefix+row['id'],))
            conn.execute("DELETE FROM klikqris_settings WHERE key IN ('account_fingerprint','verified_gateway','verified_my_pg','connection_gateway','connection_my_pg','invoice_gateway','invoice_my_pg','checkout_diagnostic','diagnostic_image','diagnostic_telegram')")
            for key,value in [('enabled',False),('mode','gateway')]:
                conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',(key,encoded(value),now))
            result={'count':len(rows),'open':plan['open'],'archived_at':now}
            plan['result']=result
            conn.execute("UPDATE klikqris_settings SET value=?,updated_at=? WHERE key='history_reset_plan'",(encoded(plan),now))
            self.audit(conn,actor,'history_reset',detail=encoded({'count':len(rows),'open':plan['open'],'reset':token}))
        return result

    async def cleanup_reset_messages(self,bot):
        if bot is None:return
        with self.connection() as conn:
            messages=[dict(row) for row in conn.execute('''SELECT m.* FROM klikqris_payment_messages m
                JOIN klikqris_transactions t ON t.id=m.transaction_id AND t.user_id=m.chat_id
                WHERE m.kind='RESET' AND m.next_retry_at<=? AND EXISTS(
                    SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||t.id) LIMIT 20''',(time.time(),))]
        for message in messages:
            if self.protected_receipt_message(message['chat_id'],message['message_id']):
                with self.connection(True) as conn:
                    conn.execute("UPDATE klikqris_payment_messages SET kind='INVOICE' WHERE transaction_id=? AND message_id=? AND kind='RESET'",(message['transaction_id'],message['message_id']))
                continue
            deleted=False;delay=min(3600,10*2**min(message['attempts'],8))
            try:
                await bot.delete_message(chat_id=message['chat_id'],message_id=message['message_id']);deleted=True
            except TelegramBadRequest as exc:deleted='message to delete not found' in str(exc).lower()
            except TelegramRetryAfter as exc:delay=max(delay,int(exc.retry_after))
            except asyncio.CancelledError:raise
            except Exception:pass
            with self.connection(True) as conn:
                conn.execute("UPDATE klikqris_payment_messages SET kind=?,attempts=attempts+1,next_retry_at=? WHERE transaction_id=? AND message_id=? AND kind='RESET'",
                    ('REMOVED' if deleted else 'RESET',0 if deleted else time.time()+delay,message['transaction_id'],message['message_id']))

    def rebind_unsent_draft(self,ident):
        # NEW is committed before the request lease. No row that has crossed
        # REQUESTING (including CREATE_UNKNOWN) can take this no-network path.
        if not self.ready():raise GatewayError('NOT_READY')
        with self.connection(True) as conn:
            row=dict(conn.execute('SELECT * FROM klikqris_transactions WHERE id=?',(ident,)).fetchone())
            if self.history_archived(ident,conn):return False
            if (row['state']!='NEW' or any(row[key] for key in
                    ('signature','qr_image','total_amount','provider_status','expires_at',
                     'api_verified_at','verified_total','lease_owner','lease_until'))):return False
            conn.execute('''UPDATE klikqris_transactions SET fingerprint=?,mode=?,sandbox=0,error=''
                WHERE id=? AND state='NEW' AND fingerprint=?''',
                (self.fingerprint(),self.settings()['mode'],ident,row['fingerprint']))
            self.audit(conn,0,'draft_account_updated',ident,'before_create')
        return True

    @staticmethod
    def status_error_context(exc,row,credential):
        exc.stage='status_reconciliation'
        exc.transaction_id=row['id']
        exc.transaction_state=row['state']
        exc.mode=row['mode']
        exc.credential=credential
        return exc

    async def read_status(self,row):
        try:return await self.api.status(row['reference'],row['mode']),'current'
        except GatewayError as exc:
            raise self.status_error_context(exc,row,'current')

    def save_status_diagnostic(self,conn,row,*,code,http_status,credential,correlation_id='',transaction_missing=False):
        detail={'stage':'status_reconciliation','code':code,'http_status':http_status,
                'credential':credential,'transaction_id':row['id'],'transaction_state':row['state'],
                'mode':row['mode'],'correlation_id':correlation_id or secrets.token_hex(8),
                'checked_at':time.time(),'transaction_missing':transaction_missing}
        conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',
                     ('status_diagnostic_'+row['id'],encoded(detail),time.time()))

    async def recover_account(self,row):
        if not self.can_recover_account(row):raise GatewayError('ACCOUNT_CHANGED')
        if row['lease_until']>time.time():raise GatewayError('BUSY')
        # Read with the active API key, then compare against the ORIGINAL
        # encrypted signature and expected amount/reference before rebinding.
        data,credential=await self.read_status(row)
        try:_,status,_=self.validate(row,data,create=not bool(row['signature']))
        except GatewayError as exc:
            exc.http_status=exc.http_status or 200
            raise self.status_error_context(exc,row,credential) from None
        if row['state']=='PAID_VERIFIED' and status not in {'PAID','SUCCESS'}:raise GatewayError('MISMATCH')
        signature=self.crypt(data['signature'].encode())
        image=self.crypt(self.crypt(row['qr_image'],decrypt=True)) if row['qr_image'] else None
        with self.connection(True) as conn:
            current=dict(conn.execute('SELECT * FROM klikqris_transactions WHERE id=?',(row['id'],)).fetchone())
            if self.history_archived(row['id'],conn):return current,data,credential
            if current['fingerprint']==self.fingerprint():return current,data,credential
            if current['fingerprint']!=row['fingerprint']:raise GatewayError('ACCOUNT_CHANGED')
            if current['lease_until']>time.time():raise GatewayError('BUSY')
            if current['state']=='PAID_VERIFIED' and status not in {'PAID','SUCCESS'}:raise GatewayError('MISMATCH')
            conn.execute('''UPDATE klikqris_transactions SET fingerprint=?,signature=?,qr_image=?
                WHERE id=? AND fingerprint=?''',(self.fingerprint(),signature,image,row['id'],row['fingerprint']))
            self.audit(conn,0,'account_key_reconciled',row['id'],'status_signature_amount_verified')
            self.save_api_evidence(conn,row['mode'],verified=True,source='account_key_reconciled',
                                   http_status=200,endpoint=self.api.endpoint_label(self.api.path(row['mode'],'status',row['reference'])))
            self.save_status_diagnostic(conn,row,code='OK',http_status=200,credential=credential)
            current=self.transaction_after(conn,row['id'])
        return current,data,credential

    async def resume(self,ident):
        row=self.transaction(ident)
        if self.history_archived(ident):return row
        try:
            if (row['fingerprint']!=self.fingerprint() or row['sandbox'] or
                    (row['state']=='NEW' and row['mode']!=self.settings()['mode'])):
                if self.rebind_unsent_draft(ident):return await self.issue(ident)
                return await self.refresh(ident)
            return await self.issue(ident)
        except GatewayError as exc:
            if exc.code=='NOT_FOUND' or (exc.code=='ENDPOINT_NOT_FOUND' and exc.http_status==404):
                self.record_checkout_failure(exc)
                return self.transaction(ident)  # Keep uncertainty; never POST a replacement.
            raise

    def record_checkout_ready(self,row):
        if row['state']!='PENDING' or not row['qr_image'] or row['fingerprint']!=self.fingerprint():return
        try:
            with self.connection(True) as conn:
                saved=conn.execute("SELECT value FROM klikqris_settings WHERE key='checkout_diagnostic'").fetchone()
                try:detail=json.loads(saved['value']) if saved else {}
                except (ValueError,TypeError):return
                if detail.get('transaction_id')==row['id'] and not detail.get('resolved_at'):
                    detail['resolved_at']=time.time()
                    conn.execute('UPDATE klikqris_settings SET value=?,updated_at=? WHERE key=?',
                                 (encoded(detail),time.time(),'checkout_diagnostic'))
        except sqlite3.Error:pass

    def settings(self):
        defaults={'enabled':self.config.enabled,'mode':self.config.mode}
        for key in defaults:
            row=self.one('SELECT value FROM klikqris_settings WHERE key=?',(key,))
            if row:
                try:defaults[key]=json.loads(row['value'])
                except (ValueError,TypeError):defaults[key]=False if key=='enabled' else 'gateway'
        # An explicit runtime mode is the deployment contract; stale DB mode
        # must not route a gateway deployment to MY PG. DB still owns enabled.
        if 'KLIKQRIS_MODE' in os.environ:defaults['mode']=self.config.mode
        return defaults

    def configured(self):
        return not self.config.error and bool(self.config.key and self.config.merchant)

    def connection_proof(self,mode):
        row=self.one('SELECT value FROM klikqris_settings WHERE key=?',('verified_'+mode,))
        try:
            proof=json.loads(row['value']) if row else {}
            if not isinstance(proof,dict) or proof.get('fingerprint')!=self.fingerprint():return {}
            if mode=='gateway' and (proof.get('source')=='status_auth_probe' or proof.get('error')=='CONNECTION_UNVERIFIED'):
                return {'fingerprint':self.fingerprint(),'verified':False,'source':'awaiting_first_invoice',
                        'checked_at':0,'history_http_status':proof.get('history_http_status',0)}
            return proof
        except (ValueError,TypeError):return {}

    def verified(self,mode):
        return self.configured() and self.connection_proof(mode).get('verified') is True

    def account_authorized(self):
        row=self.one('SELECT value FROM klikqris_settings WHERE key=?',('account_fingerprint',))
        try:
            if row:return json.loads(row['value'])==self.fingerprint()
            legacy=self.one('SELECT value FROM klikqris_settings WHERE key=?',('verified_gateway',))
            proof=json.loads(legacy['value']) if legacy else {}
            bound=proof.get('fingerprint') if isinstance(proof,dict) else None
            return not bound or bound==self.fingerprint()
        except (ValueError,TypeError):return False

    def ready(self):
        """Permission to create an invoice; payment authorization is separate."""
        try:
            settings=self.settings()
            return (self.configured() and not self.config.sandbox and settings['enabled'] is True
                    and settings['mode'] in {'gateway','my_pg'}
                    and (self.account_authorized() if settings['mode']=='gateway' else self.verified('my_pg')))
        except sqlite3.Error:return False

    def save_api_evidence(self,conn,mode,*,verified,source,actor=0,error='',http_status=0,endpoint='',history_http_status=0,checked_at=None,correlation_id=''):
        conn.execute('INSERT OR IGNORE INTO klikqris_settings VALUES(?,?,?)',
                     ('account_fingerprint',encoded(self.fingerprint()),time.time()))
        proof={'fingerprint':self.fingerprint(),'verified':bool(verified),'source':source,
               'checked_at':time.time() if checked_at is None else checked_at,'actor':actor,
               'error':error,'http_status':http_status,'endpoint':endpoint,'history_http_status':history_http_status,
               'stage':source,'correlation_id':correlation_id or secrets.token_hex(8)}
        conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',('verified_'+mode,encoded(proof),time.time()))
        if source in {'history','existing_gateway_order','existing_my_pg_order','original_account_status','connection_error'}:
            conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',('connection_'+mode,encoded(proof),time.time()))
        if source.startswith('invoice_'):
            conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',('invoice_'+mode,encoded(proof),time.time()))

    def save_stage_diagnostic(self,conn,stage,code,exc=None):
        detail={'stage':stage,'code':code,'http_status':getattr(exc,'http_status',0),
                'correlation_id':getattr(exc,'correlation_id','') or secrets.token_hex(8),
                'checked_at':time.time()}
        conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',
                     ('diagnostic_'+stage,encoded(detail),time.time()))

    def record_checkout_failure(self,exc):
        code=exc.code if isinstance(exc,GatewayError) else 'SQLITE' if isinstance(exc,sqlite3.Error) else 'INTERNAL'
        ident=getattr(exc,'correlation_id','') or secrets.token_hex(8)
        if getattr(exc,'transaction_id','') and self.history_archived(exc.transaction_id):return ident
        detail={'stage':getattr(exc,'stage','checkout'),'code':code,'http_status':getattr(exc,'http_status',0),
                'correlation_id':ident,'checked_at':time.time(),'credential':getattr(exc,'credential','current'),
                'transaction_id':getattr(exc,'transaction_id',''),'transaction_state':getattr(exc,'transaction_state',''),
                'mode':getattr(exc,'mode',''),'endpoint':getattr(exc,'endpoint','')}
        # Never log exception text: SQLite/Telegram/provider errors may contain data.
        logging.warning('KlikQRIS stage=%s code=%s correlation_id=%s',detail['stage'],code,ident)
        try:
            with self.connection(True) as conn:
                conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',('checkout_diagnostic',encoded(detail),time.time()))
        except sqlite3.Error:pass
        return ident

    def audit(self,conn,actor,action,tx='',detail=''):
        conn.execute('INSERT INTO klikqris_audit(actor,action,transaction_id,detail,created_at) VALUES(?,?,?,?,?)',(actor,action,tx,detail,time.time()))

    async def check_connection(self,actor,*,my_pg_reference=None):
        self.require_owner(actor)
        mode=self.settings()['mode'] if my_pg_reference is None else 'my_pg'
        try:
            if not self.configured():raise GatewayError('CONFIG')
            if mode=='gateway':
                previous=self.fingerprint(self.config.previous_key) if self.config.previous_key else self.fingerprint()
                actual=self.one('''SELECT * FROM klikqris_transactions WHERE mode='gateway' AND sandbox=0
                    AND fingerprint IN (?,?) AND signature IS NOT NULL AND NOT EXISTS(
                        SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||klikqris_transactions.id)
                    ORDER BY (fingerprint=?) DESC,created_at DESC LIMIT 1''',
                    (self.fingerprint(),previous,self.fingerprint()))
                if actual:
                    data,credential=await self.read_status(actual)
                    self.validate(actual,data)
                    evidence={'verified':True,'source':'existing_gateway_order','http_status':200,
                              'endpoint':self.api.endpoint_label(self.api.path('gateway','status',actual['reference']))}
                else:evidence=await self.api.connection_evidence()
            else:
                if not my_pg_reference:raise GatewayError('NOT_READY')
                data=await self.api.status(reference(my_pg_reference),'my_pg')
                if data.get('order_id')!=my_pg_reference or str(data.get('status','')).upper() not in {'PENDING','PAID','SUCCESS','EXPIRED'}:
                    raise GatewayError('SCHEMA')
                money(data.get('total_amount'),positive=True)
                evidence={'verified':True,'source':'existing_my_pg_order','http_status':200,
                          'endpoint':self.api.endpoint_label(self.api.path('my_pg','status',my_pg_reference))}
        except GatewayError as exc:
            with self.connection(True) as conn:
                self.save_api_evidence(conn,mode,verified=False,source='connection_error',actor=actor,error=exc.code,
                                       http_status=exc.http_status,endpoint=exc.endpoint,history_http_status=exc.history_http_status,correlation_id=exc.correlation_id)
                self.audit(conn,actor,'connection_failed',detail=encoded({'mode':mode,'code':exc.code}))
            raise
        with self.connection(True) as conn:
            self.save_api_evidence(conn,mode,actor=actor,**evidence)
            self.audit(conn,actor,'connection',detail=mode)
        return mode

    async def activate(self,actor):
        self.require_owner(actor)
        if not self.configured():raise GatewayError('CONFIG')
        if self.config.sandbox:raise GatewayError('SANDBOX')
        self.change(actor,'enabled',True)

    def change(self,actor,key,value):
        self.require_owner(actor)
        if key=='enabled':
            if type(value) is not bool:raise GatewayError('INPUT')
            if value and (not self.configured() or self.config.sandbox):raise GatewayError('NOT_READY')
            if value and self.settings()['mode']=='my_pg' and not self.verified('my_pg'):raise GatewayError('NOT_READY')
        elif key=='mode':
            if value not in {'gateway','my_pg'}:raise GatewayError('INPUT')
            if 'KLIKQRIS_MODE' in os.environ and value!=self.config.mode:raise GatewayError('CONFIG')
        else:raise GatewayError('INPUT')
        with self.connection(True) as conn:
            if key=='mode':
                conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',('enabled',encoded(False),time.time()))
            if key=='enabled' and value:
                conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',
                             ('account_fingerprint',encoded(self.fingerprint()),time.time()))
            if key=='enabled' and value and self.settings()['mode']=='gateway' and not self.verified('gateway'):
                self.save_api_evidence(conn,'gateway',verified=False,source='awaiting_first_invoice',actor=actor,checked_at=0)
            conn.execute('INSERT OR REPLACE INTO klikqris_settings VALUES(?,?,?)',(key,encoded(value),time.time()))
            self.audit(conn,actor,'setting',detail=encoded({key:value}))

    def transaction(self,ident,user=None,*,admin=False):
        row=self.one('SELECT * FROM klikqris_transactions WHERE id=?',(ident,))
        if admin:self.require_owner(user)
        if not row or (not admin and user is not None and row['user_id']!=user):raise GatewayError('NOT_FOUND')
        return row

    def linked(self,purpose,entity_id):
        return self.one('SELECT * FROM klikqris_transactions WHERE purpose=? AND entity_id=?',(purpose,entity_id))

    def receipt_transaction(self,source,entity):
        if source in {'order','topup'}:return self.linked(source,entity)
        if source=='qris_review':return self.one('SELECT * FROM klikqris_transactions WHERE id=?',(str(entity),))
        return None

    def protected_receipt_message(self,user,message_id):
        return bool(self.one('''SELECT 1 FROM payment_receipts r WHERE r.user_id=? AND r.message_id=?
            AND (r.status='SENT' OR r.error_code='QRIS_EDIT') AND EXISTS(
                SELECT 1 FROM klikqris_transactions t WHERE t.user_id=r.user_id AND
                ((r.source=t.purpose AND r.entity_id=CAST(t.entity_id AS TEXT)) OR
                 (r.source='qris_review' AND r.entity_id=t.id)))''',(user,message_id)))

    @staticmethod
    def receipt_key(row):
        return ('qris_review',row['id']) if row['state']=='SETTLED_BALANCE' else (row['purpose'],str(row['entity_id']))

    def receipt_payment_confirmed(self,row):
        if row['sandbox'] or not row['api_verified_at'] or row['verified_total']!=row['total_amount']:
            return False
        if row['state']=='SETTLED_BALANCE':
            return bool(self.one('''SELECT id FROM wallet_ledger WHERE id=? AND user_id=? AND type='TOPUP'
                AND amount=? AND reference=?''',(row['review_ledger_id'],row['user_id'],row['amount'],'AQ-REVIEW-'+row['id'])))
        table='topups' if row['purpose']=='topup' else 'orders'
        native=self.one('SELECT * FROM '+table+' WHERE id=? AND user_id=? AND payment_method=?',
                        (row['entity_id'],row['user_id'],METHOD))
        return bool(native and (native['status']=='completed' if row['purpose']=='topup' else native['payment_status']=='paid'))

    def remember_payment_message(self,ident,user,message_id):
        if isinstance(message_id,bool) or not isinstance(message_id,int) or not 0<message_id<=9223372036854775807:
            raise GatewayError('INPUT')
        row=self.transaction(ident,user)
        with self.connection(True) as conn:
            conn.execute('''INSERT OR IGNORE INTO klikqris_payment_messages
                (transaction_id,chat_id,message_id,created_at) VALUES(?,?,?,?)''',
                (ident,row['user_id'],message_id,time.time()))
            if self.history_archived(ident,conn):
                conn.execute("UPDATE klikqris_payment_messages SET kind='RESET',next_retry_at=0 WHERE transaction_id=? AND message_id=? AND kind='QR'",(ident,message_id))
            if row['state'] in {'SETTLED','SETTLED_BALANCE'}:
                source,entity=self.receipt_key(row)
                conn.execute("UPDATE payment_receipts SET status='ARCHIVING',next_retry_at=0 WHERE source=? AND entity_id=? AND user_id=? AND status='ARCHIVED'",(source,str(entity),row['user_id']))

    def remember_callback_message(self,call,row):
        if row['state'] in {'SETTLED','SETTLED_BALANCE'}:
            source,entity=self.receipt_key(row)
            receipt=self.one('SELECT status FROM payment_receipts WHERE source=? AND entity_id=?',(source,str(entity)))
            if receipt and receipt['status'] in {'ARCHIVING','ARCHIVED'}:return
        message=getattr(call,'message',None)
        body=getattr(message,'caption',None) or getattr(message,'text',None) or ''
        invoice=self.host.topup_invoice(row['entity_id']) if row['purpose']=='topup' else self.host.invoice(row['entity_id'])
        if (message and message.chat.id==row['user_id']==call.from_user.id and body.startswith(LABEL)
                and re.search(r'(?m)^🧾 '+re.escape(invoice)+r'\s*$',body)):
            self.remember_payment_message(row['id'],row['user_id'],message.message_id)

    async def retire_paid_messages(self,bot,ident=None):
        if bot is None:return
        if ident is None:
            with self.connection() as conn:
                ids=[r[0] for r in conn.execute('''SELECT DISTINCT m.transaction_id FROM klikqris_payment_messages m
                    JOIN klikqris_transactions t ON t.id=m.transaction_id WHERE m.kind='QR' AND m.next_retry_at<=?
                    AND t.api_verified_at>0 AND t.state IN ('PAID_VERIFIED','SETTLED','SETTLED_BALANCE') LIMIT 20''',(time.time(),))]
            for value in ids:await self.retire_paid_messages(bot,value)
            return
        row=self.transaction(ident)
        if not self.receipt_payment_confirmed(row):return
        source,entity=self.receipt_key(row)
        receipt=self.one('SELECT * FROM payment_receipts WHERE source=? AND entity_id=?',(source,str(entity)))
        if not receipt or receipt['status'] not in {'SENT','LEGACY','UNKNOWN','ARCHIVED'}:return
        with self.connection() as conn:
            messages=[dict(r) for r in conn.execute('''SELECT * FROM klikqris_payment_messages
                WHERE transaction_id=? AND kind='QR' AND next_retry_at<=?''',(ident,time.time()))]
        for message in messages:
            if receipt['message_id']==message['message_id'] and receipt['status']=='SENT':
                with self.connection(True) as conn:
                    conn.execute("UPDATE klikqris_payment_messages SET kind='INVOICE' WHERE transaction_id=? AND message_id=?",(ident,message['message_id']))
                continue
            deleted=False
            try:
                await bot.delete_message(chat_id=message['chat_id'],message_id=message['message_id'])
                deleted=True
            except TelegramBadRequest as exc:
                deleted='message to delete not found' in str(exc).lower()
            except asyncio.CancelledError:raise
            except Exception:pass
            if not deleted:
                try:
                    await bot.edit_message_caption(chat_id=message['chat_id'],message_id=message['message_id'],
                        caption='✅ Pembayaran sudah diterima. QRIS ini tidak aktif; jangan bayar lagi.',reply_markup=InlineKeyboardMarkup(inline_keyboard=[]))
                except asyncio.CancelledError:raise
                except Exception:pass
            with self.connection(True) as conn:
                conn.execute('''UPDATE klikqris_payment_messages SET kind=?,attempts=attempts+1,next_retry_at=?
                    WHERE transaction_id=? AND message_id=? AND kind='QR' ''',
                    ('REMOVED' if deleted else 'QR',0 if deleted else time.time()+min(3600,10*2**min(message['attempts'],8)),ident,message['message_id']))

    async def cleanup_success_receipts(self,bot,*,now=None):
        """Retire only acknowledged successful automatic QRIS photos, never money."""
        if bot is None:return
        now=time.time() if now is None else now
        cutoff=now-SUCCESS_RECEIPT_TTL
        with self.connection() as conn:
            jobs=[dict(row) for row in conn.execute('''SELECT t.id,r.source,r.entity_id FROM payment_receipts r
                JOIN klikqris_transactions t ON t.user_id=r.user_id AND
                  ((r.source=t.purpose AND r.entity_id=CAST(t.entity_id AS TEXT) AND t.state='SETTLED') OR
                   (r.source='qris_review' AND r.entity_id=t.id AND t.state='SETTLED_BALANCE'))
                WHERE t.sandbox=0 AND t.api_verified_at>0 AND t.verified_total=t.total_amount
                  AND r.status IN ('SENT','ARCHIVING') AND r.sent_at>0 AND r.sent_at<=?
                  AND r.next_retry_at<=? AND r.lease_until<=?
                ORDER BY r.sent_at LIMIT 10''',(cutoff,now,now))]
        for job in jobs:
            row=self.transaction(job['id'])
            if not self.receipt_payment_confirmed(row):continue
            token=secrets.token_hex(12)
            with self.connection(True) as conn:
                changed=conn.execute('''UPDATE payment_receipts SET status='ARCHIVING',lease_token=?,lease_until=?,
                    snapshot_json='{}',caption_hash='',error_code='QRIS_RETENTION'
                    WHERE source=? AND entity_id=? AND user_id=? AND status IN ('SENT','ARCHIVING')
                      AND sent_at>0 AND sent_at<=? AND next_retry_at<=? AND lease_until<=?''',
                    (token,now+300,job['source'],job['entity_id'],row['user_id'],cutoff,now,now)).rowcount
                if not changed:continue
                receipt=dict(conn.execute('SELECT * FROM payment_receipts WHERE source=? AND entity_id=?',
                                          (job['source'],job['entity_id'])).fetchone())
                # Free the obsolete QR BLOB even if Telegram is temporarily unavailable.
                # Keep signatures, references, native transactions and outbox tombstones.
                conn.execute('UPDATE klikqris_transactions SET qr_image=NULL WHERE id=?',(row['id'],))
                if isinstance(receipt['message_id'],int) and receipt['message_id']>0:
                    conn.execute('''INSERT OR IGNORE INTO klikqris_payment_messages
                        (transaction_id,chat_id,message_id,kind,created_at) VALUES(?,?,?,'INVOICE',?)''',
                        (row['id'],row['user_id'],receipt['message_id'],receipt['sent_at']))
                messages=[dict(item) for item in conn.execute('''SELECT * FROM klikqris_payment_messages
                    WHERE transaction_id=? AND chat_id=? AND kind IN ('QR','INVOICE') AND next_retry_at<=?
                    ORDER BY message_id LIMIT 20''',(row['id'],row['user_id'],now))]
            try:
                for message in messages:
                    try:
                        try:
                            await asyncio.wait_for(bot.delete_message(chat_id=row['user_id'],message_id=message['message_id']),timeout=10)
                        except TelegramBadRequest as exc:
                            if 'message to delete not found' not in str(exc).lower():raise
                    except asyncio.CancelledError:raise
                    except Exception as exc:
                        delay=max(float(getattr(exc,'retry_after',0) or 0),min(3600,10*2**min(message['attempts'],8)))
                        with self.connection(True) as conn:
                            conn.execute('''UPDATE klikqris_payment_messages SET attempts=attempts+1,next_retry_at=?
                                WHERE transaction_id=? AND chat_id=? AND message_id=? AND kind IN ('QR','INVOICE')''',
                                (now+delay,row['id'],row['user_id'],message['message_id']))
                        if isinstance(exc,TelegramRetryAfter):break
                    else:
                        with self.connection(True) as conn:
                            conn.execute('''UPDATE klikqris_payment_messages SET kind='REMOVED',next_retry_at=0
                                WHERE transaction_id=? AND chat_id=? AND message_id=?''',
                                (row['id'],row['user_id'],message['message_id']))
                with self.connection(True) as conn:
                    pending=conn.execute('''SELECT COUNT(*) n,MIN(next_retry_at) due FROM klikqris_payment_messages
                        WHERE transaction_id=? AND chat_id=? AND kind IN ('QR','INVOICE')''',(row['id'],row['user_id'])).fetchone()
                    if not pending['n']:
                        conn.execute('''UPDATE payment_receipts SET status='ARCHIVED',message_id=NULL,next_retry_at=0,
                            lease_token=NULL,lease_until=0 WHERE source=? AND entity_id=? AND lease_token=?''',
                            (job['source'],job['entity_id'],token))
                    else:
                        conn.execute('''UPDATE payment_receipts SET next_retry_at=?,lease_token=NULL,lease_until=0
                            WHERE source=? AND entity_id=? AND lease_token=?''',
                            (max(now+5,pending['due'] or 0),job['source'],job['entity_id'],token))
            except BaseException:
                with self.connection(True) as conn:
                    conn.execute('''UPDATE payment_receipts SET lease_token=NULL,lease_until=0,next_retry_at=?
                        WHERE source=? AND entity_id=? AND lease_token=?''',(now+10,job['source'],job['entity_id'],token))
                raise

    async def deliver_receipt_photo(self,bot,receipt,photo,caption):
        row=self.receipt_transaction(receipt['source'],receipt['entity_id'])
        if not row or not self.receipt_payment_confirmed(row):raise GatewayError('NOT_READY')
        # Editing a durable message ID is safe to retry even when Telegram's
        # acknowledgement is lost. It replaces the QR itself with the invoice.
        anchor=receipt['message_id'] if receipt['error_code']=='QRIS_EDIT' else None
        if not anchor:
            existing=self.one('''SELECT message_id FROM klikqris_payment_messages
                WHERE transaction_id=? AND kind='QR' ORDER BY created_at DESC,message_id DESC LIMIT 1''',(row['id'],))
            anchor=existing['message_id'] if existing else None
        if anchor:
            with self.connection(True) as conn:
                changed=conn.execute('''UPDATE payment_receipts SET message_id=?,error_code='QRIS_EDIT'
                    WHERE source=? AND entity_id=? AND lease_token=?''',
                    (anchor,receipt['source'],receipt['entity_id'],receipt['lease_token'])).rowcount
            if changed!=1:raise GatewayError('STORAGE')
            try:
                await bot.edit_message_media(chat_id=row['user_id'],message_id=anchor,
                    media=InputMediaPhoto(media=photo,caption=caption,parse_mode='HTML'),reply_markup=InlineKeyboardMarkup(inline_keyboard=[]))
            except TelegramBadRequest as exc:
                detail=str(exc).lower()
                if 'message is not modified' in detail:pass
                elif 'message to edit not found' in detail or "message can't be edited" in detail:
                    if 'message to edit not found' in detail:
                        with self.connection(True) as conn:
                            conn.execute("UPDATE klikqris_payment_messages SET kind='REMOVED' WHERE transaction_id=? AND message_id=?",(row['id'],anchor))
                    anchor=None
                else:raise
            if anchor:
                with self.connection(True) as conn:
                    conn.execute("UPDATE klikqris_payment_messages SET kind='INVOICE' WHERE transaction_id=? AND message_id=?",(row['id'],anchor))
                return SimpleNamespace(message_id=anchor)
        # Legacy/unseen QR: reserve one send before the network request. If its
        # result is unknown, do not replay sendPhoto after timeout or restart.
        with self.connection(True) as conn:
            changed=conn.execute('''UPDATE payment_receipts SET status='UNKNOWN',message_id=NULL,error_code='QRIS_SEND_STARTED'
                WHERE source=? AND entity_id=? AND lease_token=?''',
                (receipt['source'],receipt['entity_id'],receipt['lease_token'])).rowcount
        if changed!=1:raise GatewayError('STORAGE')
        try:return await bot.send_photo(row['user_id'],photo,caption=caption,parse_mode='HTML')
        except (TelegramBadRequest,TelegramForbiddenError,TelegramRetryAfter):
            with self.connection(True) as conn:
                conn.execute("UPDATE payment_receipts SET status='SENDING' WHERE source=? AND entity_id=? AND lease_token=?",(receipt['source'],receipt['entity_id'],receipt['lease_token']))
            raise

    def payment_authorized(self,conn,purpose,entity_id):
        row=conn.execute('SELECT * FROM klikqris_transactions WHERE purpose=? AND entity_id=?',(purpose,entity_id)).fetchone()
        if not row:return False
        native=conn.execute('SELECT * FROM '+('topups' if purpose=='topup' else 'orders')+' WHERE id=?',(entity_id,)).fetchone()
        base=(native['amount'] if purpose=='topup' else native['total']-int(native['discount_amount'] or 0)) if native else None
        return bool(native and native['payment_method']==METHOD and native['user_id']==row['user_id']
                    and native['provider_reference']==row['reference'] and native['payment_total']==row['total_amount']
                    and base==row['amount'] and row['state']=='PAID_VERIFIED' and not row['sandbox'] and not self.config.sandbox
                    and row['fingerprint']==self.fingerprint() and row['api_verified_at']>0
                    and row['total_amount']==row['verified_total'] and row['provider_status'] in {'PAID','SUCCESS'})

    def reserve(self,conn,purpose,entity_id,user,amount):
        if not self.ready():raise GatewayError('NOT_READY')
        existing=conn.execute('SELECT * FROM klikqris_transactions WHERE purpose=? AND entity_id=?',(purpose,entity_id)).fetchone()
        if existing:return dict(existing)
        ident=secrets.token_hex(10)
        ref='AQ-'+purpose[0].upper()+'-'+str(entity_id)+'-'+secrets.token_hex(8)
        conn.execute('''INSERT INTO klikqris_transactions
            (id,purpose,entity_id,user_id,reference,mode,sandbox,fingerprint,amount,state,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,'NEW',?)''',
            (ident,purpose,entity_id,user,ref,self.settings()['mode'],int(self.config.sandbox),self.fingerprint(),money(amount,positive=True),time.time()))
        return dict(conn.execute('SELECT * FROM klikqris_transactions WHERE id=?',(ident,)).fetchone())

    def validate(self,row,data,*,create=False):
        if not isinstance(data,dict) or data.get('order_id')!=row['reference']:raise GatewayError('MISMATCH',uncertain=create)
        if 'id_merchant' in data and str(data['id_merchant'])!=self.config.merchant:raise GatewayError('MISMATCH',uncertain=create)
        if 'merchant_id' in data and str(data['merchant_id'])!=self.config.merchant:raise GatewayError('MISMATCH',uncertain=create)
        total=money(data.get('total_amount'),positive=True)
        if total<row['amount'] or (row['total_amount'] is not None and total!=row['total_amount']):raise GatewayError('MISMATCH',uncertain=create)
        if (create or 'amount' in data) and money(data.get('amount'),positive=True)!=row['amount']:raise GatewayError('MISMATCH',uncertain=create)
        status=data.get('status')
        if not isinstance(status,str) or status.upper() not in {'PENDING','PAID','SUCCESS','EXPIRED','FAILED'}:
            raise GatewayError('SCHEMA',uncertain=create)
        signature=data.get('signature')
        if create and (not isinstance(signature,str) or not 8<=len(signature)<=2048):raise GatewayError('SCHEMA',uncertain=True)
        if row.get('signature') and (not isinstance(signature,str) or not hmac.compare_digest(signature.encode(),self.crypt(row['signature'],decrypt=True))):
            raise GatewayError('MISMATCH',uncertain=create)
        until=expiry(data['expired_at']) if data.get('expired_at') else None
        if create and until is None:raise GatewayError('SCHEMA',uncertain=True)
        return total,status.upper(),until

    def save_invoice(self,conn,row,total,until):
        # The provider total already contains its unique amount/fees. No local
        # unique code is added. Existing amount/price snapshots are untouched.
        deadline=datetime.fromtimestamp(until,timezone.utc).isoformat(timespec='seconds') if until else ''
        if row['purpose']=='topup':
            conn.execute('''UPDATE topups SET payment_total=?,unique_code=0,provider_reference=?,expires_at=?
                WHERE id=? AND user_id=? AND payment_method=? AND status='pending' ''',
                (total,row['reference'],deadline,row['entity_id'],row['user_id'],METHOD))
        else:
            conn.execute('''UPDATE orders SET payment_total=?,unique_code=0,provider_reference=?,reserved_until=?
                WHERE id=? AND user_id=? AND payment_method=? AND payment_status!='paid' ''',
                (total,row['reference'],deadline,row['entity_id'],row['user_id'],METHOD))

    async def issue(self,ident):
        row=self.transaction(ident)
        if self.history_archived(ident):return row
        if row['fingerprint']!=self.fingerprint() or row['sandbox'] or self.config.sandbox:raise GatewayError('ACCOUNT_CHANGED')
        token=secrets.token_hex(12)
        with self.connection(True) as conn:
            changed=conn.execute("UPDATE klikqris_transactions SET state='REQUESTING',lease_owner=?,lease_until=? WHERE id=? AND state='NEW' AND fingerprint=? AND mode=? AND sandbox=? AND NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||klikqris_transactions.id)",
                                 (token,time.time()+self.config.timeout+30,ident,row['fingerprint'],row['mode'],row['sandbox'])).rowcount
        if not changed:return self.transaction(ident)
        try:
            data=await self.api.create(row['reference'],row['amount'],row['mode'])
            total,status,until=self.validate(row,data,create=True)
            with self.connection(True) as conn:
                changed=conn.execute('''UPDATE klikqris_transactions SET total_amount=?,signature=?,
                    state=CASE WHEN state='CANCELLED_LOCAL' THEN state ELSE 'PENDING' END,provider_status=?,
                    expires_at=?,next_poll_at=?,error='',lease_owner=NULL,lease_until=0 WHERE id=? AND lease_owner=? AND fingerprint=?
                    AND NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||klikqris_transactions.id)''',
                    (total,self.crypt(data['signature'].encode()),status,until,time.time()+self.config.poll_seconds,ident,token,row['fingerprint'])).rowcount
                if not changed:return self.transaction_after(conn,ident)
                self.save_invoice(conn,row,total,until)
                self.save_api_evidence(conn,row['mode'],verified=True,source='invoice_created',http_status=200,
                                       endpoint=self.api.endpoint_label(self.api.path(row['mode'],'create')))
            try:
                image=await self.api.image(data)
                with self.connection(True) as conn:
                    conn.execute("UPDATE klikqris_transactions SET qr_image=? WHERE id=? AND fingerprint=? AND state='PENDING'",(self.crypt(image),ident,row['fingerprint']))
            except (GatewayError,ValueError) as exc:
                with self.connection(True) as conn:
                    if self.history_archived(ident,conn):return self.transaction_after(conn,ident)
                    conn.execute("UPDATE klikqris_transactions SET error='IMAGE' WHERE id=?",(ident,))
                    self.save_stage_diagnostic(conn,'image','IMAGE',exc)
            # A create response alone never credits money, even if it says paid.
            if status!='PENDING':return await self.refresh(ident)
        except asyncio.CancelledError:
            with self.connection(True) as conn:
                conn.execute("UPDATE klikqris_transactions SET state='CREATE_UNKNOWN',lease_owner=NULL,lease_until=0 WHERE id=? AND state='REQUESTING'",(ident,))
            raise
        except Exception as exc:
            code=exc.code if isinstance(exc,GatewayError) else 'SQLITE' if isinstance(exc,sqlite3.Error) else 'INTERNAL'
            with self.connection(True) as conn:
                if self.history_archived(ident,conn):return self.transaction_after(conn,ident)
                conn.execute("""UPDATE klikqris_transactions SET state='CREATE_UNKNOWN',error=?,next_poll_at=?,
                    lease_owner=NULL,lease_until=0 WHERE id=? AND state='REQUESTING'""",
                    (code,time.time()+max(self.config.poll_seconds,getattr(exc,'retry_after',0)),ident))
                if isinstance(exc,GatewayError):
                    self.save_api_evidence(conn,row['mode'],verified=False,source='invoice_create_error',error=exc.code,
                                           http_status=exc.http_status,endpoint=exc.endpoint or self.api.endpoint_label(self.api.path(row['mode'],'create')),correlation_id=exc.correlation_id)
                else:
                    self.save_api_evidence(conn,row['mode'],verified=False,source='invoice_create_error',error=code)
        return self.transaction(ident)

    def notice(self,conn,row,event):
        conn.execute('''INSERT OR IGNORE INTO klikqris_notifications
            (id,transaction_id,event,status) VALUES(?,?,?,'PENDING')''',(row['id']+':'+event,row['id'],event))

    async def refresh(self,ident):
        row=self.transaction(ident)
        if self.history_archived(ident):return row
        if row['state'] in FINAL:return row
        if row['state']=='REQUESTING' and row['lease_until']>time.time():return row
        recovered=None;credential='current'
        try:
            if row['fingerprint']!=self.fingerprint():row,recovered,credential=await self.recover_account(row)
            if row['state']=='PAID_VERIFIED':return await self.settle(ident)
            if recovered is not None:data=recovered
            else:data,credential=await self.read_status(row)
            try:total,status,until=self.validate(row,data)
            except GatewayError as exc:
                exc.http_status=exc.http_status or 200
                raise self.status_error_context(exc,row,credential) from None
            with self.connection(True) as conn:
                current=conn.execute('SELECT * FROM klikqris_transactions WHERE id=?',(ident,)).fetchone()
                if self.history_archived(ident,conn):
                    if status in {'PAID','SUCCESS'} and current['state'] not in FINAL:
                        conn.execute("UPDATE klikqris_transactions SET state='REVIEW',provider_status=?,api_verified_at=?,verified_total=?,error='PAYMENT_AFTER_RESET' WHERE id=?",(status,time.time(),total,ident))
                        self.notice(conn,row,'REVIEW')
                    return self.transaction_after(conn,ident)
                if current['state'] in FINAL or current['state']=='PAID_VERIFIED':
                    return dict(current)
                conn.execute('''UPDATE klikqris_transactions SET total_amount=?,provider_status=?,checked_at=?,
                    next_poll_at=?,expires_at=COALESCE(?,expires_at),error='' WHERE id=?''',
                    (total,status,time.time(),time.time()+self.config.poll_seconds,until,ident))
                self.save_invoice(conn,row,total,until or row['expires_at'])
                self.save_status_diagnostic(conn,row,code='OK',http_status=200,credential=credential)
                if not current['signature'] and isinstance(data.get('signature'),str) and 8<=len(data['signature'])<=2048:
                    conn.execute('UPDATE klikqris_transactions SET signature=? WHERE id=?',(self.crypt(data['signature'].encode()),ident))
                if status in {'PAID','SUCCESS'}:
                    state='SANDBOX_PAID' if row['sandbox'] or self.config.sandbox else 'REVIEW' if current['state']=='REVIEW' else 'PAID_VERIFIED'
                    conn.execute('''UPDATE klikqris_transactions SET state=?,api_verified_at=?,verified_total=? WHERE id=?''',
                                 (state,time.time(),total,ident))
                elif status in {'EXPIRED','FAILED'}:
                    self.expire_native(conn,row)
                    conn.execute('UPDATE klikqris_transactions SET state=? WHERE id=?',(status,ident))
                    self.notice(conn,row,'FAILED' if status=='FAILED' else 'EXPIRED')
                elif current['state'] in {'REQUESTING','CREATE_UNKNOWN','NEW'}:
                    conn.execute("UPDATE klikqris_transactions SET state='PENDING' WHERE id=?",(ident,))
            if status=='PENDING' and not row['qr_image']:
                try:
                    image=await self.api.image(data)
                    with self.connection(True) as conn:conn.execute("UPDATE klikqris_transactions SET qr_image=? WHERE id=? AND state='PENDING'",(self.crypt(image),ident))
                except (GatewayError,ValueError):pass
            if status in {'SUCCESS','PAID'} and not row['sandbox'] and not self.config.sandbox:
                return await self.settle(ident)
        except GatewayError as exc:
            if not getattr(exc,'transaction_id',''):self.status_error_context(exc,row,credential)
            with self.connection(True) as conn:
                self.save_status_diagnostic(conn,row,code=exc.code,http_status=exc.http_status,credential=exc.credential,
                                            correlation_id=exc.correlation_id,transaction_missing=exc.transaction_missing)
                conn.execute('UPDATE klikqris_transactions SET checked_at=?,error=?,next_poll_at=? WHERE id=? AND state NOT IN (\'SETTLED\',\'SETTLED_BALANCE\')',
                             (time.time(),exc.code,time.time()+max(self.config.poll_seconds,exc.retry_after),ident))
            raise
        return self.transaction(ident)

    def expire_native(self,conn,row):
        if row['purpose']=='topup':
            conn.execute("UPDATE topups SET status='expired',updated_at=? WHERE id=? AND payment_method=? AND status='pending'",
                         (datetime.now().isoformat(timespec='seconds'),row['entity_id'],METHOD))
        else:
            order=conn.execute('SELECT * FROM orders WHERE id=? AND payment_method=?',(row['entity_id'],METHOD)).fetchone()
            if order and order['payment_status']!='paid' and order['status'] not in {'completed','cancelled'}:
                self.host.release_order_reservation(conn,order)
                conn.execute("UPDATE orders SET status='expired',payment_status='expired',reserved_until='' WHERE id=?",(row['entity_id'],))
                self.host.sync_variant_reserved_stock(conn,int(order['variant_id']))

    async def settle(self,ident):
        token=secrets.token_hex(12)
        with self.connection(True) as conn:
            row=conn.execute('SELECT * FROM klikqris_transactions WHERE id=?',(ident,)).fetchone()
            if not row or row['state']!='PAID_VERIFIED' or row['sandbox'] or self.config.sandbox or row['fingerprint']!=self.fingerprint() or row['api_verified_at']<=0 or row['verified_total']!=row['total_amount']:
                return dict(row) if row else None
            changed=conn.execute("UPDATE klikqris_transactions SET lease_owner=?,lease_until=? WHERE id=? AND lease_until<=? AND state='PAID_VERIFIED'",
                                 (token,time.time()+180,ident,time.time())).rowcount
            if not changed:return dict(row)
            row=dict(row)
            table='topups' if row['purpose']=='topup' else 'orders'
            native=conn.execute('SELECT * FROM '+table+' WHERE id=? AND user_id=? AND payment_method=?',
                                (row['entity_id'],row['user_id'],METHOD)).fetchone()
            if not native or native['status'] in {'cancelled','rejected'}:
                conn.execute("UPDATE klikqris_transactions SET state='REVIEW',error='PAYMENT_AFTER_CANCEL',lease_owner=NULL,lease_until=0 WHERE id=?",(ident,))
                self.notice(conn,row,'REVIEW')
                return self.transaction_after(conn,ident)
            if not self.payment_authorized(conn,row['purpose'],row['entity_id']):
                conn.execute("UPDATE klikqris_transactions SET state='REVIEW',error='NATIVE_MISMATCH',lease_owner=NULL,lease_until=0 WHERE id=?",(ident,))
                self.notice(conn,row,'REVIEW')
                return self.transaction_after(conn,ident)
        try:
            if row['purpose']=='topup':
                result,reason=self.host.verify_topup_atomic(row['entity_id'],0)
                success=result is not None and reason in {'completed','already_completed'}
            else:
                if self.bot is None:raise GatewayError('NOT_READY')
                await self.host.mark_order_paid(row['entity_id'],self.bot,row['total_amount'])
                with self.connection() as conn:
                    native=conn.execute('SELECT payment_status FROM orders WHERE id=?',(row['entity_id'],)).fetchone()
                    success=bool(native and native['payment_status']=='paid')
            if success:
                with self.connection(True) as conn:
                    conn.execute("UPDATE klikqris_transactions SET state='SETTLED',lease_owner=NULL,lease_until=0,error='' WHERE id=? AND lease_owner=?",(ident,token))
                    self.notice(conn,row,'PAID')
                self.host.payment_receipts.queue(self.host,row['purpose'],row['entity_id'])
        finally:
            with self.connection(True) as conn:
                conn.execute('UPDATE klikqris_transactions SET lease_owner=NULL,lease_until=0 WHERE id=? AND lease_owner=?',(ident,token))
        return self.transaction(ident)

    @staticmethod
    def transaction_after(conn,ident):
        return dict(conn.execute('SELECT * FROM klikqris_transactions WHERE id=?',(ident,)).fetchone())

    async def fulfill_once(self,order_id,bot,implementation):
        row=self.linked('order',order_id)
        if not row:return await implementation(order_id,bot)
        if row['sandbox']:return False
        lock=self.delivery_locks.setdefault(order_id,asyncio.Lock())
        async with lock:
            token=secrets.token_hex(12)
            with self.connection(True) as conn:
                changed=conn.execute('''UPDATE klikqris_transactions SET delivery_owner=?,delivery_until=?
                    WHERE id=? AND delivery_until<=?''',(token,time.time()+300,row['id'],time.time())).rowcount
            if not changed:return False
            try:return await implementation(order_id,bot)
            finally:
                with self.connection(True) as conn:
                    conn.execute('UPDATE klikqris_transactions SET delivery_owner=NULL,delivery_until=0 WHERE id=? AND delivery_owner=?',(row['id'],token))
                if not getattr(lock,'_waiters',None):self.delivery_locks.pop(order_id,None)

    async def credit_review(self,actor,ident):
        self.require_owner(actor)
        await self.refresh(ident)
        with self.connection(True) as conn:
            row=conn.execute('SELECT * FROM klikqris_transactions WHERE id=?',(ident,)).fetchone()
            if row['state']=='SETTLED_BALANCE':return dict(row)
            if row['state']!='REVIEW' or row['provider_status'] not in {'PAID','SUCCESS'} or not row['api_verified_at'] or row['sandbox'] or row['verified_total']!=row['total_amount'] or row['fingerprint']!=self.fingerprint():raise GatewayError('NOT_READY')
            ref='AQ-REVIEW-'+ident
            prior=conn.execute("SELECT id FROM wallet_ledger WHERE user_id=? AND type='TOPUP' AND reference=?",(row['user_id'],ref)).fetchone()
            if prior:ledger_id=prior['id']
            else:
                wallet=conn.execute('SELECT balance FROM wallets WHERE user_id=?',(row['user_id'],)).fetchone()
                balance=(int(wallet['balance']) if wallet else 0)+row['amount']
                if not 0<=balance<=9223372036854775807:raise GatewayError('STORAGE')
                stamp=datetime.now().isoformat(timespec='seconds')
                conn.execute('INSERT INTO wallets(user_id,balance,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET balance=excluded.balance,updated_at=excluded.updated_at',(row['user_id'],balance,stamp))
                ledger_id=conn.execute('''INSERT INTO wallet_ledger(user_id,type,amount,balance_after,reference,note,created_at)
                    VALUES(?,'TOPUP',?,?,?,?,?)''',(row['user_id'],row['amount'],balance,ref,'Pembayaran QRIS Otomatis dipindahkan ke saldo setelah pemeriksaan owner.',stamp)).lastrowid
            conn.execute("UPDATE klikqris_transactions SET state='SETTLED_BALANCE',review_ledger_id=?,error='' WHERE id=?",(ledger_id,ident))
            self.audit(conn,actor,'credit_review',ident,str(row['amount']))
            self.notice(conn,row,'BALANCE')
        self.host.payment_receipts.queue(self.host,'qris_review',ident)
        return self.transaction(ident)

    async def webhook(self,request):
        if request.content_length and request.content_length>8192:return web.json_response({'ok':False},status=413)
        raw=await request.content.read(8193)
        if len(raw)>8192:return web.json_response({'ok':False},status=413)
        try:
            body=json.loads(raw.decode(),parse_float=Decimal)
            data=body.get('data',body) if isinstance(body,dict) else None
            if not isinstance(data,dict):raise GatewayError('INPUT')
            ref=reference(data.get('order_id'))
            row=self.one('SELECT * FROM klikqris_transactions WHERE reference=?',(ref,))
            if not row:return web.json_response({'ok':False},status=404)
            if row['fingerprint']!=self.fingerprint() and not self.can_recover_account(row):raise GatewayError('AUTH')
            supplied=data.get('signature')
            if not row['signature']:return web.json_response({'ok':False,'retry':True},status=503)
            if not isinstance(supplied,str) or not 1<=len(supplied)<=2048 or not hmac.compare_digest(supplied.encode(),self.crypt(row['signature'],decrypt=True)):
                raise GatewayError('AUTH')
            if row['mode']=='my_pg' and str(data.get('merchant_id',''))!=self.config.merchant:raise GatewayError('AUTH')
            for key in ('merchant_id','id_merchant'):
                if key in data and str(data[key])!=self.config.merchant:raise GatewayError('AUTH')
            total=data.get('amount_paid',data.get('total_amount'))
            if total is not None and money(total,positive=True)!=row['total_amount']:raise GatewayError('MISMATCH')
            base=data.get('amount_request',data.get('amount'))
            if base is not None and money(base,positive=True)!=row['amount']:raise GatewayError('MISMATCH')
            status=data.get('status')
            if not isinstance(status,str) or status.upper() not in {'PAID','SUCCESS','EXPIRED'}:raise GatewayError('INPUT')
            if status.upper() in {'PAID','SUCCESS'} and total is None:raise GatewayError('MISMATCH')
            if self.history_archived(row['id']) and row['state'] not in FINAL:
                if status.upper() in {'PAID','SUCCESS'}:
                    with self.connection(True) as conn:
                        conn.execute("UPDATE klikqris_transactions SET state='REVIEW',error='PAYMENT_AFTER_RESET_UNVERIFIED' WHERE id=? AND state NOT IN ('SETTLED','SETTLED_BALANCE')",(row['id'],))
                        self.notice(conn,row,'REVIEW')
                return web.json_response({'ok':True})
            if row['state'] not in FINAL:await self.refresh(row['id'])
            return web.json_response({'ok':True})
        except (ValueError,UnicodeError):return web.json_response({'ok':False},status=400)
        except GatewayError as exc:
            return web.json_response({'ok':False},status=401 if exc.code=='AUTH' else 400 if exc.code in {'INPUT','MISMATCH','SCHEMA'} else 503)
        except sqlite3.Error:return web.json_response({'ok':False},status=503)

    async def poll_once(self,*,force=False):
        now=time.time()
        with self.connection(True) as conn:
            conn.execute("UPDATE klikqris_transactions SET state='CREATE_UNKNOWN',lease_owner=NULL,lease_until=0 WHERE state='REQUESTING' AND lease_until<=?",(now,))
            rows=[dict(row) for row in conn.execute('''SELECT * FROM klikqris_transactions WHERE
                state IN ('NEW','CREATE_UNKNOWN','PENDING','PAID_VERIFIED','CANCELLED_LOCAL') AND next_poll_at<=?
                AND NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||klikqris_transactions.id)
                ORDER BY next_poll_at LIMIT 20''',(1e20 if force else now,))]
        for row in rows:
            try:
                if row['state']=='NEW':await self.issue(row['id'])
                else:await self.refresh(row['id'])
            except GatewayError as exc:
                if exc.code=='RATE_LIMIT':break
            except asyncio.CancelledError:raise
            except Exception:
                with self.connection(True) as conn:
                    conn.execute("UPDATE klikqris_transactions SET error='STORAGE',next_poll_at=? WHERE id=?",(time.time()+60,row['id']))
        if self.bot is not None:
            await self.deliver_notices()
            await self.retire_paid_messages(self.bot)

    async def deliver_notices(self):
        with self.connection() as conn:
            jobs=[dict(row) for row in conn.execute("SELECT * FROM klikqris_notifications WHERE status='PENDING' AND next_retry_at<=? AND lease_until<=? ORDER BY next_retry_at LIMIT 10",(time.time(),time.time()))]
        for job in jobs:
            token=secrets.token_hex(10)
            with self.connection(True) as conn:
                if conn.execute("UPDATE klikqris_notifications SET lease_owner=?,lease_until=? WHERE id=? AND status='PENDING' AND lease_until<=?",(token,time.time()+60,job['id'],time.time())).rowcount!=1:continue
            row=self.transaction(job['transaction_id'])
            if job['event'] in {'PAID','BALANCE'}:
                source,entity=self.receipt_key(row)
                if not self.host.payment_receipts.queue(self.host,source,entity):
                    with self.connection(True) as conn:
                        conn.execute("UPDATE klikqris_notifications SET next_retry_at=?,lease_owner=NULL,lease_until=0 WHERE id=? AND lease_owner=?",(time.time()+30,job['id'],token))
                    continue
                # The existing image outbox is the sole success notification.
                with self.connection(True) as conn:
                    conn.execute("UPDATE klikqris_notifications SET status='PHOTO_QUEUED',sent_at=?,lease_owner=NULL,lease_until=0 WHERE id=? AND lease_owner=?",(time.time(),job['id'],token))
                continue
            invoice=self.host.topup_invoice(row['entity_id']) if row['purpose']=='topup' else self.host.invoice(row['entity_id'])
            label={'EXPIRED':'⏳ PEMBAYARAN KEDALUWARSA','FAILED':'❌ PEMBAYARAN TIDAK BERHASIL','REVIEW':'⏳ PEMBAYARAN SEDANG DIPERIKSA'}[job['event']]
            text=label+'\n'+LABEL+'\n\n'+html.escape(invoice)+'\n'
            if job['event']=='REVIEW':text+='Pembayaran diterima setelah invoice tidak aktif. Owner akan memeriksanya.\n'
            else:text+='Invoice tidak dapat dibayar lagi. Buat pembayaran baru jika diperlukan.\n'
            try:
                await self.bot.send_message(row['user_id'],text)
                if job['event']=='REVIEW' and self.host.ADMIN_ID:
                    await self.bot.send_message(self.host.ADMIN_ID,'KlikQRIS: pembayaran membutuhkan rekonsiliasi. Buka QRIS Otomatis → Transaksi Pending.',reply_markup=self.owner_keyboard([[('📋 Periksa','detail',row['id'])]]))
            except asyncio.CancelledError:raise
            except Exception:
                with self.connection(True) as conn:
                    attempts=job['attempts']+1
                    conn.execute('''UPDATE klikqris_notifications SET attempts=?,status=?,next_retry_at=?,lease_owner=NULL,lease_until=0
                        WHERE id=? AND lease_owner=?''',(attempts,'FAILED' if attempts>=8 else 'PENDING',time.time()+min(3600,10*2**attempts),job['id'],token))
            else:
                with self.connection(True) as conn:
                    conn.execute("UPDATE klikqris_notifications SET status='SENT',sent_at=?,lease_owner=NULL,lease_until=0 WHERE id=? AND lease_owner=?",(time.time(),job['id'],token))

    async def start(self,bot):
        self.bot=bot
        jobs=[]
        if self.task is None or self.task.done():
            async def run():
                while True:
                    try:await self.poll_once()
                    except asyncio.CancelledError:raise
                    except Exception:pass
                    await asyncio.sleep(max(5,min(self.config.poll_seconds,30)))
            self.task=asyncio.create_task(run(),name='klikqris_payments')
            jobs.append(self.task)
        if self.cleanup_task is None or self.cleanup_task.done():
            async def clean():
                while True:
                    try:
                        await self.cleanup_success_receipts(bot)
                        await self.cleanup_reset_messages(bot)
                    except asyncio.CancelledError:raise
                    except Exception as exc:logging.warning('QRIS invoice cleanup deferred type=%s',type(exc).__name__)
                    await asyncio.sleep(30)
            self.cleanup_task=asyncio.create_task(clean(),name='klikqris_invoice_cleanup')
            jobs.append(self.cleanup_task)
        return jobs

    async def close(self):
        tasks=[task for task in (self.task,self.cleanup_task) if task is not None]
        for task in tasks:task.cancel()
        if tasks:await asyncio.gather(*tasks,return_exceptions=True)
        self.task=self.cleanup_task=None
        await self.api.close()

    async def buyer_guard(self,call):
        if not call.message or str(call.message.chat.type)!='private' or call.message.chat.id!=call.from_user.id:
            raise GatewayError('FORBIDDEN')
        if self.host.security_blocked(call.from_user.id):raise GatewayError('FORBIDDEN')
        if not self.host.is_owner(call.from_user.id) and (self.host.safe_mode_enabled() or self.host.maintenance_enabled()):raise GatewayError('NOT_READY')
        if not await self.host.is_channel_member(call.bot,call.from_user.id):raise GatewayError('FORBIDDEN')
        if not self.ready():raise GatewayError('NOT_READY')
        ok,_=self.host.persistent_rate_limit(call.from_user.id,'autoqris_create',limit=5,window_seconds=60)
        if not ok:raise GatewayError('RATE_LIMIT')
        self.bot=call.bot

    async def topup(self,call,amount,state=None):
        await self.buyer_guard(call)
        amount=money(amount,positive=True)
        if amount<self.host.get_min_topup():raise GatewayError('INPUT')
        async with self.host.purchase_lock(call.from_user.id):
            with self.connection(True) as conn:
                row=conn.execute('''SELECT t.* FROM klikqris_transactions t JOIN topups n ON n.id=t.entity_id
                    WHERE t.purpose='topup' AND t.user_id=? AND t.amount=? AND (n.status='pending' OR t.state IN ('REQUESTING','CREATE_UNKNOWN','CANCELLED_LOCAL'))
                    AND t.state IN ('NEW','REQUESTING','CREATE_UNKNOWN','PENDING','PAID_VERIFIED','CANCELLED_LOCAL')
                    AND NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||t.id)
                    ORDER BY t.created_at DESC LIMIT 1''',
                    (call.from_user.id,amount)).fetchone()
                if row:tx=dict(row)
                else:
                    stamp=datetime.now().isoformat(timespec='seconds')
                    ident=conn.execute('''INSERT INTO topups(user_id,username,amount,unique_code,payment_total,
                        payment_method,status,created_at,updated_at,expires_at) VALUES(?,?,?,0,?,?,'pending',?,?,'')''',
                        (call.from_user.id,call.from_user.username or '',amount,amount,METHOD,stamp,stamp)).lastrowid
                    tx=self.reserve(conn,'topup',ident,call.from_user.id,amount)
            resumed=await self.resume(tx['id'])
            self.record_checkout_ready(resumed)
            if state is not None:await state.clear()
            await self.show_payment(call,tx['id'])

    async def checkout(self,call,bot,state,variant_id,qty):
        await self.buyer_guard(call)
        qty=money(qty,positive=True)
        data=await state.get_data()
        note=self.host.get_checkout_note_from_state(data)
        with self.connection() as conn:
            family_product=conn.execute('SELECT p.* FROM products p JOIN product_variants v ON v.product_id=p.id WHERE v.id=?',(variant_id,)).fetchone()
        if self.host.product_is_famhead(family_product) and (
            int(data.get('checkout_variant_id',0) or 0)!=variant_id
            or not self.host.valid_family_gmail(data.get('family_gmail',''))
        ):
            # Keep the existing family checkout wizard; no invoice/stock hold
            # is created until its required account data has been collected.
            await self.host.require_family_checkout_gmail(call,state,family_product,variant_id,qty,data)
            return
        lookup_sql='''SELECT t.* FROM klikqris_transactions t JOIN orders o ON o.id=t.entity_id
            WHERE t.purpose='order' AND t.user_id=? AND o.variant_id=? AND o.qty=?
            AND (o.status='pending' OR t.state IN ('REQUESTING','CREATE_UNKNOWN','CANCELLED_LOCAL'))
            AND o.payment_status!='paid' AND t.state IN ('NEW','REQUESTING','CREATE_UNKNOWN','PENDING','PAID_VERIFIED','CANCELLED_LOCAL')
            AND NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||t.id)
            ORDER BY t.created_at DESC LIMIT 1'''
        lookup_args=(call.from_user.id,variant_id,qty)
        async with self.host.purchase_lock(call.from_user.id):
            if not self.one(lookup_sql,lookup_args):
                # The guard can write security events; keep it outside BEGIN
                # IMMEDIATE and apply it only when creating a new native order.
                allowed,_=self.host.anti_abuse_checkout(call.from_user.id,METHOD)
                if not allowed:raise GatewayError('LIMIT')
            with self.connection(True) as conn:
                row=conn.execute(lookup_sql,lookup_args).fetchone()
                if row:tx=dict(row)
                else:
                    variant=conn.execute('SELECT * FROM product_variants WHERE id=?',(variant_id,)).fetchone()
                    product=conn.execute('SELECT * FROM products WHERE id=?',(variant['product_id'],)).fetchone() if variant else None
                    if not variant or not product or not variant['active'] or not self.host.product_is_available(product) or self.host.available_stock(variant)<qty:
                        raise GatewayError('STOCK')
                    if self.host.variant_is_sharing(variant) and qty!=1:raise GatewayError('INPUT')
                    if self.host.product_is_famhead(product) and (int(data.get('checkout_variant_id',0) or 0)!=variant_id or not self.host.valid_family_gmail(data.get('family_gmail',''))):
                        raise GatewayError('FAMILY_GMAIL')
                    unit=self.host.effective_unit_price(variant,qty)
                    subtotal=unit*qty
                    voucher,discount=self.host.checkout_discount_from_state(data,call.from_user.id,product['id'],variant_id,subtotal,conn=conn)
                    if subtotal-discount<=0:
                        raise self.host.VoucherCheckoutError('Voucher menutup seluruh tagihan. Selesaikan dengan saldo bot tanpa potongan saldo.',wallet_only=True)
                    amount=money(subtotal-discount,positive=True)
                    if not self.host.reserve_stock_for_order(conn,variant_id,qty):raise GatewayError('STOCK')
                    ident=conn.execute('''INSERT INTO orders(user_id,username,product_id,variant_id,qty,unit_price,total,
                        status,payment_method,payment_status,note,unique_code,payment_total,stock_reserved,reserved_until,created_at,
                        voucher_code,discount_amount) VALUES(?,?,?,?,?,?,?,'pending',?,'unpaid',?,0,?,1,'',?,?,?)''',
                        (call.from_user.id,call.from_user.username or '',product['id'],variant_id,qty,unit,subtotal,METHOD,note,amount,
                         datetime.now().isoformat(timespec='seconds'),voucher,discount)).lastrowid
                    tx=self.reserve(conn,'order',ident,call.from_user.id,amount)
            resumed=await self.resume(tx['id'])
            self.record_checkout_ready(resumed)
            await state.clear()
            await self.show_payment(call,tx['id'])

    def user_keyboard(self,row):
        rows=[[InlineKeyboardButton(text='🔄 Cek Status',callback_data=PREFIX+'u:check:'+row['id'])]]
        if row['state'] in {'NEW','REQUESTING','CREATE_UNKNOWN','PENDING'}:
            rows.append([InlineKeyboardButton(text='❌ Batalkan',callback_data=PREFIX+'u:cancel:'+row['id'])])
        rows.append([InlineKeyboardButton(text='🏠 Menu Awal',callback_data='home')])
        return InlineKeyboardMarkup(inline_keyboard=rows)

    def status_text(self,row):
        invoice=self.host.topup_invoice(row['entity_id']) if row['purpose']=='topup' else self.host.invoice(row['entity_id'])
        status={'NEW':'Menyiapkan pembayaran','REQUESTING':'Menyiapkan pembayaran','CREATE_UNKNOWN':'Menunggu kepastian invoice',
                'PENDING':'Menunggu pembayaran','PAID_VERIFIED':'Pembayaran diterima; sedang diproses',
                'SETTLED':'Pembayaran berhasil','SETTLED_BALANCE':'Pembayaran masuk ke saldo',
                'EXPIRED':'Kedaluwarsa','FAILED':'Pembayaran tidak berhasil','REVIEW':'Pembayaran sedang diperiksa owner',
                'CANCELLED_LOCAL':'Dibatalkan di bot; jangan bayar QRIS ini'}.get(row['state'],'Sedang diperiksa')
        text=LABEL+'\n<b>MABOYY DIGITAL</b>\n\n🧾 '+html.escape(invoice)+'\n'
        text+=('💰 Nominal saldo: ' if row['purpose']=='topup' else '💵 Harga pesanan: ')+self.host.rupiah(row['amount'])+'\n'
        if row['total_amount'] is not None:
            text+='Biaya/penyesuaian QRIS: '+self.host.rupiah(row['total_amount']-row['amount'])+'\n'
            text+='<b>Total pembayaran: '+self.host.rupiah(row['total_amount'])+'</b>\n'
        text+='📌 Status: '+html.escape(status)+'\n'
        if row['expires_at'] and row['state'] not in {'SETTLED','SETTLED_BALANCE','REVIEW'}:
            text+='⏳ Berlaku hingga: '+self.host.payment_receipts.format_wib(row['expires_at'],compact=True)+'\n'
        if row['state']=='PENDING' and row['error'] not in {'NOT_FOUND','ENDPOINT_NOT_FOUND'}:text+='Bayar tepat sesuai total. Status akan diperbarui otomatis.\n'
        if row['state'] in {'REQUESTING','CREATE_UNKNOWN'}:text+='Invoice sedang diperiksa. Jangan membuat pembayaran pengganti atau membayar dua kali.\n'
        if row['error'] and row['state'] not in {'SETTLED','SETTLED_BALANCE'}:text+='Pemeriksaan belum selesai; cek kembali atau hubungi owner.\n'
        return text+'\n<i>'+html.escape(self.host.STORE_FOOTER)+'</i>'

    def native_status(self,purpose,entity_id):
        row=self.linked(purpose,entity_id)
        if not row:raise GatewayError('NOT_FOUND')
        return self.status_text(row),self.user_keyboard(row)

    async def show_status(self,call,ident,*,refresh=True,admin=False):
        row=self.transaction(ident,call.from_user.id,admin=admin)
        self.bot=call.bot
        if self.history_archived(ident):
            if admin:return await self.owner_detail(call,ident)
            return await self.host.safe_edit_or_answer(call,self.status_text(row)+'\nRiwayat QRIS ini sudah ditutup oleh owner. Jangan bayar QRIS lama; pembelian berikutnya memakai pesanan baru.',reply_markup=self.user_keyboard(row),parse_mode='HTML')
        if not admin:self.remember_callback_message(call,row)
        if refresh:
            try:row=await self.refresh(ident)
            except GatewayError as exc:
                self.record_checkout_failure(exc)
                row=self.transaction(ident,call.from_user.id,admin=admin)
        if admin:return await self.owner_detail(call,ident)
        if row['state'] in {'SETTLED','SETTLED_BALANCE'}:
            source,entity=self.receipt_key(row)
            receipt=self.one('SELECT status FROM payment_receipts WHERE source=? AND entity_id=?',(source,str(entity)))
            if receipt and receipt['status'] in {'ARCHIVING','ARCHIVED'}:
                note='Foto invoice sudah dihapus otomatis setelah 1 jam.' if receipt['status']=='ARCHIVED' else 'Invoice sudah melewati 1 jam; pembersihan otomatis sedang dicoba.'
                await self.host.safe_edit_or_answer(call,self.status_text(row)+'\n'+note+' Riwayat pembayaran tetap tersedia.',reply_markup=self.user_keyboard(row),parse_mode='HTML')
                return
            await self.host.payment_receipts.notify(self.host,call.bot,source,entity)
            await self.retire_paid_messages(call.bot,ident)
            return
        if row['fingerprint']!=self.fingerprint() or row['error'] in {'NOT_FOUND','ENDPOINT_NOT_FOUND'}:
            await self.host.safe_edit_or_answer(call,self.status_text(row)+'\nTagihan baru belum dibuat. Referensi invoice lama masih harus direkonsiliasi oleh owner; jangan membayar dua kali.',reply_markup=self.user_keyboard(row),parse_mode='HTML')
            return
        # Include the original QR when reopening or recovering a pending invoice.
        # This only displays stored payment data; it never creates another invoice.
        if row['state']=='PENDING' and row['qr_image'] and (not row['expires_at'] or row['expires_at']>time.time()):
            return await self.show_payment(call,ident)
        await self.host.safe_edit_or_answer(call,self.status_text(row),reply_markup=self.user_keyboard(row),parse_mode='HTML')

    async def show_payment(self,call,ident):
        row=self.transaction(ident,call.from_user.id)
        if self.history_archived(ident):return await self.show_status(call,ident,refresh=False)
        if row['fingerprint']!=self.fingerprint():return await self.show_status(call,ident,refresh=False)
        if row['error'] in {'NOT_FOUND','ENDPOINT_NOT_FOUND'}:return await self.show_status(call,ident)
        if row['state']!='PENDING' or not row['qr_image'] or (row['expires_at'] and row['expires_at']<=time.time()):
            return await self.show_status(call,ident)
        raw=self.crypt(row['qr_image'],decrypt=True)
        try:
            sent=await call.bot.send_photo(call.from_user.id,BufferedInputFile(raw,filename='qris-'+str(row['entity_id'])+'.png'),
                caption=self.status_text(row),reply_markup=self.user_keyboard(row),parse_mode='HTML')
        except Exception:
            with self.connection(True) as conn:
                conn.execute("UPDATE klikqris_transactions SET error='TELEGRAM' WHERE id=?",(ident,))
                self.save_stage_diagnostic(conn,'telegram','TELEGRAM')
                self.audit(conn,0,'qr_delivery_failed',ident,encoded({'stage':'telegram','code':'TELEGRAM','correlation_id':secrets.token_hex(8)}))
            # Never fall back to a provider URL, dashboard or report link.
            return await self.host.safe_edit_or_answer(call,self.status_text(row)+'\nGambar QRIS belum dapat ditampilkan. Jangan membayar sebelum QRIS tersedia.',reply_markup=self.user_keyboard(row),parse_mode='HTML')
        self.remember_payment_message(ident,row['user_id'],sent.message_id)
        if row['purpose']=='topup':
            if not self.host.save_topup_payment_message(row['entity_id'],row['user_id'],sent.message_id):
                await self.host.retire_topup_payment_message(call.bot,row['user_id'],sent.message_id)
        await self.retire_paid_messages(call.bot,ident)
        source,entity=self.receipt_key(self.transaction(ident))
        receipt=self.one('SELECT message_id FROM payment_receipts WHERE source=? AND entity_id=?',(source,str(entity)))
        try:
            if not receipt or receipt['message_id']!=call.message.message_id:await call.message.delete()
        except Exception:pass

    async def cancel(self,call,ident):
        row=self.transaction(ident,call.from_user.id)
        if row['purpose']=='topup':
            _,status=self.host.cancel_topup_atomic(row['entity_id'],call.from_user.id)
            ok=status in {'cancelled','already_cancelled'}
        else:
            ok,_=await self.host.cancel_pending_order(row['entity_id'],call.bot)
        if ok:
            with self.connection(True) as conn:
                conn.execute("UPDATE klikqris_transactions SET state='CANCELLED_LOCAL' WHERE id=? AND state IN ('NEW','REQUESTING','CREATE_UNKNOWN','PENDING')",(ident,))
            await self.host.render_cancelled_payment_message(call,LABEL+'\nInvoice dibatalkan di bot. Jangan bayar QRIS ini. Pembayaran yang terlanjur masuk akan diperiksa owner.',self.user_keyboard(self.transaction(ident)))
        else:await self.show_status(call,ident)

    def owner_keyboard(self,rows):
        return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=label,callback_data=PREFIX+'a:'+action+(':'+str(value) if value is not None else '')) for label,action,value in line] for line in rows])

    async def owner_panel(self,call,*,note=''):
        self.require_owner(call.from_user.id)
        settings=self.settings()
        proof=self.connection_proof(settings['mode'])
        stamp=proof.get('checked_at',0)
        if not isinstance(stamp,(int,float)) or not 0<stamp<253402300800:stamp=0
        verified=self.verified(settings['mode'])
        ready=self.ready()
        api_status='Terakhir terverifikasi' if verified else (
            ('Gagal membuat QRIS (' if proof.get('source')=='invoice_create_error' else 'Pemeriksaan gagal (')+str(proof['error'])+')'
            if proof.get('error') else 'Belum terverifikasi')
        if proof.get('error') in {'NETWORK','UPSTREAM'} and int(proof.get('http_status') or 0)>=500:
            api_status='Layanan API mengembalikan HTTP '+str(proof['http_status'])+'; pembuatan QRIS belum dapat dipastikan'
        problems=self.config.problems()
        webhook=self.config.webhook_url if not any('KLIKQRIS_WEBHOOK_URL' in issue for issue in self.config.issues) else 'Perlu diperbaiki di environment hosting.'
        text=('👑 <b>PENGATURAN QRIS OTOMATIS</b>\n\nProvider: KlikQRIS\n'
              f"Versi bot: {html.escape(str(self.host.BOT_VERSION))}\n"
              f"Mode: {'MY PG' if settings['mode']=='my_pg' else 'Gateway biasa'}\n"
              f"Izin membuat invoice: {'AKTIF' if ready else 'NONAKTIF / belum siap'}\n"
              f"Status API: {html.escape(api_status)}\n"
              f"Diperiksa: {self.host.payment_receipts.format_wib(stamp,compact=True) if stamp else '-'}\n"
              f"API Key: {'Terisi' if self.config.key else 'Belum diisi'} • Merchant ID: {'Terisi' if self.config.merchant else 'Belum diisi'}\n"
              'Terisi hanya menunjukkan keberadaan nilai, bukan autentikasi berhasil.\n'
              f"Konfigurasi: {'Tersedia' if self.configured() else 'Perlu diperbaiki'}\n"
              f"Sandbox: {'ON; saldo/produk nyata diblokir' if self.config.sandbox else 'OFF'}\n\n"
              'Webhook: '+html.escape(webhook or 'Atur URL webhook pada dashboard; polling tetap tersedia.')+'\n')
        if proof.get('error') in {'NETWORK','UPSTREAM'} and int(proof.get('http_status') or 0)>=500:
            text+='\n⚠️ Nonaktifkan pembelian baru sementara. Periksa transaksi pending sebelum membuat invoice pengganti. HTTP 5xx dapat berasal dari gateway atau perantara jaringan; bukan bukti API key salah.\n'
        if problems:text+='\n⚠️ '+html.escape('\n'.join(problems))+'\n'
        if proof.get('endpoint'):
            text+='Pemeriksaan: '+html.escape(str(proof['endpoint']))+'\n'
            if proof.get('http_status'):text+='HTTP: '+str(int(proof['http_status']))+'\n'
        if proof.get('history_http_status')==404:
            text+='ℹ️ HTTP 404 riwayat bukan bukti autentikasi atau riwayat kosong.\n'
        if not verified and settings['mode']=='gateway' and not problems and not proof.get('error'):
            text+='API akan diverifikasi saat invoice pembayaran dibuat. Saldo masuk setelah pembayaran sah.\n'
        if proof.get('source')=='original_account_status':
            text+='Pemeriksaan lama memakai key asal. Ulangi Cek Koneksi untuk memeriksa key aktif.\n'
        if verified and proof.get('source') in {'invoice_created','existing_gateway_order'}:
            text+='Verifikasi API memakai invoice nyata.\n'
        saved=self.one('SELECT value FROM klikqris_settings WHERE key=?',('invoice_'+settings['mode'],))
        try:invoice=json.loads(saved['value']) if saved else {}
        except (ValueError,TypeError):invoice={}
        connection=self.one('SELECT value FROM klikqris_settings WHERE key=?',('connection_'+settings['mode'],))
        try:connection=json.loads(connection['value']) if connection else {}
        except (ValueError,TypeError):connection={}
        for title,item in [('Cek Koneksi terakhir',connection),('Create invoice terakhir',invoice)]:
            if not isinstance(item,dict) or item.get('fingerprint')!=self.fingerprint():continue
            stamp=item.get('checked_at',0)
            text+='\n'+title+': '+html.escape(str(item.get('error') or item.get('source') or '-'))+'\n'
            text+='Waktu: '+self.host.payment_receipts.format_wib(stamp,compact=True)+'\n'
            text+='Tahap: '+html.escape(str(item.get('stage',item.get('source','-'))))+' • HTTP: '+str(int(item.get('http_status') or 0) or '-')+'\n'
            text+='ID: '+html.escape(str(item.get('correlation_id') or '-'))+'\n'
        for key in ('checkout_diagnostic','diagnostic_image','diagnostic_telegram'):
            diagnostic=self.one('SELECT value FROM klikqris_settings WHERE key=?',(key,))
            if diagnostic:
                try:
                    diagnostic=json.loads(diagnostic['value'])
                    if key=='checkout_diagnostic':text+='\nKesalahan proses QRIS terakhir'+(' (teratasi)' if diagnostic.get('resolved_at') else ' (riwayat)')+'\n'
                    text+='\nTahap: '+html.escape(str(diagnostic['stage']))+' • Kode: '+html.escape(str(diagnostic['code']))+' • HTTP: '+str(diagnostic['http_status'] or '-')+'\nID: '+html.escape(diagnostic['correlation_id'])+'\nWaktu: '+self.host.payment_receipts.format_wib(diagnostic['checked_at'],compact=True)+'\n'
                    if diagnostic.get('transaction_state'):
                        text+='Status transaksi: '+html.escape(str(diagnostic['transaction_state']))+' • Mode: '+html.escape(str(diagnostic.get('mode','')))+'\n'
                        text+='Kredensial pembacaan: '+('akun asal' if diagnostic.get('credential')=='previous' else 'akun aktif')+'\n'
                except (ValueError,TypeError,KeyError):pass
        blocked=self.one('''SELECT COUNT(*) n FROM klikqris_transactions WHERE fingerprint!=?
            AND state IN ('NEW','REQUESTING','CREATE_UNKNOWN','PENDING','PAID_VERIFIED','CANCELLED_LOCAL')
            AND NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||klikqris_transactions.id)''',(self.fingerprint(),))['n']
        if blocked:
            text+='\nKonfigurasi lama: '+str(blocked)+' transaksi belum final. Draft NEW yang belum dikirim dipulihkan saat checkout dibuka.\n'
            text+='Semua request API memakai key aktif. Key lama hanya untuk membuka data terenkripsi secara lokal.\n'
            text+='Jika status referensi lama tetap 404, minta KlikQRIS memeriksa hasil create asli; jangan reset transaksi atau membuat pengganti.\n'
        if self.config.normalized:
            text+='\nℹ️ Format nilai environment dibaca otomatis; cukup isi nilainya saja.\n'
        if note:text+='\n'+html.escape(note)+'\n'
        rows=[[('🔌 Cek Koneksi','connect',None),('⚙️ Pilih Mode','modes',None)],
              [('🔴 Nonaktifkan' if ready else '🟢 Aktifkan KlikQRIS','toggle','off' if ready else 'on')],
              [('📊 Riwayat Transaksi','history',0),('⏳ Transaksi Pending','pending',0)],
              [('🔄 Rekonsiliasi','reconcile',None)],
              [('🧹 Reset Riwayat QRIS','reset_preview',None)],
              [('⬅️ Pengaturan Pembayaran','back',None)]]
        if settings['enabled'] and not ready:rows.insert(2,[('🔴 Nonaktifkan','toggle','off')])
        await self.host.safe_edit_or_answer(call,text,reply_markup=self.owner_keyboard(rows),parse_mode='HTML')

    async def owner_list(self,call,*,pending=False,page=0):
        self.require_owner(call.from_user.id)
        visible="NOT EXISTS(SELECT 1 FROM klikqris_settings s WHERE s.key='archived_'||klikqris_transactions.id)"
        term="WHERE state NOT IN ('SETTLED','SETTLED_BALANCE','EXPIRED','FAILED','SANDBOX_PAID') AND ("+visible+" OR state='REVIEW')" if pending else 'WHERE '+visible
        count=self.one('SELECT COUNT(*) n FROM klikqris_transactions '+term)['n']
        page=max(0,min(int(page),max(0,(count-1)//6)))
        with self.connection() as conn:
            rows=[dict(row) for row in conn.execute('SELECT * FROM klikqris_transactions '+term+' ORDER BY created_at DESC LIMIT 6 OFFSET ?',(page*6,))]
        action='pending' if pending else 'history'
        text='📊 <b>TRANSAKSI QRIS OTOMATIS</b>\nProvider: KlikQRIS\nHalaman '+str(page+1)+'/'+str(max(1,(count+5)//6))+'\n\n'
        controls=[]
        for row in rows:
            text+=html.escape(row['reference'])+' • '+self.host.rupiah(row['total_amount'] or row['amount'])+' • '+html.escape(row['state'])+'\n'
            controls.append([('🔎 '+row['reference'],'detail',row['id'])])
        if not rows:text+='Belum ada transaksi.\n'
        nav=[]
        if page:nav.append(('⬅️ Sebelumnya',action,page-1))
        if (page+1)*6<count:nav.append(('Berikutnya ➡️',action,page+1))
        if nav:controls.append(nav)
        controls.append([('⬅️ Kembali','menu',None)])
        await self.host.safe_edit_or_answer(call,text,reply_markup=self.owner_keyboard(controls),parse_mode='HTML')

    async def owner_reset_preview(self,call):
        plan=self.prepare_history_reset(call.from_user.id)
        text=('🧹 <b>RESET RIWAYAT QRIS OTOMATIS</b>\n\n'
              'Riwayat pada panel: '+str(plan['count'])+' transaksi.\n'
              'Invoice belum final: '+str(plan['open'])+'.\n\n'
              'Pesanan QRIS yang belum dibayar akan ditutup di bot dan reservasi stok dilepas. '
              'Saldo, pesanan yang sudah dibayar, serta penanda pembayaran tetap disimpan.\n\n'
              '<b>Ini tidak membatalkan invoice di KlikQRIS.</b> QR lama mungkin masih dapat dibayar; '
              'pembayaran yang masuk belakangan perlu diperiksa owner. Jangan membayar QR lama.\n\n'
              'Setelah reset, QRIS dijeda. Aktifkan kembali dari panel sebelum membuat pembelian baru dengan key aktif. '
              'Reset tidak membuat invoice. Konfirmasi berlaku 10 menit dan harus diulang jika data berubah.')
        await self.host.safe_edit_or_answer(call,text,reply_markup=self.owner_keyboard([
            [('✅ Tutup & kosongkan riwayat','reset_commit',plan['token'])],[('⬅️ Batal','menu',None)]]),parse_mode='HTML')

    async def owner_detail(self,call,ident,*,confirm_credit=False):
        row=self.transaction(ident,call.from_user.id,admin=True)
        text=self.status_text(row)+'\n\nProvider: KlikQRIS\nRef: '+html.escape(row['reference'])+'\nMode: '+row['mode']+'\nUser: '+str(row['user_id'])+'\nKode: '+html.escape(row['error'] or '-')
        if self.history_archived(ident):text+='\n\nRiwayat ditutup lewat reset owner. Penanda pembayaran disimpan; invoice provider tidak dibatalkan otomatis.'
        source,entity=self.receipt_key(row)
        receipt=self.one('SELECT status FROM payment_receipts WHERE source=? AND entity_id=?',(source,str(entity)))
        if receipt and receipt['status'] in {'ARCHIVING','ARCHIVED'}:
            text+='\n\nInvoice foto sudah melewati masa simpan 1 jam dan dijadwalkan untuk dihapus otomatis. Riwayat dan pembayaran tetap tersimpan.'
        if receipt and receipt['status']=='UNKNOWN':
            text+='\n\nPengiriman invoice belum dapat dipastikan. Periksa chat penerima; gambar tidak dikirim ulang otomatis agar tidak ganda. Saldo dan pembayaran tidak diulang.'
        status_detail=self.one('SELECT value FROM klikqris_settings WHERE key=?',('status_diagnostic_'+ident,))
        if status_detail:
            try:
                detail=json.loads(status_detail['value'])
                text+='\n\nPemeriksaan referensi ini: '+html.escape(str(detail['code']))+' • HTTP: '+str(detail['http_status'] or '-')
                text+='\nAkun: '+('asal' if detail.get('credential')=='previous' else 'aktif')+' • Tahap: status_reconciliation'
                text+='\nWaktu: '+self.host.payment_receipts.format_wib(detail['checked_at'],compact=True)+' • ID: '+html.escape(detail['correlation_id'])
                if detail['code'] in {'NOT_FOUND','ENDPOINT_NOT_FOUND'}:text+='\n404 belum membuktikan create sebelumnya tidak terjadi; tidak ada POST pengganti.'
            except (ValueError,TypeError,KeyError):pass
        controls=[[('🔄 Rekonsiliasi Status','check',ident)]]
        if row['state']=='REVIEW':
            if confirm_credit:
                text+='\n\nPindahkan '+self.host.rupiah(row['amount'])+' ke wallet user tersebut? Order lama tetap dibatalkan; produk tidak dikirim. Penyesuaian/biaya QRIS tidak dikreditkan.'
                controls.insert(0,[('✅ Konfirmasi Kredit Saldo','credit',ident)])
            else:controls.insert(0,[('💰 Pindahkan ke Saldo','credit_confirm',ident)])
        controls.append([('⬅️ Kembali','pending',0),('🏠 QRIS Otomatis','menu',None)])
        await self.host.safe_edit_or_answer(call,text,reply_markup=self.owner_keyboard(controls),parse_mode='HTML')


def register(router,gateway):
    host=gateway.host

    async def failure(call,exc,*,owner=False):
        codes={'CONFIG':'Periksa environment hosting yang ditandai pada panel KlikQRIS.',
               'AUTH':'Autentikasi ditolak. Periksa API Key/Merchant ID dan izin akun.',
               'NOT_READY':'Lengkapi konfigurasi dan matikan sandbox. Gateway biasa memakai Aktifkan KlikQRIS; MY PG memerlukan verifikasi merchant terhubung.',
               'SANDBOX':'Sandbox sedang ON. Atur KLIKQRIS_SANDBOX=false dan redeploy sebelum mengaktifkan pembayaran nyata.',
               'REJECTED':'API menolak pemeriksaan. Periksa status aktivasi gateway, API Key, Merchant ID, dan izin akun di dashboard KlikQRIS.',
               'SCHEMA':'Bentuk respons API tidak sesuai dokumentasi; koneksi belum dinyatakan berhasil.',
               'HTTP':'API mengembalikan status HTTP yang belum didukung; koneksi belum dinyatakan berhasil.',
               'HISTORY_UNAVAILABLE':'Riwayat API HTTP 404: bukan bukti autentikasi berhasil atau riwayat kosong.',
               'CONNECTION_UNVERIFIED':'Riwayat API tidak tersedia dan autentikasi endpoint status belum dapat dibuktikan. Pembayaran baru belum diaktifkan; tidak ada invoice dibuat.',
               'ENDPOINT_NOT_FOUND':'Endpoint API mengembalikan HTTP 404. Periksa akses gateway pada akun KlikQRIS; ini tidak membuktikan transaksi bot hilang.',
               'NOT_FOUND':'Transaksi belum ditemukan. Jangan membuat invoice pengganti untuk transaksi yang masih belum pasti.',
               'NETWORK':'Koneksi API belum berhasil. Cek status invoice sebelum mencoba ulang.',
               'UPSTREAM':'API/perantara mengembalikan HTTP 5xx. Hasil create mungkin belum pasti; rekonsiliasi dahulu.',
               'DNS':'Resolusi DNS gagal.', 'TLS':'Verifikasi TLS gagal.', 'TIMEOUT':'Request timeout; cek status invoice sebelum mencoba ulang.',
               'JSON_INVALID':'Respons API bukan JSON valid.',
               'MISMATCH':'Referensi atau nominal tidak sesuai; saldo/produk belum diproses.',
               'ACCOUNT_CHANGED':'Invoice memakai konfigurasi lama. API hanya memakai key aktif; key lama hanya membuka signature/QR tersimpan secara lokal. Rekonsiliasi atau periksa referensi dengan KlikQRIS, tanpa invoice pengganti.',
               'BUSY':'Invoice masih diproses. Tunggu lalu Cek Status; jangan membuat tagihan pengganti.',
               'RESET_CHANGED':'Data atau konfigurasi berubah, atau konfirmasi kedaluwarsa. Buka ulang Reset Riwayat QRIS; belum ada data ditutup.',
               'STOCK':'Stok tidak mencukupi.', 'RATE_LIMIT':'Terlalu banyak permintaan. Tunggu sebelum mencoba kembali.',
               'FORBIDDEN':'Akses ditolak.'}
        text=codes.get(getattr(exc,'code',''),'Pembayaran belum dapat diproses; data transaksi tetap disimpan untuk pemeriksaan.') if owner else buyer_error(exc)
        if not owner:gateway.record_checkout_failure(exc)
        if owner and getattr(exc,'code','')=='NOT_FOUND' and str(getattr(call,'data','') or '').split(':')[2:3] in [['connect'],['toggle'],['mode']]:
            text='Pemeriksaan koneksi mengembalikan HTTP 404. Ini bukan pencarian transaksi user; koneksi belum terverifikasi.'
        if owner and getattr(exc,'code','')!='FORBIDDEN' and host.is_owner(call.from_user.id) and call.message and str(call.message.chat.type)=='private' and call.message.chat.id==call.from_user.id:
            try:await gateway.owner_panel(call,note='❌ '+text)
            except sqlite3.Error:
                await host.safe_edit_or_answer(call,'⚠️ Pengaturan KlikQRIS belum dapat dibaca dari database. Coba kembali; transaksi tersimpan tetap dipertahankan.',reply_markup=gateway.owner_keyboard([[('⬅️ Kembali','back',None)]]))
        await host.safe_callback_notice(call,text[:190],show_alert=True)

    @router.callback_query(F.data=='owner:auto_qris')
    async def owner_entry(call,state):
        try:
            if not call.message or str(call.message.chat.type)!='private' or call.message.chat.id!=call.from_user.id:raise GatewayError('FORBIDDEN')
            gateway.require_owner(call.from_user.id)
            await state.clear()
            await gateway.owner_panel(call)
            await host.safe_callback_notice(call)
        except (GatewayError,sqlite3.Error) as exc:await failure(call,exc,owner=True)

    @router.callback_query(F.data.startswith('topupmethod:auto:'))
    async def topup_entry(call,state):
        try:
            parts=call.data.split(':')
            if len(parts)!=3 or not re.fullmatch(r'[0-9]{1,12}',parts[2]):raise GatewayError('INPUT')
            await host.safe_callback_notice(call)
            await gateway.topup(call,int(parts[2]),state)
        except (GatewayError,sqlite3.Error) as exc:await failure(call,exc)

    @router.callback_query(F.data.startswith(PREFIX))
    async def callback(call,state):
        owner=False
        try:
            if not call.message or str(call.message.chat.type)!='private' or call.message.chat.id!=call.from_user.id:raise GatewayError('FORBIDDEN')
            parts=str(call.data or '').split(':')
            if not 3<=len(parts)<=4:raise GatewayError('INPUT')
            scope,action=parts[1:3];value=parts[3] if len(parts)==4 else None
            owner=scope=='a'
            if owner:gateway.require_owner(call.from_user.id)
            elif scope!='u':raise GatewayError('INPUT')
            gateway.bot=call.bot
            ok,_=host.persistent_rate_limit(call.from_user.id,'autoqris_callback',limit=20,window_seconds=60)
            if not ok:raise GatewayError('RATE_LIMIT')
            await host.safe_callback_notice(call)
            if not owner:
                gateway.transaction(value,call.from_user.id)
                if action=='check':await gateway.show_status(call,value)
                elif action=='qr':await gateway.show_payment(call,value)
                elif action=='cancel':await gateway.cancel(call,value)
                else:raise GatewayError('INPUT')
                return
            if action!='my_pg_input':await state.clear()
            if action=='menu':await gateway.owner_panel(call)
            elif action=='reset_preview':await gateway.owner_reset_preview(call)
            elif action=='reset_commit':
                result=gateway.apply_history_reset(call.from_user.id,value)
                await gateway.owner_panel(call,note=str(result['count'])+' riwayat QRIS ditutup. QRIS dijeda; pilih Aktifkan saat siap memakai key aktif. Invoice provider tidak dibatalkan otomatis.')
            elif action=='connect':
                if gateway.settings()['mode']=='my_pg':
                    await state.set_state(AutoQRISAdminState.merchant_reference)
                    return await host.safe_edit_or_answer(call,'Kirim ID transaksi MY PG yang sudah ada pada merchant terhubung. Pemeriksaan hanya membaca API; tidak membuat tagihan percobaan. Jangan kirim token sesi atau cookie.',reply_markup=gateway.owner_keyboard([[('⬅️ Batal','menu',None)]]))
                await gateway.check_connection(call.from_user.id)
                await gateway.owner_panel(call,note='Pemeriksaan selesai; tidak ada transaksi dibuat.')
            elif action=='toggle':
                if value not in {'on','off'}:raise GatewayError('INPUT')
                if value=='on':await gateway.activate(call.from_user.id)
                else:gateway.change(call.from_user.id,'enabled',False)
                await gateway.owner_panel(call,note='KlikQRIS berhasil diaktifkan untuk membuat invoice pembayaran.' if value=='on' else 'KlikQRIS dinonaktifkan untuk pembayaran baru; transaksi berjalan tetap diperiksa.')
            elif action=='modes':
                await host.safe_edit_or_answer(call,'Pilih PG KlikQRIS untuk gateway biasa, lalu Aktifkan KlikQRIS. API dibuktikan melalui invoice pembayaran nyata. MY PG memerlukan merchant terhubung dan transaksi existing yang berhasil diverifikasi.',reply_markup=gateway.owner_keyboard([[('PG KlikQRIS • Gateway biasa','mode','gateway')],[('MY PG • verifikasi merchant','my_pg_input',None)],[('⬅️ Kembali','menu',None)]]))
            elif action=='mode':
                if value!='gateway':raise GatewayError('INPUT')
                gateway.change(call.from_user.id,'mode',value)
                await gateway.owner_panel(call)
            elif action=='my_pg_input':
                gateway.change(call.from_user.id,'mode','my_pg')
                await state.set_state(AutoQRISAdminState.merchant_reference)
                await host.safe_edit_or_answer(call,'Hubungkan merchant MY PG di dashboard terlebih dahulu. Kirim satu ID transaksi MY PG yang sudah ada untuk pemeriksaan API. Jangan kirim API Key, token sesi atau cookie. Mode MY PG dipilih dan pembelian baru dinonaktifkan. Verifikasi diperlukan sebelum aktivasi.',reply_markup=gateway.owner_keyboard([[('⬅️ Batal','menu',None)]]))
            elif action in {'history','pending'}:
                if value is None or not re.fullmatch(r'[0-9]{1,6}',value):raise GatewayError('INPUT')
                await gateway.owner_list(call,pending=action=='pending',page=int(value))
            elif action=='reconcile':
                await gateway.poll_once(force=True)
                await gateway.owner_list(call,pending=True)
            elif action=='detail':await gateway.owner_detail(call,value)
            elif action=='check':await gateway.show_status(call,value,admin=True)
            elif action=='credit_confirm':await gateway.owner_detail(call,value,confirm_credit=True)
            elif action=='credit':
                await gateway.credit_review(call.from_user.id,value)
                await gateway.owner_detail(call,value)
            elif action=='back':
                await host.safe_edit_or_answer(call,'💳 Pengaturan Pembayaran',reply_markup=host.qris_settings_menu())
            else:raise GatewayError('INPUT')
        except (GatewayError,sqlite3.Error) as exc:await failure(call,exc,owner=owner)

    @router.message(AutoQRISAdminState.merchant_reference,F.text & ~F.text.startswith('/') & ~F.text.in_(TEXT_MENU_ACTIONS))
    async def merchant_reference_input(message,state):
        if not host.is_owner(message.from_user.id) or str(message.chat.type)!='private' or message.chat.id!=message.from_user.id:
            return await message.answer('Akses ditolak.')
        try:
            await gateway.check_connection(message.from_user.id,my_pg_reference=reference((message.text or '').strip()))
            gateway.change(message.from_user.id,'mode','my_pg')
            await state.clear()
            await message.answer('MY PG berhasil diperiksa melalui transaksi existing. Mode dipilih; aktifkan pengajuan dari panel QRIS Otomatis bila diperlukan.',reply_markup=gateway.owner_keyboard([[('⚙️ QRIS Otomatis','menu',None)]]))
        except (GatewayError,sqlite3.Error) as exc:
            code=exc.code if isinstance(exc,GatewayError) else 'STORAGE'
            status=exc.http_status if isinstance(exc,GatewayError) else 0
            await message.answer('Kode: '+html.escape(str(code))+' • HTTP: '+str(status or '-')+'\nMY PG belum dapat diverifikasi. Periksa merchant terhubung dan ID transaksi yang benar, atau kembali ke gateway biasa.',reply_markup=gateway.owner_keyboard([[('⬅️ Kembali','menu',None)]]))
    return gateway
