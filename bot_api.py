"""Owner-managed partner API over the host's existing aiohttp server and wallet.

Keys are hashed, quotes bind prices, and orders bind a durable idempotency key.
No provider credentials, new wallet, payment gateway or network client lives here.
"""
import asyncio
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import sqlite3
import time
from datetime import datetime,timezone
from urllib.parse import urlparse

from aiohttp import web
from aiohttp.web_log import AccessLogger
from aiogram import F
from aiogram.fsm.state import State,StatesGroup
from aiogram.types import InlineKeyboardMarkup,InlineKeyboardButton,CopyTextButton

SCOPES=('products','otp','sosmed')
PREFIX='owner:api:'
MAX_BODY=16384


class APIError(Exception):
    def __init__(self,code,status=400,retry_after=0):
        self.code,self.status,self.retry_after=code,status,retry_after


def init_schema(conn):
    statements=[
        """CREATE TABLE IF NOT EXISTS partner_api_keys(
            id TEXT PRIMARY KEY,name TEXT NOT NULL,user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,token_prefix TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('ACTIVE','DISABLED','REVOKED')),
            scopes TEXT NOT NULL,rate_limit INTEGER NOT NULL CHECK(rate_limit BETWEEN 1 AND 120),
            created_by INTEGER NOT NULL,created_at REAL NOT NULL,last_used_at REAL,
            request_count INTEGER NOT NULL DEFAULT 0,rate_window INTEGER NOT NULL DEFAULT 0,
            rate_hits INTEGER NOT NULL DEFAULT 0,creation_nonce TEXT NOT NULL UNIQUE)""",
        """CREATE TABLE IF NOT EXISTS partner_api_quotes(
            id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,key_id TEXT NOT NULL,
            kind TEXT NOT NULL,native_quote TEXT NOT NULL DEFAULT '',total_idr INTEGER NOT NULL CHECK(total_idr>=0),
            payload TEXT NOT NULL DEFAULT '',expires_at REAL NOT NULL,created_at REAL NOT NULL,
            FOREIGN KEY(key_id) REFERENCES partner_api_keys(id))""",
        """CREATE TABLE IF NOT EXISTS partner_api_orders(
            id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,key_id TEXT NOT NULL,quote_id TEXT NOT NULL UNIQUE,
            idempotency_key TEXT NOT NULL,request_hash TEXT NOT NULL,kind TEXT NOT NULL,
            state TEXT NOT NULL,native_order_id INTEGER,error_code TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,updated_at REAL NOT NULL,UNIQUE(user_id,idempotency_key),
            FOREIGN KEY(key_id) REFERENCES partner_api_keys(id),FOREIGN KEY(quote_id) REFERENCES partner_api_quotes(id))""",
        """CREATE TABLE IF NOT EXISTS partner_api_audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT,actor_id INTEGER NOT NULL,key_id TEXT NOT NULL,
            action TEXT NOT NULL,created_at REAL NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS idx_partner_api_orders_user ON partner_api_orders(user_id,created_at)",
        "CREATE INDEX IF NOT EXISTS idx_partner_api_quotes_expiry ON partner_api_quotes(expires_at)",
    ]
    for statement in statements:conn.execute(statement)


def integer(value,minimum=1,maximum=9223372036854775807):
    if type(value) is str and re.fullmatch(r'[0-9]{1,19}',value):value=int(value)
    if type(value) is not int or not minimum<=value<=maximum:raise APIError('INVALID_INPUT')
    return value


class PartnerAccessLogger(AccessLogger):
    def log(self,request,response,duration):
        if request.path.startswith('/api/v1'):
            # Never log raw URLs, query strings, bodies or Authorization.
            self.logger.info('Partner API %s status=%s duration=%.3f',request.method,response.status,duration)
        else:super().log(request,response,duration)


class Manager:
    def __init__(self,host):self.host=host

    def rows(self,sql,args=()):
        conn=self.host.db()
        try:return [dict(row) for row in conn.execute(sql,args).fetchall()]
        finally:conn.close()

    def one(self,sql,args=()):
        rows=self.rows(sql,args)
        return rows[0] if rows else None

    def audit(self,conn,actor,key,action):
        conn.execute('INSERT INTO partner_api_audit(actor_id,key_id,action,created_at) VALUES(?,?,?,?)',
                     (actor,key,action,time.time()))

    def enabled(self):return self.host.get_setting('partner_api_enabled','0')=='1'

    def owner(self,actor):
        if not self.host.is_owner(actor):raise APIError('FORBIDDEN',403)

    def base_url(self):
        value=str(getattr(self.host,'PUBLIC_BASE_URL','') or '').rstrip('/')
        parsed=urlparse(value)
        if parsed.scheme=='https' and parsed.netloc and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment:
            return value+'/api/v1'
        return ''

    def create_key(self,actor,name,user_id,nonce,*,replace_id=None):
        self.owner(actor);user_id=integer(user_id)
        if not isinstance(name,str) or not 1<=len(name.strip())<=40:raise APIError('INVALID_INPUT')
        if not re.fullmatch(r'[a-f0-9]{24}',str(nonce)):raise APIError('INVALID_INPUT')
        conn=self.host.db()
        try:
            self.host.begin_immediate_retry(conn)
            previous=conn.execute('SELECT * FROM partner_api_keys WHERE creation_nonce=?',(nonce,)).fetchone()
            if previous:
                conn.rollback();return dict(previous),None
            profile=conn.execute('SELECT user_id FROM verified_users WHERE user_id=? AND active=1',(user_id,)).fetchone()
            if not profile or self.host.security_blocked(user_id):raise APIError('USER_NOT_REGISTERED')
            if conn.execute("SELECT COUNT(*) FROM partner_api_keys WHERE status!='REVOKED'").fetchone()[0]>=200:raise APIError('KEY_LIMIT',409)
            old=conn.execute('SELECT * FROM partner_api_keys WHERE id=?',(replace_id,)).fetchone() if replace_id else None
            if replace_id and (not old or old['status']=='REVOKED'):raise APIError('NOT_FOUND',404)
            if old and old['user_id']!=user_id:raise APIError('INVALID_INPUT')
            ident=secrets.token_hex(8);token='mby_'+ident+'.'+secrets.token_urlsafe(32)
            scopes=old['scopes'] if old else json.dumps(SCOPES)
            limit=old['rate_limit'] if old else 60
            conn.execute("""INSERT INTO partner_api_keys(id,name,user_id,token_hash,token_prefix,status,scopes,rate_limit,
                created_by,created_at,creation_nonce) VALUES(?,?,?,?,?,'ACTIVE',?,?,?,?,?)""",
                (ident,name.strip(),user_id,hashlib.sha256(token.encode()).hexdigest(),'mby_'+ident+'.…',scopes,limit,actor,time.time(),nonce))
            if old:
                conn.execute("UPDATE partner_api_keys SET status='REVOKED' WHERE id=?",(old['id'],))
                self.audit(conn,actor,old['id'],'ROTATE')
            self.audit(conn,actor,ident,'CREATE');conn.commit()
            return self.key(ident),token
        except BaseException:conn.rollback();raise
        finally:conn.close()

    def key(self,ident):
        row=self.one('SELECT * FROM partner_api_keys WHERE id=?',(ident,))
        if not row:raise APIError('NOT_FOUND',404)
        return row

    def change_key(self,actor,ident,action,value=None):
        self.owner(actor);conn=self.host.db()
        try:
            self.host.begin_immediate_retry(conn)
            key=conn.execute('SELECT * FROM partner_api_keys WHERE id=?',(ident,)).fetchone()
            if not key or key['status']=='REVOKED':raise APIError('NOT_FOUND',404)
            if action=='toggle':
                conn.execute('UPDATE partner_api_keys SET status=? WHERE id=?',('DISABLED' if key['status']=='ACTIVE' else 'ACTIVE',ident))
            elif action=='revoke':conn.execute("UPDATE partner_api_keys SET status='REVOKED' WHERE id=?",(ident,))
            elif action=='limit':conn.execute('UPDATE partner_api_keys SET rate_limit=? WHERE id=?',(integer(value,1,120),ident))
            elif action in SCOPES:
                scopes=set(json.loads(key['scopes']))
                if action in scopes:scopes.remove(action)
                else:scopes.add(action)
                conn.execute('UPDATE partner_api_keys SET scopes=? WHERE id=?',(json.dumps(sorted(scopes)),ident))
            else:raise APIError('INVALID_INPUT')
            self.audit(conn,actor,ident,action.upper());conn.commit()
        except BaseException:conn.rollback();raise
        finally:conn.close()

    def authenticate(self,request):
        values=request.headers.getall('Authorization',[])
        if len(values)!=1:raise APIError('INVALID_AUTH',401)
        match=re.fullmatch(r'(?i:Bearer) (mby_([a-f0-9]{16})\.[A-Za-z0-9_-]{43})',values[0])
        if not match:raise APIError('INVALID_AUTH',401)
        key=self.key_for_auth(match[2])
        if not key or not hmac.compare_digest(key['token_hash'],hashlib.sha256(match[1].encode()).hexdigest()):raise APIError('INVALID_AUTH',401)
        if key['status']!='ACTIVE' or self.host.security_blocked(key['user_id']):raise APIError('ACCESS_DISABLED',403)
        if not self.one('SELECT user_id FROM verified_users WHERE user_id=? AND active=1',(key['user_id'],)):raise APIError('ACCESS_DISABLED',403)
        now=time.time();window=int(now//60);conn=self.host.db()
        try:
            self.host.begin_immediate_retry(conn)
            current=conn.execute('SELECT status,rate_window,rate_hits,rate_limit FROM partner_api_keys WHERE id=?',(key['id'],)).fetchone()
            if current['status']!='ACTIVE':raise APIError('ACCESS_DISABLED',403)
            hits=current['rate_hits']+1 if current['rate_window']==window else 1
            if hits>current['rate_limit']:raise APIError('RATE_LIMIT',429,max(1,60-int(now%60)))
            conn.execute('UPDATE partner_api_keys SET rate_window=?,rate_hits=?,request_count=request_count+1,last_used_at=? WHERE id=?',(window,hits,now,key['id']))
            conn.commit()
        except BaseException:conn.rollback();raise
        finally:conn.close()
        return key

    def key_for_auth(self,ident):return self.one('SELECT * FROM partner_api_keys WHERE id=?',(ident,))

    def scope(self,key,kind):
        if kind not in SCOPES or kind not in json.loads(key['scopes']):raise APIError('SCOPE_DENIED',403)

    def new_purchase_guard(self,key):
        current=self.key(key['id'])
        if current['status']!='ACTIVE':raise APIError('ACCESS_DISABLED',403)
        if not self.enabled():raise APIError('API_CLOSED',503)
        if self.host.security_blocked(key['user_id']):raise APIError('ACCESS_DISABLED',403)
        if self.host.safe_mode_enabled() or self.host.maintenance_enabled():raise APIError('STORE_CLOSED',503)

    def wib(self,value):
        if value in (None,''):return None
        moment=datetime.fromtimestamp(value,timezone.utc) if isinstance(value,(int,float)) else self.host.parse_stored_datetime(value)
        return moment.astimezone(self.host.JAKARTA_TZ).isoformat(timespec='seconds') if moment else None

    def public(self,value,limit=180):return self.host.SOSMED_STORE.ui.public_label(str(value or ''),limit)

    def save_quote(self,key,kind,total,*,native='',payload=None,expires=None):
        ident='Q-'+secrets.token_hex(12);now=time.time()
        encrypted=self.host.OTP_STORE.encrypt(payload) if payload is not None else ''
        conn=self.host.db()
        try:
            conn.execute("""DELETE FROM partner_api_quotes WHERE id IN (
                SELECT q.id FROM partner_api_quotes q WHERE q.expires_at<?
                AND NOT EXISTS(SELECT 1 FROM partner_api_orders o WHERE o.quote_id=q.id) LIMIT 100)""",(now-86400,))
            conn.execute('INSERT INTO partner_api_quotes VALUES(?,?,?,?,?,?,?,?,?)',
                (ident,key['user_id'],key['id'],kind,native,integer(total,0),encrypted,expires or now+60,now));conn.commit()
        finally:conn.close()
        return self.quote(key,ident,kind,allow_expired=True)

    def quote(self,key,ident,kind=None,*,allow_expired=False):
        row=self.one('SELECT * FROM partner_api_quotes WHERE id=? AND user_id=?',(str(ident),key['user_id']))
        if not row or kind and row['kind']!=kind:raise APIError('NOT_FOUND',404)
        if not allow_expired and row['expires_at']<=time.time():raise APIError('QUOTE_EXPIRED',409)
        return row

    def quote_view(self,row):
        return {'quote_id':row['id'],'kind':row['kind'],'total_idr':row['total_idr'],'currency':'IDR',
                'expires_at':self.wib(row['expires_at']),'payment_method':'WALLET'}

    async def catalog(self,key,kind,query):
        self.scope(key,kind);page=integer(query.get('page','1'),1,1000);limit=integer(query.get('per_page','20'),1,50)
        search=str(query.get('search','')).strip()
        if len(search)>100:raise APIError('INVALID_INPUT')
        if kind=='products':
            conn=self.host.db()
            try:
                clause=self.host.product_available_sql('p')
                rows=conn.execute(f"""SELECT v.*,p.name AS product_name,p.fulfillment_mode,p.product_type
                    FROM product_variants v JOIN products p ON p.id=v.product_id
                    WHERE v.active=1 AND p.active=1 AND {clause}
                    AND (instr(lower(p.name),lower(?))>0 OR instr(lower(v.name),lower(?))>0)
                    ORDER BY p.name COLLATE NOCASE,v.name COLLATE NOCASE,v.id LIMIT ? OFFSET ?""",
                    (search,search,limit+1,(page-1)*limit)).fetchall()
                data=[{'variant_id':r['id'],'product_id':r['product_id'],'name':self.public(r['product_name']),
                    'variant':self.public(r['name']),'price_idr':int(self.host.effective_unit_price(r,1)),
                    'stock':self.host.available_stock(r),'quantity':1,
                    'requires_gmail':self.host.product_is_famhead(r),'preorder':self.host.product_is_preorder(r)} for r in rows[:limit]]
            finally:conn.close()
            more=len(rows)>limit
        elif kind=='otp':
            country=integer(query.get('country_id'));platform=integer(query.get('platform_id'))
            operator=integer(query['operator_id']) if query.get('operator_id') else None
            rows,more=await self.host.OTP_STORE.catalog.products(country,platform,operator,page,limit=limit)
            data=[]
            for row in rows:
                sale,_=self.host.OTP_STORE.pricing.calculate(row,row['price'])
                offer=self.save_quote(key,'otp_offer',sale,payload=row)
                data.append({'offer_id':offer['id'],'name':self.public(row.get('platform_name') or row.get('name')),
                    'country_id':country,'platform_id':platform,'operator_id':operator,
                    'price_idr':sale,'stock':row['available'],'expires_at':self.wib(offer['expires_at'])})
        else:
            store=self.host.SOSMED_STORE
            rows,total=store.catalog.listing(category=query.get('category'),query=search,page=page-1,page_size=limit,filters={'available':True})
            data=[]
            for row in rows:
                _,sale=store.pricing.rate(row)
                data.append({'service_id':row['provider_service_id'],'name':self.public(row['name']),
                    'category':self.public(row['category']),'min':row['min_quantity'],'max':row['max_quantity'],
                    'price_per_1000_idr':sale,'type':row['type'],
                    'target_type':self.host.sosmed_buzzerpanel.FormAdapter.target_kind(row)})
            more=page*limit<total
        return {'items':data,'page':page,'per_page':limit,'has_more':more,'currency':'IDR'}

    async def make_quote(self,key,body):
        kind=body.get('kind');self.scope(key,kind);self.new_purchase_guard(key)
        if kind=='products':
            if set(body)-{'kind','variant_id','quantity','family_gmail','note'}:raise APIError('INVALID_INPUT')
            variant=integer(body.get('variant_id'));integer(body.get('quantity',1),1,1)
            row=self.product(variant)
            gmail=str(body.get('family_gmail','')).strip();note=body.get('note','')
            if not isinstance(note,str) or len(note)>500 or '[famhead gmail]' in note.lower():raise APIError('INVALID_INPUT')
            if self.host.product_is_famhead(row) and not self.host.valid_family_gmail(gmail):raise APIError('GMAIL_REQUIRED')
            if gmail and not self.host.valid_family_gmail(gmail):raise APIError('INVALID_INPUT')
            if self.host.available_stock(row)<1:raise APIError('OUT_OF_STOCK',409)
            total=int(self.host.effective_unit_price(row,1))
            row=self.save_quote(key,kind,total,payload={'variant_id':variant,'family_gmail':gmail,'checkout_note':note})
        elif kind=='otp':
            if set(body)!={'kind','offer_id'}:raise APIError('INVALID_INPUT')
            offer=self.quote(key,body['offer_id'],'otp_offer')
            product=self.host.OTP_STORE.decrypt(offer['payload'])
            native=await self.host.OTP_STORE.purchase.quote(key['user_id'],product)
            row=self.save_quote(key,kind,native['selling_price_idr'],native=native['quote_id'],expires=native['expires_at'])
        else:
            if set(body)!={'kind','service_id','parameters'} or not isinstance(body['parameters'],dict):raise APIError('INVALID_INPUT')
            native=await self.host.SOSMED_STORE.purchase.quote(key['user_id'],integer(body['service_id']),body['parameters'])
            row=self.save_quote(key,kind,native['sale'],native=native['quote_id'],expires=native['expires_at'])
        return self.quote_view(row)

    def product(self,variant_id,conn=None):
        owned=conn is None;conn=conn or self.host.db()
        try:
            row=conn.execute(f"""SELECT v.*,p.name AS product_name,p.fulfillment_mode,p.product_type
                FROM product_variants v JOIN products p ON p.id=v.product_id
                WHERE v.id=? AND v.active=1 AND p.active=1 AND {self.host.product_available_sql('p')}""",(variant_id,)).fetchone()
            if not row:raise APIError('NOT_FOUND',404)
            return row
        finally:
            if owned:conn.close()

    def order(self,key,ident):
        row=self.one('SELECT * FROM partner_api_orders WHERE id=? AND user_id=?',(str(ident),key['user_id']))
        if not row:raise APIError('NOT_FOUND',404)
        self.scope(key,row['kind']);return row

    def native_order(self,row):
        kind=row['kind'];user=row['user_id']
        if kind=='products':
            return self.one('SELECT * FROM orders WHERE id=? AND user_id=?',(row['native_order_id'],user)),None
        quote=self.one('SELECT native_quote FROM partner_api_quotes WHERE id=?',(row['quote_id'],))
        if kind=='otp':
            attempt=self.one('SELECT * FROM otp_purchase_attempts WHERE quote_id=? AND user_id=?',(quote['native_quote'],user))
            native=self.one('SELECT * FROM otp_orders WHERE attempt_id=? AND buyer_user_id=?',(attempt['attempt_id'],user)) if attempt else None
        else:
            attempt=self.one('SELECT * FROM sosmed_purchase_attempts WHERE quote_id=? AND user_id=?',(quote['native_quote'],user))
            native=self.one('SELECT * FROM sosmed_orders WHERE attempt_id=? AND user_id=?',(attempt['attempt_id'],user)) if attempt else None
        return native,attempt

    def order_view(self,row):
        native,attempt=self.native_order(row)
        quote=self.one('SELECT total_idr,expires_at FROM partner_api_quotes WHERE id=?',(row['quote_id'],))
        data={'order_id':row['id'],'kind':row['kind'],'quote_id':row['quote_id'],
            'total_idr':quote['total_idr'],'currency':'IDR','created_at':self.wib(row['created_at']),
            'updated_at':self.wib(row['updated_at']),'status':row['state'],
            'error_code':row['error_code'] or None,'refunded_idr':0,'refund_status':'NONE','held_idr':0}
        if not native:
            if attempt:
                data['status']=attempt['state']
                if attempt['state'] in {'RESERVED','REQUESTING','PENDING_RECONCILIATION','RECONCILIATION_REQUIRED'}:
                    data['held_idr']=quote['total_idr']
                if attempt['state']=='FAILED':data['error_code']='ORDER_FAILED'
            elif row['state']=='PREPARED' and quote['expires_at']<=time.time():
                data.update(status='FAILED',error_code='QUOTE_EXPIRED')
            return data
        if row['kind']=='products':
            status=('COMPLETED' if native['fulfillment_status']=='delivered' and native['payment_status']=='paid'
                    else 'CANCELED' if native['status'] in {'canceled','cancelled','expired','rejected','refunded'}
                    else 'PROCESSING')
            data.update(status=status,invoice=self.host.invoice(native['id']),
                fulfillment_status=native['fulfillment_status'],payment_status=native['payment_status'],
                delivery_text=native['delivery_text'] if status=='COMPLETED' else None)
        elif row['kind']=='otp':
            data.update(status=native['status'],phone_number=native['phone_number'],
                expires_at=self.wib(native['expires_at']),refunded_idr=native['refund_idr'],
                refund_status=native['refund_state'],otp_code=None,sms_message=None)
            # Follow the native SMS retention and encryption. No OTP is inferred
            # from the phone, status, a prior order or provider error text.
            event=self.one('SELECT * FROM otp_sms_events WHERE provider_order_id=? ORDER BY sms_revision DESC LIMIT 1',(native['provider_order_id'],))
            if event and event['encrypted_payload'] and event['received_at']>=time.time()-self.host.OTP_STORE.config.retention_hours*3600:
                payload=self.host.OTP_STORE.decrypt(event['encrypted_payload'])
                data.update(otp_code=payload.get('otp_code'),sms_message=payload.get('otp_message'))
        else:
            data.update(status=native['status'],service_id=native['service_id'],
                service_name=self.public(native['service_name_snapshot']),target=native['target'],quantity=native['quantity'],
                start_count=native['start_count'],remains=native['remains'],
                refunded_idr=native['refund_amount'],refund_status=native['refund_state'])
        return data

    async def product_buy(self,key,row,quote,bot):
        payload=self.host.OTP_STORE.decrypt(quote['payload']);user=key['user_id']
        allowed,_=self.host.anti_abuse_checkout(user,'WALLET')
        if not allowed:raise APIError('CHECKOUT_RESTRICTED',403)
        allowed,retry=self.host.persistent_rate_limit(user,'checkout_payment',limit=5,window_seconds=30)
        if not allowed:raise APIError('RATE_LIMIT',429,retry)
        conn=self.host.db()
        try:
            self.host.begin_immediate_retry(conn)
            current=conn.execute('SELECT native_order_id FROM partner_api_orders WHERE id=?',(row['id'],)).fetchone()
            if current['native_order_id']:
                conn.rollback();return
            self.new_purchase_guard(key)
            variant=self.product(payload['variant_id'],conn)
            product=conn.execute('SELECT * FROM products WHERE id=?',(variant['product_id'],)).fetchone()
            total=int(self.host.effective_unit_price(variant,1))
            if total!=quote['total_idr']:raise APIError('PRICE_CHANGED',409)
            if quote['expires_at']<=time.time():raise APIError('QUOTE_EXPIRED',409)
            if self.host.product_is_famhead(product) and not self.host.valid_family_gmail(payload.get('family_gmail','')):raise APIError('GMAIL_REQUIRED')
            profile=conn.execute('SELECT username FROM verified_users WHERE user_id=?',(user,)).fetchone()
            native_id,_=self.host.commit_wallet_product_order(conn,user,str(profile['username'] or ''),product,variant,1,
                total,total,total,self.host.get_checkout_note_from_state(payload))
            conn.execute("UPDATE partner_api_orders SET native_order_id=?,state='PROCESSING',updated_at=? WHERE id=?",(native_id,time.time(),row['id']))
            conn.commit()
        except BaseException:conn.rollback();raise
        finally:conn.close()
        self.host.record_payment_event('order',native_id,'paid',total,user,'method=WALLET;source=PARTNER_API')
        # The existing fulfillment lease, inventory allocation, receipt, rating
        # and transaction-channel queue remain the sole delivery mechanism.
        await self.host.fulfill_order(native_id,bot)

    async def buy(self,key,body,idempotency,bot):
        if set(body)!={'quote_id'} or not re.fullmatch(r'[A-Za-z0-9_.:-]{8,80}',str(idempotency or '')):
            raise APIError('IDEMPOTENCY_REQUIRED')
        quote=self.quote(key,body['quote_id'],allow_expired=True);self.scope(key,quote['kind'])
        digest=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        conn=self.host.db()
        try:
            self.host.begin_immediate_retry(conn)
            previous=conn.execute('SELECT * FROM partner_api_orders WHERE user_id=? AND idempotency_key=?',(key['user_id'],idempotency)).fetchone()
            if previous:
                if previous['request_hash']!=digest:raise APIError('IDEMPOTENCY_CONFLICT',409)
                ident=previous['id'];conn.rollback()
            else:
                self.new_purchase_guard(key)
                if quote['expires_at']<=time.time():raise APIError('QUOTE_EXPIRED',409)
                if conn.execute('SELECT 1 FROM partner_api_orders WHERE quote_id=?',(quote['id'],)).fetchone():raise APIError('QUOTE_USED',409)
                ident='A-'+secrets.token_hex(12);now=time.time()
                conn.execute("""INSERT INTO partner_api_orders(id,user_id,key_id,quote_id,idempotency_key,request_hash,kind,state,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,'PREPARED',?,?)""",(ident,key['user_id'],key['id'],quote['id'],idempotency,digest,quote['kind'],now,now))
                conn.commit()
        except BaseException:conn.rollback();raise
        finally:conn.close()
        async with self.host.purchase_lock(key['user_id']):
            row=self.order(key,ident);native,attempt=self.native_order(row)
            if native or attempt or row['state']!='PREPARED':return self.order_view(row)
            try:
                self.new_purchase_guard(key)
                if quote['kind']=='products':await self.product_buy(key,row,quote,bot)
                elif quote['kind']=='otp':await self.host.OTP_STORE.purchase.buy(key['user_id'],quote['native_quote'])
                else:await self.host.SOSMED_STORE.purchase.buy(key['user_id'],quote['native_quote'])
            except asyncio.CancelledError:raise
            except Exception as exc:
                # A native attempt is the durable authority after an uncertain
                # POST. Never release its hold or make a replacement purchase.
                current=self.order(key,ident);native,attempt=self.native_order(current)
                if native or attempt:return self.order_view(current)
                code,status,retry=self.error_details(exc)
                self.update_order(ident,'FAILED',code)
                raise APIError(code,status,retry) from None
            self.update_order(ident,'PROCESSING','')
            return self.order_view(self.order(key,ident))

    def update_order(self,ident,state,error):
        conn=self.host.db()
        try:
            conn.execute('UPDATE partner_api_orders SET state=?,error_code=?,updated_at=? WHERE id=?',(state,error,time.time(),ident));conn.commit()
        finally:conn.close()

    async def read_order(self,key,ident,refresh=False):
        row=self.order(key,ident);native,_=self.native_order(row)
        refresh_error=None
        if refresh and native and row['kind'] in {'otp','sosmed'}:
            try:
                if row['kind']=='otp':
                    self.host.OTP_STORE.repo.rate(key['user_id'],'partner_status',30,60)
                    await self.host.OTP_STORE.orders.refresh(native)
                else:await self.host.SOSMED_STORE.orders.refresh(key['user_id'],native['id'])
            except Exception as exc:refresh_error=self.error_details(exc)[0]
        data=self.order_view(row)
        if refresh_error:data['refresh_error']=refresh_error
        return data

    async def cancel(self,key,ident):
        row=self.order(key,ident)
        if row['kind']!='otp':raise APIError('CANCEL_UNAVAILABLE',409)
        async with self.host.purchase_lock(key['user_id']):
            native,_=self.native_order(row)
            if not native:raise APIError('ORDER_UNCERTAIN',409)
            if native['status']=='CANCELED':return self.order_view(row)
            await self.host.OTP_STORE.orders.action(key['user_id'],native['id'],'cancel')
            return self.order_view(row)

    @staticmethod
    def error_details(exc):
        if isinstance(exc,APIError):return exc.code,exc.status,exc.retry_after
        code=getattr(exc,'code','')
        mapped={'USER_BALANCE':'INSUFFICIENT_BALANCE','PRICE_CHANGED':'PRICE_CHANGED','QUOTE_EXPIRED':'QUOTE_EXPIRED',
                'NO_OFFER_AVAILABLE':'OUT_OF_STOCK','INPUT':'INVALID_INPUT','INVALID_INPUT':'INVALID_INPUT',
                'CANCEL_TOO_EARLY':'CANCEL_TOO_EARLY','CONFLICT':'ACTION_UNAVAILABLE',
                'ACTIVE_LIMIT':'ACTIVE_LIMIT','ORDER_LIMIT':'ACTIVE_LIMIT','COOLDOWN':'RATE_LIMIT',
                'RATE_LIMIT':'RATE_LIMIT','NOT_FOUND':'NOT_FOUND','OUT_OF_STOCK':'OUT_OF_STOCK',
                'INSUFFICIENT_BALANCE':'INSUFFICIENT_BALANCE','PAYMENT_METHOD':'ORDER_FAILED','DUPLICATE':'ORDER_UNCERTAIN'}
        value=mapped.get(code,'SERVICE_UNAVAILABLE')
        status=429 if value=='RATE_LIMIT' else 404 if value=='NOT_FOUND' else 409 if value in {'PRICE_CHANGED','QUOTE_EXPIRED','OUT_OF_STOCK','INSUFFICIENT_BALANCE','ACTIVE_LIMIT','ACTION_UNAVAILABLE','CANCEL_TOO_EARLY','ORDER_UNCERTAIN'} else 400 if value=='INVALID_INPUT' else 503
        return value,status,int(max(0,getattr(exc,'retry_after',0) or 0))

    async def body(self,request):
        if request.content_type!='application/json':raise APIError('JSON_REQUIRED',415)
        if request.content_length and request.content_length>MAX_BODY:raise APIError('BODY_TOO_LARGE',413)
        raw=bytearray()
        try:
            async with asyncio.timeout(10):
                async for chunk in request.content.iter_chunked(2048):
                    raw.extend(chunk)
                    if len(raw)>MAX_BODY:raise APIError('BODY_TOO_LARGE',413)
        except asyncio.TimeoutError:raise APIError('BODY_TIMEOUT',408) from None
        try:
            def unique(pairs):
                data={}
                for name,value in pairs:
                    if name in data:raise ValueError('Duplicate JSON key')
                    data[name]=value
                return data
            data=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda value:(_ for _ in ()).throw(ValueError('Non-finite JSON')))
        except (ValueError,UnicodeError,RecursionError):raise APIError('INVALID_JSON') from None
        if not isinstance(data,dict):raise APIError('INVALID_JSON')
        return data

    async def handle(self,request):
        request_id=secrets.token_hex(8);status=200;headers={'Cache-Control':'no-store, private','Pragma':'no-cache'}
        try:
            key=self.authenticate(request)
            if any(k.lower() in {'api_key','apikey','token','authorization'} for k in request.query):raise APIError('AUTH_HEADER_REQUIRED')
            route=request.match_info.get('operation','');kind=request.match_info.get('kind','')
            if route=='balance':data={'user_id':key['user_id'],'balance_idr':self.host.get_balance(key['user_id']),'currency':'IDR'}
            elif route=='catalog':data=await self.catalog(key,kind,request.query)
            elif route=='otp_meta':
                self.scope(key,'otp');resource=request.match_info['resource']
                if resource not in {'countries','platforms','operators'}:raise APIError('NOT_FOUND',404)
                path={'countries':'countries','platforms':'services','operators':'operators'}[resource]
                params={k:integer(request.query[k]) for k in ('country_id','platform_id') if k in request.query}
                rows=await self.host.OTP_STORE.catalog.listing('/catalog/'+path,params or None)
                rows=self.host.OTP_STORE.catalog.named_rows(rows,operators=resource=='operators')
                data={'items':[{'id':r.get('operator_id') if resource=='operators' else r['id'],'name':self.public(r['name'])} for r in rows]}
            elif route=='quote':data=await self.make_quote(key,await self.body(request));status=201
            elif route=='buy':
                data=await self.buy(key,await self.body(request),request.headers.get('Idempotency-Key'),request.app['bot'])
                status=202 if data['status'] in {'PREPARED','RESERVED','REQUESTING','PENDING_RECONCILIATION','RECONCILIATION_REQUIRED'} else 200
            elif route=='order':data=await self.read_order(key,request.match_info['ident'],request.query.get('refresh')=='1')
            elif route=='orders':
                page=integer(request.query.get('page','1'),1,1000);limit=integer(request.query.get('per_page','20'),1,50)
                rows=self.rows('SELECT * FROM partner_api_orders WHERE user_id=? ORDER BY created_at DESC,id LIMIT ? OFFSET ?',(key['user_id'],limit+1,(page-1)*limit))
                summaries=[]
                for row in rows[:limit]:
                    if row['kind'] not in json.loads(key['scopes']):continue
                    summary=self.order_view(row)
                    summaries.append({k:v for k,v in summary.items() if k not in {'delivery_text','phone_number','otp_code','sms_message','target'}})
                data={'items':summaries,
                      'page':page,'per_page':limit,'has_more':len(rows)>limit}
            elif route=='cancel':
                body=await self.body(request)
                if body:raise APIError('INVALID_INPUT')
                data=await self.cancel(key,request.match_info['ident'])
            else:data={'service':'Maboyy Digital','api_version':'v1','new_orders_enabled':self.enabled(),
                       'scopes':json.loads(key['scopes']),'payment_method':'WALLET','currency':'IDR'}
            result={'success':True,'data':data,'request_id':request_id}
        except asyncio.CancelledError:raise
        except Exception as exc:
            code,status,retry=self.error_details(exc)
            if retry:headers['Retry-After']=str(max(1,retry))
            result={'success':False,'error':{'code':code},'request_id':request_id}
            logging.warning('Partner API request=%s error=%s cause=%s',request_id,code,type(exc).__name__)
        return web.json_response(result,status=status,headers=headers)

    def add_routes(self,app):
        # Operations are route defaults, never client-controlled query fields.
        async def bind(request,operation,**values):
            request.match_info.update(operation=operation,**values)
            return await self.handle(request)
        async def root(r):return await bind(r,'root')
        async def balance(r):return await bind(r,'balance')
        async def products(r):return await bind(r,'catalog',kind='products')
        async def otp(r):return await bind(r,'catalog',kind='otp')
        async def smm(r):return await bind(r,'catalog',kind='sosmed')
        async def meta(r):return await bind(r,'otp_meta')
        async def quote(r):return await bind(r,'quote')
        async def buy(r):return await bind(r,'buy')
        async def orders(r):return await bind(r,'orders')
        async def order(r):return await bind(r,'order')
        async def cancel(r):return await bind(r,'cancel')
        for verb,path,handler in [
            ('GET','',root),('GET','/balance',balance),('GET','/products',products),
            ('GET','/otp/services',otp),('GET','/otp/{resource:countries|platforms|operators}',meta),
            ('GET','/sosmed/services',smm),('POST','/quotes',quote),('POST','/orders',buy),
            ('GET','/orders',orders),('GET','/orders/{ident}',order),('POST','/orders/{ident}/cancel',cancel)]:
            app.router.add_route(verb,'/api/v1'+path,handler)

    def keyboard(self,rows):
        return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=label,callback_data=PREFIX+action) for label,action in row] for row in rows])

    async def panel(self,call):
        count=self.one("SELECT COUNT(*) n FROM partner_api_keys WHERE status='ACTIVE'")['n']
        base=self.base_url()
        text=('🔑 <b>API BOT — MABOYY DIGITAL</b>\n\n'
            +f"Pembelian API: <b>{'AKTIF' if self.enabled() else 'NONAKTIF'}</b>\nAPI key aktif: <b>{count}</b>\n"
            +'Endpoint: '+('<code>'+html.escape(base)+'</code>' if base else 'Isi PUBLIC_BASE_URL HTTPS existing di Railway.')
            +'\n\nLayanan: Produk, OTP, SOSMED.\nSetiap key memakai saldo akun Telegram yang dipilih. '
            +'Harga mengikuti harga jual toko. Key bukan token bot Telegram.\n'
            +'Menutup pembelian tidak menghapus transaksi berjalan; key aktif tetap dapat memeriksa pesanan.')
        rows=[[('➕ Buat API Key','create'),('📋 Daftar API Key','list:0')],
              [('🔴 Tutup Pembelian' if self.enabled() else '🟢 Buka Pembelian','global')],
              [('📊 Aktivitas','audit'),('📘 Panduan API','docs')]]
        keyboard=self.keyboard(rows)
        keyboard.inline_keyboard.append([InlineKeyboardButton(text='🔙 Owner',callback_data='owner:panel')])
        return await self.host.safe_edit_or_answer(call,text,reply_markup=keyboard,parse_mode='HTML')

    async def list_keys(self,call,page=0):
        page=integer(page,0,1000)
        rows=self.rows('SELECT id,name,status FROM partner_api_keys ORDER BY created_at DESC,id LIMIT 11 OFFSET ?',(page*10,))
        buttons=[[(('🟢' if r['status']=='ACTIVE' else '⚫' if r['status']=='REVOKED' else '🔴')+' '+r['name'],'key:'+r['id'])] for r in rows[:10]]
        nav=[]
        if page:nav.append(('⬅️','list:'+str(page-1)))
        if len(rows)>10:nav.append(('➡️','list:'+str(page+1)))
        if nav:buttons.append(nav)
        buttons.append([('🔙 API Bot','menu')])
        return await self.host.safe_edit_or_answer(call,'📋 <b>API KEY MITRA</b>\nPilih key untuk mengatur akses. Key rahasia tidak ditampilkan ulang.',reply_markup=self.keyboard(buttons),parse_mode='HTML')

    async def key_panel(self,call,ident):
        row=self.key(ident);scopes=json.loads(row['scopes'])
        text=(f"🔑 <b>{html.escape(row['name'])}</b>\n\nUser ID: <code>{row['user_id']}</code>\n"
            +f"Key: <code>{row['token_prefix']}</code>\nStatus: {row['status']}\n"
            +f"Limit: {row['rate_limit']}/menit\nRequest: {row['request_count']}\n"
            +'Terakhir: '+html.escape(self.host.format_wib_datetime(self.wib(row['last_used_at'])))
            +'\n\nSaldo memakai akun tersebut. Menonaktifkan/mencabut key tidak membatalkan pesanan atau mengubah saldo.')
        rows=[]
        if row['status']!='REVOKED':
            rows=[[('🔴 Nonaktifkan' if row['status']=='ACTIVE' else '🟢 Aktifkan','toggle:'+ident),('🔄 Ganti Key','rotate:'+ident)],
                  [('⚙️ Atur Limit','limit:'+ident),('🗑 Cabut Permanen','revoke:'+ident)]]
            rows.extend([[(('✅ ' if scope in scopes else '❌ ')+scope.upper(),'scope_'+scope+':'+ident)] for scope in SCOPES])
        rows.extend([[('📦 Transaksi Key','orders:'+ident)],[('🔙 Daftar','list:0')]])
        return await self.host.safe_edit_or_answer(call,text,reply_markup=self.keyboard(rows),parse_mode='HTML')

    async def reveal(self,call,row,token):
        if token is None:
            return await self.host.safe_callback_notice(call,'Key sudah dibuat. Rahasia hanya ditampilkan sekali; gunakan Ganti Key jika belum tersimpan.',show_alert=True)
        keyboard=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text='SALIN API KEY',copy_text=CopyTextButton(text=token))],
            [InlineKeyboardButton(text='🔙 Pengaturan Key',callback_data=PREFIX+'key:'+row['id'])]])
        await call.bot.send_message(call.from_user.id,
            '🔑 <b>API KEY BARU</b>\n\n'+f"Mitra: {html.escape(row['name'])}\nUser ID: <code>{row['user_id']}</code>\n"
            +'<code>'+token+'</code>\n\nSimpan sebagai secret di bot mitra. Ditampilkan sekali; server hanya menyimpan hash. '
            +'Jangan memasang key di URL, source publik atau chat user. Key ini bukan BOT_TOKEN Telegram.',
            reply_markup=keyboard,parse_mode='HTML',protect_content=True)


class APIState(StatesGroup):
    create=State()
    limit=State()
    confirm=State()


def register(router,manager):
    host=manager.host

    async def authorized(event):
        message=getattr(event,'message',None) or event
        chat=getattr(message,'chat',None);uid=getattr(getattr(event,'from_user',None),'id',None)
        if not host.is_owner(uid) or not chat or str(chat.type)!='private' or chat.id!=uid:
            if getattr(event,'data',None) is not None:await host.safe_callback_notice(event,'Khusus owner melalui chat privat bot.',show_alert=True)
            else:await event.answer('Khusus owner melalui chat privat bot.')
            return False
        return True

    @router.callback_query(F.data.startswith(PREFIX))
    async def partner_api_owner(call,state):
        if not await authorized(call):return
        await host.safe_callback_notice(call)
        action=str(call.data)[len(PREFIX):]
        try:
            if action=='confirm':
                saved=(await state.get_data()).get('partner_api_pending')
                if await state.get_state()!=APIState.confirm.state or not isinstance(saved,dict):raise APIError('SESSION_EXPIRED',409)
                if saved['action']=='create':
                    row,token=manager.create_key(call.from_user.id,saved['name'],saved['user_id'],saved['nonce'])
                    await state.clear();await manager.reveal(call,row,token);return
                if saved['action']=='global':
                    if saved['value'] and not manager.base_url():raise APIError('HTTPS_URL_REQUIRED')
                    host.set_setting('partner_api_enabled','1' if saved['value'] else '0')
                    conn=host.db()
                    try:manager.audit(conn,call.from_user.id,'','API_ON' if saved['value'] else 'API_OFF');conn.commit()
                    finally:conn.close()
                    await state.clear();return await manager.panel(call)
                row=manager.key(saved['ident'])
                if saved['action']=='rotate':
                    row,token=manager.create_key(call.from_user.id,row['name'],row['user_id'],saved['nonce'],replace_id=row['id'])
                    await state.clear();await manager.reveal(call,row,token);return
                # Confirmation binds the old record, avoiding stale double
                # clicks toggling a newly changed key back to its old setting.
                if row['status']!=saved['status'] or row['scopes']!=saved['scopes']:raise APIError('STATE_CHANGED',409)
                manager.change_key(call.from_user.id,row['id'],saved['action'],saved.get('value'))
                await state.clear();return await manager.key_panel(call,row['id'])
            if action=='menu':await state.clear();return await manager.panel(call)
            if action=='create':
                await state.clear();await state.set_state(APIState.create)
                return await host.safe_edit_or_answer(call,'➕ <b>BUAT API KEY</b>\n\nKirim nama mitra dan User ID Telegram dalam satu pesan.\n'
                    'Contoh: <code>Bot Toko Dua | 123456789</code>\n\nAkun mitra harus pernah membuka /start. '
                    'Saldo akun itu yang dipakai. Jangan kirim token bot atau API key provider.',reply_markup=manager.keyboard([[('🔙 Batal','menu')]]),parse_mode='HTML')
            if action.startswith('list:'):return await manager.list_keys(call,integer(action.split(':')[1],0,1000))
            if action.startswith('key:'):return await manager.key_panel(call,action.split(':')[1])
            if action=='docs':
                text=('📘 <b>PANDUAN API MITRA</b>\n\nEndpoint: <code>'+html.escape(manager.base_url() or 'PUBLIC_BASE_URL/api/v1')+'</code>\n'
                    'Header: <code>Authorization: Bearer API_KEY_MITRA</code>\nContent-Type: application/json\n\n'
                    '<code>GET /balance</code> — saldo akun mitra\n<code>GET /products</code> — produk/variasi A–Z\n'
                    '<code>GET /otp/countries</code>, <code>/otp/platforms</code>\n'
                    '<code>GET /otp/services?country_id=…&amp;platform_id=…</code>\n'
                    '<code>GET /sosmed/services?search=tiktok</code>\n'
                    '<code>POST /quotes</code> — harga yang harus disetujui\n<code>POST /orders</code> — beli memakai quote_id\n'
                    '<code>GET /orders/ORDER_ID?refresh=1</code> — status/hasil\n<code>POST /orders/ORDER_ID/cancel</code> — batal OTP sesuai izin layanan\n\n'
                    'Pembelian wajib header <code>Idempotency-Key</code> unik. Saat timeout, ulang dengan key dan quote_id yang sama; '
                    'jangan membuat order pengganti. Harga SOSMED per 1.000; total dihitung server. '
                    'Pembayaran hanya saldo existing. Lengkap: README dan API_BOT_GUIDE.md dalam paket source.')
                return await host.safe_edit_or_answer(call,text,reply_markup=manager.keyboard([[('🔙 API Bot','menu')]]),parse_mode='HTML')
            if action=='audit':
                rows=manager.rows('SELECT action,key_id,created_at FROM partner_api_audit ORDER BY id DESC LIMIT 12')
                text='📊 <b>AKTIVITAS API</b>\n\n'+'\n'.join(html.escape(r['action']+' · '+(r['key_id'] or 'API')+' · '+host.format_wib_datetime(manager.wib(r['created_at']))) for r in rows)
                return await host.safe_edit_or_answer(call,text,reply_markup=manager.keyboard([[('🔙 API Bot','menu')]]),parse_mode='HTML')
            if action.startswith('orders:'):
                ident=action.split(':')[1];manager.key(ident)
                rows=manager.rows('SELECT * FROM partner_api_orders WHERE key_id=? ORDER BY created_at DESC LIMIT 10',(ident,))
                lines=[]
                for row in rows:
                    view=manager.order_view(row)
                    lines.append(html.escape(row['id']+' · '+row['kind']+' · '+view['status']+' · '+host.rupiah(view['total_idr'])))
                return await host.safe_edit_or_answer(call,'📦 <b>TRANSAKSI API</b>\n\n'+('\n'.join(lines) or 'Belum ada transaksi.'),reply_markup=manager.keyboard([[('🔙 Key','key:'+ident)]]),parse_mode='HTML')
            if action=='global':
                pending={'action':'global','value':not manager.enabled()}
                text='Ubah pembelian API dari '+('AKTIF ke NONAKTIF' if manager.enabled() else 'NONAKTIF ke AKTIF')+'?\nTransaksi dan saldo tetap mengikuti data existing.'
            else:
                verb,ident=action.split(':',1);row=manager.key(ident)
                if row['status']=='REVOKED':raise APIError('NOT_FOUND',404)
                pending={'action':verb,'ident':ident,'status':row['status'],'scopes':row['scopes'],'nonce':secrets.token_hex(12)}
                if verb=='limit':
                    await state.set_state(APIState.limit);await state.update_data(partner_api_pending=pending)
                    return await host.safe_edit_or_answer(call,f"Limit lama: {row['rate_limit']}/menit.\nKirim limit baru 1–120 request/menit.",reply_markup=manager.keyboard([[('🔙 Batal','key:'+ident)]]))
                if verb.startswith('scope_'):pending['action']=verb[6:]
                elif verb not in {'toggle','revoke','rotate'}:raise APIError('INVALID_INPUT')
                text='Konfirmasi perubahan '+pending['action']+' untuk '+row['name']+'\nStatus lama: '+row['status']+'\nAkses lama: '+', '.join(json.loads(row['scopes']))
                if verb=='rotate':text+='\nKey lama akan dicabut setelah key baru berhasil dibuat.'
                if verb=='revoke':text+='\nPencabutan permanen. Pesanan berjalan tidak dibatalkan.'
            await state.set_state(APIState.confirm);await state.update_data(partner_api_pending=pending)
            return await host.safe_edit_or_answer(call,html.escape(text),reply_markup=manager.keyboard([[('✅ Simpan','confirm'),('🔙 Batal','menu')]]),parse_mode='HTML')
        except (APIError,ValueError,IndexError):
            return await host.safe_callback_notice(call,'Data/sesi belum valid. Buka ulang menu API; tidak ada perubahan saldo.',show_alert=True)
        except sqlite3.Error:
            logging.warning('Partner API owner storage unavailable')
            return await host.safe_callback_notice(call,'Pengaturan belum dapat disimpan. Coba kembali nanti.',show_alert=True)

    @router.message(APIState.create,F.text,~F.text.startswith('/'))
    async def partner_api_create_input(message,state):
        if not await authorized(message):return
        try:
            name,target=message.text.rsplit('|',1);name=name.strip();uid=integer(target.strip())
            if not 1<=len(name)<=40 or not manager.one('SELECT user_id FROM verified_users WHERE user_id=? AND active=1',(uid,)):raise APIError('INVALID_INPUT')
            pending={'action':'create','name':name,'user_id':uid,'nonce':secrets.token_hex(12)}
            await state.set_state(APIState.confirm);await state.update_data(partner_api_pending=pending)
            await message.answer('🔑 <b>KONFIRMASI API KEY</b>\n\nNama: '+html.escape(name)+f'\nUser ID: <code>{uid}</code>\n'
                +'Akses: Produk, OTP, SOSMED\nLimit: 60/menit\nSaldo: akun tersebut.\nKey hanya ditampilkan sekali setelah disimpan.',
                reply_markup=manager.keyboard([[('✅ Buat Key','confirm'),('🔙 Batal','menu')]]),parse_mode='HTML')
        except (APIError,ValueError):await message.answer('Format belum sesuai. Kirim Nama Mitra | User ID. Akun tersebut harus pernah membuka /start.',reply_markup=manager.keyboard([[('🔙 Batal','menu')]]))

    @router.message(APIState.limit,F.text,~F.text.startswith('/'))
    async def partner_api_limit_input(message,state):
        if not await authorized(message):return
        try:
            limit=integer(message.text.strip(),1,120);pending=(await state.get_data()).get('partner_api_pending')
            if not isinstance(pending,dict) or pending.get('action')!='limit':raise APIError('SESSION_EXPIRED')
            row=manager.key(pending['ident']);pending['value']=limit
            await state.set_state(APIState.confirm);await state.update_data(partner_api_pending=pending)
            await message.answer(f"Konfirmasi limit API {html.escape(row['name'])}:\nLama: {row['rate_limit']}/menit\nBaru: {limit}/menit",
                reply_markup=manager.keyboard([[('✅ Simpan','confirm'),('🔙 Batal','key:'+row['id'])]]),parse_mode='HTML')
        except (APIError,ValueError):await message.answer('Limit harus angka 1–120 request/menit.')

    return manager
