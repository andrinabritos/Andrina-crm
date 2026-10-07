#!/usr/bin/env python3
"""CRM operativo. Python 3.12+, SQLite. Ejecutar detrás de HTTPS en producción."""
import argparse, base64, hashlib, hmac, json, os, secrets, sqlite3, time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from getpass import getpass
ROOT = Path(__file__).resolve().parent
DB = Path(os.environ.get('CRM_DB', str(ROOT / 'data' / 'crm.sqlite3')))
ORIGIN = os.environ.get('APP_ORIGIN', 'http://localhost:8000').rstrip('/')
SECURE = ORIGIN.startswith('https://')
STATUSES = ['Pendiente','En curso','En revisión','Bloqueada','Completada']
WORKFLOW = ['Idea','Guion','Producción','Diseño / Edición','Revisión interna','Cliente','Correcciones','Aprobado','Programado','Publicado']

def connect():
    db = sqlite3.connect(DB, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db

def init():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','team')),password TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT REFERENCES users(id) ON DELETE CASCADE,csrf TEXT NOT NULL,expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts(key TEXT PRIMARY KEY,count INTEGER NOT NULL,started REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,client_id TEXT NOT NULL REFERENCES clients(id),assignee_id TEXT NOT NULL REFERENCES users(id),data TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS comments(id TEXT PRIMARY KEY,task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,user_id TEXT REFERENCES users(id),text TEXT NOT NULL,created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY,task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,user_id TEXT REFERENCES users(id),text TEXT NOT NULL,snapshot TEXT NOT NULL,created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),data TEXT NOT NULL);
        INSERT OR IGNORE INTO settings VALUES(1,'{"name":"Andrina Studio","accent":"#d9f36a","secondary":"#c8b8f2","avatar":""}');
        ''')
    os.chmod(DB, 0o600)

def uid(): return secrets.token_hex(12)
def now(): return datetime.now(timezone.utc).isoformat()
def dump(v): return json.dumps(v, ensure_ascii=False)
def password_hash(password):
    salt = secrets.token_bytes(16)
    return base64.b64encode(salt + hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)).decode()
def password_ok(password, stored):
    raw = base64.b64decode(stored)
    return hmac.compare_digest(raw[16:], hashlib.pbkdf2_hmac('sha256', password.encode(), raw[:16], 600000))
DUMMY_HASH = password_hash(secrets.token_hex(24))
class Error(Exception):
    def __init__(self, message, code=400): self.message, self.code = message, code

def textfield(data,key,limit=500,required=False):
    value = data.get(key,'')
    if not isinstance(value,str) or len(value)>limit: raise Error(f'Campo inválido: {key}')
    value=value.strip()
    if required and not value: raise Error(f'Completá el campo {key}.')
    return value

def datefield(data,key):
    s=textfield(data,key,10)
    if s:
        try: datetime.strptime(s,'%Y-%m-%d')
        except ValueError: raise Error('Fecha inválida.')
    return s

def passwordfield(data):
    value=data.get('password','')
    if not isinstance(value,str) or not 1<=len(value)<=1000: raise Error('Contraseña inválida.')
    return value

def taskdata(d,db):
    out={k:textfield(d,k,lim,k=='title') for k,lim in [('title',180),('description',15000),('script',20000),('copy',20000),('blocker',2000),('priorityReason',2000),('clientId',60),('assigneeId',60),('format',80),('platform',80)]}
    for key, choices, default in [('kind',['Tarea','Contenido'],'Tarea'),('status',STATUSES,'Pendiente'),('stage',WORKFLOW,'Idea'),('priority',['Planificable','Próximo','Prioritario','Crítico'],'Planificable')]:
        out[key]=d.get(key,default)
        if out[key] not in choices: raise Error(f'{key} inválido.')
    out['due']=datefield(d,'due');out['publishDate']=datefield(d,'publishDate')
    for key,default in [('rounds',0),('roundLimit',2)]:
        v=d.get(key,default)
        if type(v)!=int or not 0<=v<=100: raise Error('Cantidad de correcciones inválida.')
        out[key]=v
    if out['priority'] in ['Crítico','Prioritario'] and not out['priorityReason']: raise Error('Indicá el motivo de la prioridad.')
    if out['status']=='Bloqueada' and not out['blocker']: raise Error('Indicá qué falta para continuar.')
    out['links']=d.get('links',[])
    if not isinstance(out['links'],list) or len(out['links'])>20: raise Error('Máximo 20 enlaces.')
    for link in out['links']:
        if not isinstance(link,str) or len(link)>2000 or urlparse(link).scheme not in ['https','http'] or not urlparse(link).netloc: raise Error('Usá enlaces http o https completos.')
    if not db.execute('SELECT 1 FROM clients WHERE id=?',(out['clientId'],)).fetchone(): raise Error('Cliente inexistente.')
    if not db.execute('SELECT 1 FROM users WHERE id=? AND active=1',(out['assigneeId'],)).fetchone(): raise Error('Responsable inexistente o desactivado.')
    return out

def serialize(row):
    return dict(json.loads(row['data']), id=row['id'],version=row['version'])
def log(db,task,user,message,data): db.execute('INSERT INTO activity(task_id,user_id,text,snapshot,created) VALUES(?,?,?,?,?)',(task,user,message,dump(data),now()))

class Handler(BaseHTTPRequestHandler):
    server_version='AndrinaCRM'
    def setup(self):
        super().setup();self.connection.settimeout(20)
    def log_message(self,*args): pass
    def response(self,value,code=200,cookie=None):
        payload=dump(value).encode();self.send_response(code);self.send_header('Content-Type','application/json; charset=utf-8');self.headers_common()
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(payload)
    def headers_common(self):
        self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','same-origin')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors "+os.environ.get('FRAME_ANCESTORS',"'self'"))
    def cookie(self,token='',clear=False): return f'crm_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={0 if clear else 43200}'+('; Secure' if SECURE else '')
    def body(self):
        try: n=int(self.headers.get('Content-Length',0))
        except ValueError: raise Error('Solicitud inválida.')
        if n<0 or n>120000: raise Error('Solicitud demasiado grande.',413)
        try: data=json.loads(self.rfile.read(n))
        except (ValueError,UnicodeDecodeError): raise Error('JSON inválido.')
        if not isinstance(data,dict): raise Error('Solicitud inválida.')
        return data
    def auth(self,db,write=False):
        c=SimpleCookie()
        try:c.load(self.headers.get('Cookie',''))
        except Exception:raise Error('Iniciá sesión.',401)
        token=c.get('crm_session');key=hashlib.sha256(token.value.encode()).hexdigest() if token else ''
        row=db.execute('SELECT users.*,sessions.csrf FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>? AND active=1',(key,time.time())).fetchone()
        if not row:raise Error('Iniciá sesión.',401)
        if write and (self.headers.get('Origin')!=ORIGIN or not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),row['csrf'])):raise Error('Verificación de seguridad fallida. Recargá la página.',403)
        return row,key
    def admin(self,user):
        if user['role']!='admin':raise Error('Solo administración puede realizar esta acción.',403)
    def owned(self,db,user,id):
        row=db.execute('SELECT * FROM tasks WHERE id=?',(id,)).fetchone()
        if not row or (user['role']!='admin' and row['assignee_id']!=user['id']):raise Error('Tarea no disponible.',404)
        return row
    def do_GET(self):
        try:
            path=urlparse(self.path).path
            if path.startswith('/api/'):
                with connect() as db:
                    user,key=self.auth(db)
                    if path=='/api/state':
                        rows=db.execute('SELECT * FROM tasks'+('' if user['role']=='admin' else ' WHERE assignee_id=?'),() if user['role']=='admin' else (user['id'],)).fetchall()
                        taskids={r['id'] for r in rows};clientids={r['client_id'] for r in rows}
                        clients=[dict(json.loads(r['data']),id=r['id']) for r in db.execute('SELECT * FROM clients') if user['role']=='admin' or r['id'] in clientids]
                        if user['role']!='admin': clients=[{k:c[k] for k in ['id','name','plan','memory']} for c in clients]
                        comments=[dict(r) for r in db.execute('SELECT comments.*,users.name AS author FROM comments JOIN users ON users.id=comments.user_id') if r['task_id'] in taskids]
                        activity=[{k:r[k] for k in ['id','task_id','text','created','author']} for r in db.execute('SELECT activity.*,users.name AS author FROM activity JOIN users ON users.id=activity.user_id ORDER BY id DESC LIMIT 5000') if r['task_id'] in taskids]
                        users=[dict(r) for r in db.execute('SELECT id,name,email,role,active FROM users') if user['role']=='admin' or r['id']==user['id']]
                        self.response({'user':{k:user[k] for k in ['id','name','email','role']},'csrf':user['csrf'],'tasks':[serialize(r) for r in rows],'clients':clients,'users':users,'comments':comments,'activity':activity,'settings':json.loads(db.execute('SELECT data FROM settings').fetchone()[0])});return
                    if path=='/api/export':
                        self.admin(user)
                        self.response({table:[dict(r) for r in db.execute('SELECT * FROM '+table)] for table in ['clients','tasks','comments','activity','settings']});return
                    raise Error('Ruta inexistente.',404)
            filename={'/':'index.html','/index.html':'index.html','/app.js':'app.js','/style.css':'style.css'}.get(path)
            if not filename:raise Error('Ruta inexistente.',404)
            payload=(ROOT/'public'/filename).read_bytes();self.send_response(200)
            self.send_header('Content-Type',{'html':'text/html','js':'text/javascript','css':'text/css'}[filename.split('.')[-1]]+'; charset=utf-8');self.headers_common();self.end_headers();self.wfile.write(payload)
        except Error as e:self.response({'error':e.message},e.code)
    def do_POST(self): self.mutate()
    def do_PATCH(self): self.mutate()
    def do_DELETE(self): self.mutate()
    def mutate(self):
        try:
            path=urlparse(self.path).path;data=self.body()
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                if path=='/api/login' and self.command=='POST':
                    if self.headers.get('Origin')!=ORIGIN:raise Error('Origen no permitido.',403)
                    email=textfield(data,'email',254,True).lower();password=passwordfield(data)
                    # Cuenta + IP: persiste entre reinicios; no confiar en X-Forwarded-For.
                    keys=['email:'+email,'ip:'+self.client_address[0]]
                    for k in keys:
                        a=db.execute('SELECT * FROM attempts WHERE key=?',(k,)).fetchone()
                        if a and a['count']>=10 and time.time()-a['started']<900:raise Error('Demasiados intentos. Esperá 15 minutos.',429)
                    u=db.execute('SELECT * FROM users WHERE email=? AND active=1',(email,)).fetchone()
                    valid=password_ok(password,u['password'] if u else DUMMY_HASH)
                    if not u or not valid:
                        for k in keys:db.execute('INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN ?-started>900 THEN 1 ELSE count+1 END,started=CASE WHEN ?-started>900 THEN excluded.started ELSE started END',(k,time.time(),time.time(),time.time()))
                        db.commit();raise Error('Email o contraseña incorrectos.',401)
                    db.execute('DELETE FROM attempts WHERE key=?',('email:'+email,));db.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
                    token=secrets.token_urlsafe(32);db.execute('INSERT INTO sessions VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],secrets.token_hex(24),time.time()+43200));db.commit()
                    self.response({'ok':True},cookie=self.cookie(token));return
                user,key=self.auth(db,True)
                if path=='/api/logout':
                    db.execute('DELETE FROM sessions WHERE token=?',(key,));db.commit();self.response({'ok':True},cookie=self.cookie(clear=True));return
                if path=='/api/tasks' and self.command=='POST':
                    self.admin(user);t=taskdata(data,db);id=uid();db.execute('INSERT INTO tasks VALUES(?,?,?,?,1)',(id,t['clientId'],t['assigneeId'],dump(t)));log(db,id,user['id'],'Creó la tarea',t)
                elif path.startswith('/api/tasks/'):
                    id=path.split('/')[3];row=self.owned(db,user,id)
                    if data.get('version')!=row['version']:raise Error('Otra persona actualizó esta tarea. Recargá antes de guardar.',409)
                    if self.command=='DELETE':
                        self.admin(user);db.execute('DELETE FROM tasks WHERE id=?',(id,))
                    elif self.command=='PATCH':
                        old=serialize(row);t=taskdata(data,db)
                        if user['role']!='admin' and any(t[k]!=old[k] for k in ['clientId','assigneeId','priority','priorityReason','due','publishDate','roundLimit','rounds']):raise Error('La planificación y prioridad las define administración.',403)
                        if t['rounds']>t['roundLimit'] and not (user['role']=='admin' and data.get('overrideRounds') is True):raise Error('Se superaron las rondas incluidas. Administración debe aceptar la excepción.',409)
                        db.execute('UPDATE tasks SET client_id=?,assignee_id=?,data=?,version=version+1 WHERE id=?',(t['clientId'],t['assigneeId'],dump(t),id));log(db,id,user['id'],'Actualizó la tarea · versión '+str(row['version']+1),t)
                    else:raise Error('Método inválido.',405)
                elif path=='/api/comments' and self.command=='POST':
                    id=textfield(data,'taskId',60,True);self.owned(db,user,id);message=textfield(data,'text',4000,True)
                    db.execute('INSERT INTO comments VALUES(?,?,?,?,?)',(uid(),id,user['id'],message,now()))
                elif path=='/api/clients' and self.command=='POST':
                    self.admin(user);client=self.clientdata(data);id=uid();db.execute('INSERT INTO clients VALUES(?,?)',(id,dump(client)))
                elif path.startswith('/api/clients/') and self.command=='PATCH':
                    self.admin(user);id=path.split('/')[3];client=self.clientdata(data)
                    if not db.execute('SELECT 1 FROM clients WHERE id=?',(id,)).fetchone():raise Error('Cliente inexistente.',404)
                    db.execute('UPDATE clients SET data=? WHERE id=?',(dump(client),id))
                elif path=='/api/users' and self.command=='POST':
                    self.admin(user);name=textfield(data,'name',120,True);email=textfield(data,'email',254,True).lower();pw=passwordfield(data)
                    if '@' not in email or len(pw)<12:raise Error('Usá un email válido y una contraseña de al menos 12 caracteres.')
                    db.execute('INSERT INTO users VALUES(?,?,?,?,?,1)',(uid(),name,email,'team',password_hash(pw)))
                elif path.startswith('/api/users/') and self.command=='PATCH':
                    self.admin(user);id=path.split('/')[3]
                    if not db.execute('SELECT 1 FROM users WHERE id=?',(id,)).fetchone():raise Error('Persona inexistente.',404)
                    if 'active' in data:
                        if id==user['id']:raise Error('No podés desactivar tu propio acceso.')
                        if type(data['active'])!=bool:raise Error('Valor inválido.')
                        db.execute('UPDATE users SET active=? WHERE id=?',(int(data['active']),id));db.execute('DELETE FROM sessions WHERE user_id=?',(id,))
                    if 'password' in data:
                        pw=passwordfield(data)
                        if len(pw)<12:raise Error('Usá al menos 12 caracteres.')
                        db.execute('UPDATE users SET password=? WHERE id=?',(password_hash(pw),id));db.execute('DELETE FROM sessions WHERE user_id=?',(id,))
                elif path=='/api/settings' and self.command=='PATCH':
                    self.admin(user);s={k:textfield(data,k,lim) for k,lim in [('name',120),('accent',7),('secondary',7),('avatar',2000)]}
                    import re
                    if not all(re.fullmatch('#[0-9a-fA-F]{6}',s[k]) for k in ['accent','secondary']):raise Error('Color inválido.')
                    if s['avatar'] and (urlparse(s['avatar']).scheme!='https' or not urlparse(s['avatar']).netloc):raise Error('La foto debe ser una URL HTTPS.')
                    db.execute('UPDATE settings SET data=? WHERE id=1',(dump(s),))
                else:raise Error('Ruta o método inexistente.',404)
                db.commit();self.response({'ok':True})
        except Error as e:self.response({'error':e.message},e.code)
        except sqlite3.IntegrityError:self.response({'error':'El email ya existe o hay un dato relacionado inválido.'},409)
        except Exception:self.response({'error':'No pudimos guardar. Intentá nuevamente.'},500)
    def clientdata(self,d):
        c={k:textfield(d,k,lim,k=='name') for k,lim in [('name',120),('contact',250),('plan',250),('memory',15000),('notes',15000)]}
        c['startDate']=datefield(d,'startDate')
        return c

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--init-admin',action='store_true');p.add_argument('--reset-password');p.add_argument('--port',type=int,default=int(os.environ.get('PORT',8000)));a=p.parse_args();init()
    if a.init_admin:
        email=input('Email de administración: ').strip().lower();name=input('Nombre: ').strip();pw=getpass('Contraseña (mínimo 12 caracteres): ')
        if len(pw)<12 or '@' not in email or not name:raise SystemExit('Datos inválidos.')
        with connect() as db:
            if db.execute('SELECT 1 FROM users WHERE role="admin"').fetchone():raise SystemExit('Ya existe administración.')
            db.execute('INSERT INTO users VALUES(?,?,?,?,?,1)',(uid(),name,email,'admin',password_hash(pw)))
        print('Acceso creado.');
    elif a.reset_password:
        pw=getpass('Nueva contraseña (mínimo 12 caracteres): ')
        if len(pw)<12:raise SystemExit('Contraseña demasiado corta.')
        with connect() as db:
            u=db.execute('SELECT id FROM users WHERE email=?',(a.reset_password.lower(),)).fetchone()
            if not u:raise SystemExit('Email inexistente.')
            db.execute('UPDATE users SET password=?,active=1 WHERE id=?',(password_hash(pw),u['id']));db.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
        print('Acceso restablecido.')
    else:
        print(f'CRM en {ORIGIN}. Ctrl+C para detener.');ThreadingHTTPServer((os.environ.get('HOST','127.0.0.1'),a.port),Handler).serve_forever()
