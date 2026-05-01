'''
Vitline — личный кабинет абонента.

  GET  /               — страница входа
  POST /login          — авторизация
  GET  /dashboard      — личный кабинет
  GET  /wireguard      — скачать WireGuard-конфиг / QR
  POST /wireguard/new  — сгенерировать новый конфиг
  GET  /logout
  GET  /api/stats      — JSON: текущий трафик сессии

Запуск:
  uvicorn portal.app:app --host 0.0.0.0 --port 8080 --reload
'''
import asyncio
import hashlib
import json
import logging
from pathlib import Path

from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature

import sys, os
sys.path.insert(0, str(Path(__file__).parent.parent))

import config
from billing.database  import Database
from billing.sessions  import SessionManager
from wireguard.manager import WireguardManager
from wireguard.output  import render_client_conf

logger  = logging.getLogger('portal')
app     = FastAPI(title='Vitline Portal', docs_url=None, redoc_url=None)
_tpl    = Path(__file__).parent / 'templates'
_static = Path(__file__).parent / 'static'

templates = Jinja2Templates(directory=str(_tpl))

if _static.exists():
    app.mount('/static', StaticFiles(directory=str(_static)), name='static')

_signer  = URLSafeTimedSerializer(os.getenv('PORTAL_SECRET', 'vitline-dev-secret'))
_db      = None
_sessions = None
_wg      = None


def get_db():
    return _db

def get_wg():
    return _wg


# ── сессионные cookie ─────────────────────────────────────────────────────────

def make_cookie(username):
    return _signer.dumps(username)

def read_cookie(token, max_age=86400 * 7):
    try:
        return _signer.loads(token, max_age=max_age)
    except BadSignature:
        return None

def current_user(request: Request):
    token = request.cookies.get('vt_session')
    if not token:
        return None
    return read_cookie(token)


# ── startup / shutdown ────────────────────────────────────────────────────────

@app.on_event('startup')
async def startup():
    global _db, _sessions, _wg
    _db       = Database(config.DB_HOST, config.DB_PORT,
                         config.DB_USER, config.DB_PASSWORD, config.DB_NAME)
    _sessions = SessionManager(_db)
    _wg       = WireguardManager(
        db              = _db,
        interface       = config.WG_INTERFACE,
        pool_cidr       = config.WG_POOL_CIDR,
        listen_port     = config.WG_PORT,
        conf_dir        = config.WG_CONF_DIR,
        server_endpoint = config.WG_ENDPOINT,
        dns             = config.WG_DNS,
    )
    await _db.connect()
    await _wg.setup()
    logger.info('Vitline portal запущен')

@app.on_event('shutdown')
async def shutdown():
    await _db.close()


# ── маршруты ──────────────────────────────────────────────────────────────────

@app.get('/', response_class=HTMLResponse)
async def login_page(request: Request):
    user = current_user(request)
    if user:
        return RedirectResponse('/dashboard', status_code=302)
    return templates.TemplateResponse('login.html', {'request': request, 'error': None})


@app.post('/login', response_class=HTMLResponse)
async def login(request: Request,
                username: str = Form(...),
                password: str = Form(...)):
    sub = await _db.get_subscriber(username)

    if not sub or not sub['active'] or sub['password'] != password:
        return templates.TemplateResponse('login.html', {
            'request': request,
            'error':   'Неверный логин или пароль'
        })

    resp = RedirectResponse('/dashboard', status_code=302)
    resp.set_cookie('vt_session', make_cookie(username),
                    httponly=True, max_age=86400 * 7, samesite='lax')
    return resp


@app.get('/logout')
async def logout():
    resp = RedirectResponse('/', status_code=302)
    resp.delete_cookie('vt_session')
    return resp


@app.get('/dashboard', response_class=HTMLResponse)
async def dashboard(request: Request):
    username = current_user(request)
    if not username:
        return RedirectResponse('/', status_code=302)

    sub    = await _db.get_subscriber(username)
    tariff = await _db.get_tariff(sub['tariff_id'])
    usage  = await _db.monthly_usage(username)
    peers  = await _wg.list_peers(username)

    active_sessions = await _db.active_sessions()
    my_sessions     = [s for s in active_sessions if s['username'] == username]

    rx_gb  = round(usage['rx'] / 1024**3, 2)
    tx_gb  = round(usage['tx'] / 1024**3, 2)
    limit  = tariff.get('monthly_gb')
    used_pct = round(rx_gb / limit * 100) if limit else None

    return templates.TemplateResponse('dashboard.html', {
        'request':     request,
        'username':    username,
        'sub':         sub,
        'tariff':      tariff,
        'rx_gb':       rx_gb,
        'tx_gb':       tx_gb,
        'limit_gb':    limit,
        'used_pct':    used_pct,
        'peers':       peers,
        'sessions':    my_sessions,
    })


@app.post('/wireguard/new', response_class=HTMLResponse)
async def wg_new(request: Request):
    username = current_user(request)
    if not username:
        return RedirectResponse('/', status_code=302)

    peers = await _wg.list_peers(username)
    if len(peers) >= 5:
        return RedirectResponse('/dashboard?error=max_peers', status_code=302)

    label = f'device-{len(peers)+1}'
    await _wg.provision_peer(username, label=label)
    return RedirectResponse('/dashboard?wg=new', status_code=302)


@app.get('/wireguard/{peer_id}/conf')
async def wg_download_conf(peer_id: int, request: Request):
    username = current_user(request)
    if not username:
        raise HTTPException(403)

    peers = await _wg.list_peers(username)
    peer  = next((p for p in peers if p['id'] == peer_id), None)
    if not peer:
        raise HTTPException(404)

    cfg = await _wg.provision_peer(username)
    conf_text = cfg.get('config_text', '')

    return Response(
        content    = conf_text,
        media_type = 'text/plain',
        headers    = {'Content-Disposition': f'attachment; filename="vitline-{username}.conf"'},
    )


@app.get('/api/stats')
async def api_stats(request: Request):
    username = current_user(request)
    if not username:
        raise HTTPException(403)

    usage    = await _db.monthly_usage(username)
    sessions = await _db.active_sessions()
    my_s     = [s for s in sessions if s['username'] == username]

    live_rx = sum(s['rx_bytes'] for s in my_s)
    live_tx = sum(s['tx_bytes'] for s in my_s)

    return JSONResponse({
        'rx_month_gb': round(usage['rx'] / 1024**3, 3),
        'tx_month_gb': round(usage['tx'] / 1024**3, 3),
        'live_rx_mb':  round(live_rx / 1024**2, 1),
        'live_tx_mb':  round(live_tx / 1024**2, 1),
        'sessions':    len(my_s),
    })
