'''
Vitline ISP — единая точка запуска.

  python main.py              — RADIUS + WireGuard + коллектор + DNS
  python main.py radius       — только RADIUS
  python main.py portal       — только веб-портал (uvicorn)
  python main.py monitor      — только NetFlow-коллектор
  python main.py dns          — только DNS-прокси
  python main.py tunnel        — только WS-туннель
  python main.py bgp [...]    — BGP daemon (ExaBGP-режим)

  # управление абонентами
  python main.py adduser LOGIN PASS TARIFF_ID
  python main.py block   LOGIN
  python main.py unblock LOGIN
  python main.py sessions
  python main.py tariffs
  python main.py usage   LOGIN
  python main.py seed

  # WireGuard
  python main.py wg-add    LOGIN [PUBKEY]
  python main.py wg-remove PUBKEY
  python main.py wg-list
  python main.py wg-stats
'''
import asyncio
import logging
import sys

import config
from billing.database  import Database
from billing.sessions  import SessionManager
from radius.server     import start_radius
from wireguard.manager import WireguardManager
from wireguard.output  import print_config, print_qr, save_config
from monitor.collector  import run_collector
from dns.resolver       import run_dns
from tunnel.ws_bridge   import run_ws_tunnel

logging.basicConfig(
    level   = logging.INFO,
    format  = '%(asctime)s  %(levelname)-7s  %(name)s — %(message)s',
    datefmt = '%H:%M:%S',
)
logger = logging.getLogger('vitline')


def make_db():
    return Database(
        host     = config.DB_HOST,
        port     = config.DB_PORT,
        user     = config.DB_USER,
        password = config.DB_PASSWORD,
        db       = config.DB_NAME,
    )

def make_wg(db):
    return WireguardManager(
        db              = db,
        interface       = config.WG_INTERFACE,
        pool_cidr       = config.WG_POOL_CIDR,
        listen_port     = config.WG_PORT,
        conf_dir        = config.WG_CONF_DIR,
        server_endpoint = config.WG_ENDPOINT,
        dns             = config.WG_DNS,
    )


# ── полный стек ───────────────────────────────────────────────────────────────

async def run_all():
    db       = make_db()
    sessions = SessionManager(db)
    wg       = make_wg(db)

    await db.connect()
    await wg.setup()

    async def _cleanup():
        while True:
            await asyncio.sleep(config.CLEANUP_INTERVAL)
            await sessions.cleanup_stale(config.MAX_IDLE_SESSION)

    asyncio.create_task(_cleanup())

    auth_t, acct_t = await start_radius(
        host      = config.RADIUS_HOST,
        auth_port = config.RADIUS_AUTH_PORT,
        acct_port = config.RADIUS_ACCT_PORT,
        secret    = config.RADIUS_SECRET,
        db        = db,
        sessions  = sessions,
    )

    asyncio.create_task(run_collector(db))
    asyncio.create_task(run_dns())
    asyncio.create_task(run_ws_tunnel())

    logger.info('=' * 50)
    logger.info('  Vitline ISP — все сервисы запущены')
    logger.info('  RADIUS  auth=%d  acct=%d', config.RADIUS_AUTH_PORT, config.RADIUS_ACCT_PORT)
    logger.info('  WG      port=%d  pool=%s', config.WG_PORT, config.WG_POOL_CIDR)
    logger.info('  NetFlow port=2055  sFlow port=6343')
    logger.info('  DNS     port=5353')
    logger.info('  Portal  → uvicorn portal.app:app --port 8080')
    logger.info('=' * 50)

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info('остановка...')
    finally:
        auth_t.close()
        acct_t.close()
        await db.close()


# ── CLI ───────────────────────────────────────────────────────────────────────

async def run_cli(args):
    db  = make_db()
    wg  = make_wg(db)
    cmd = args[0]
    await db.connect()
    await wg.setup()

    if cmd == 'seed':
        await db.seed()
        print('✓ тестовые данные загружены')

    elif cmd == 'adduser' and len(args) == 4:
        await db.add_subscriber(args[1], args[2], int(args[3]))
        print(f'✓ абонент {args[1]}  тариф={args[3]}')

    elif cmd == 'block' and len(args) == 2:
        await db.set_active(args[1], False)
        print(f'✓ {args[1]} заблокирован')

    elif cmd == 'unblock' and len(args) == 2:
        await db.set_active(args[1], True)
        print(f'✓ {args[1]} разблокирован')

    elif cmd == 'sessions':
        rows = await db.active_sessions()
        if not rows:
            print('активных сессий нет')
        else:
            print(f'{"пользователь":<20}  {"сессия":<24}  старт')
            print('─' * 60)
            for r in rows:
                print(f'{r["username"]:<20}  {r["session_id"]:<24}  {r["started_at"]}')

    elif cmd == 'tariffs':
        rows = await db.list_tariffs()
        print(f'{"id":<5}  {"название":<20}  {"↓ мбит":<10}  {"↑ мбит":<10}  гб/мес')
        print('─' * 58)
        for r in rows:
            gb = str(r['monthly_gb']) if r['monthly_gb'] else '∞'
            print(f'{r["id"]:<5}  {r["name"]:<20}  '
                  f'{r["rate_down_kbps"]//1024:<10}  '
                  f'{r["rate_up_kbps"]//1024:<10}  {gb}')

    elif cmd == 'usage' and len(args) == 2:
        u = await db.monthly_usage(args[1])
        print(f'{args[1]}:  вх {u["rx"]/1024**3:.2f} ГБ  /  исх {u["tx"]/1024**3:.2f} ГБ')

    elif cmd == 'wg-add' and len(args) >= 2:
        username = args[1]
        pubkey   = args[2] if len(args) > 2 else None
        if pubkey:
            cfg = await wg.add_peer(username, pubkey)
            print(f'✓ пир добавлен  ip={cfg["client_ip"]}')
        else:
            cfg = await wg.provision_peer(username, label=f'auto-{username}')
            save_config(cfg['config_text'], f'/tmp/vitline-{username}.conf')
            print_config(cfg['config_text'], title=f'Vitline WG — {username}')
            print_qr(cfg['config_text'])

    elif cmd == 'wg-remove' and len(args) == 2:
        await wg.remove_peer(args[1])
        print('✓ пир удалён')

    elif cmd == 'wg-list':
        peers = await wg.list_peers()
        if not peers:
            print('нет WireGuard-пиров')
        else:
            print(f'{"пользователь":<20}  {"ip":<16}  {"статус":<10}  метка')
            print('─' * 65)
            for p in peers:
                st = 'enabled' if p['enabled'] else 'disabled'
                print(f'{p["username"]:<20}  {p["client_ip"]:<16}  {st:<10}  {p["label"] or ""}')

    elif cmd == 'wg-stats':
        stats = await wg.peer_stats()
        peers = await wg.list_peers()
        p2u   = {p['public_key']: p['username'] for p in peers}
        if not stats:
            print('нет данных (интерфейс не поднят?)')
        else:
            for pub, s in stats.items():
                user = p2u.get(pub, pub[:12] + '...')
                rx   = f'{s["rx_bytes"]/1024/1024:.1f} МБ'
                tx   = f'{s["tx_bytes"]/1024/1024:.1f} МБ'
                hs   = s['last_handshake']
                print(f'{user:<20}  rx={rx:<12} tx={tx:<12}  '
                      f'{"never" if not hs else str(hs)+"s ago"}')

    else:
        print(__doc__)

    await db.close()


# ── точка входа ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    args = sys.argv[1:]

    if not args:
        asyncio.run(run_all())

    elif args[0] == 'bgp':
        sys.argv = ['daemon.py'] + args[1:]
        from bgp.daemon import main as bgp_main
        bgp_main()

    elif args[0] == 'portal':
        import uvicorn
        uvicorn.run('portal.app:app', host='0.0.0.0', port=8080, reload=False)

    elif args[0] == 'monitor':
        asyncio.run(run_collector())

    elif args[0] == 'dns':
        asyncio.run(run_dns())

    elif args[0] == 'tunnel':
        asyncio.run(run_ws_tunnel())

    elif args[0] == 'radius':
        async def _only_radius():
            db       = make_db()
            sessions = SessionManager(db)
            await db.connect()
            auth_t, acct_t = await start_radius(
                host=config.RADIUS_HOST,
                auth_port=config.RADIUS_AUTH_PORT,
                acct_port=config.RADIUS_ACCT_PORT,
                secret=config.RADIUS_SECRET, db=db, sessions=sessions,
            )
            try:
                await asyncio.Event().wait()
            finally:
                auth_t.close(); acct_t.close(); await db.close()
        asyncio.run(_only_radius())

    else:
        asyncio.run(run_cli(args))
