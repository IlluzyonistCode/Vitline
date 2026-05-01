'''
BGP-демон — управляет анонсами через ExaBGP API.

Схема работы:
  ExaBGP запускает этот скрипт как процесс-контроллер.
  Мы пишем команды в stdout  → ExaBGP отправляет их пирам.
  ExaBGP пишет события в stdin → мы их читаем и обрабатываем.

Запуск (не напрямую, а через ExaBGP):
  exabgp /etc/exabgp/exabgp.conf

Для тестирования без ExaBGP:
  python bgp/daemon.py --dry-run
'''
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

logger = logging.getLogger('bgp.daemon')


# ── Состояние пиров ───────────────────────────────────────────────────────────

PEER_UP   = 'up'
PEER_DOWN = 'down'


class PeerState:

    def __init__(self, peer_ip):
        self.peer_ip    = peer_ip
        self.state      = PEER_DOWN
        self.uptime     = None
        self.prefixes_rx = 0

    def mark_up(self):
        self.state  = PEER_UP
        self.uptime = time.time()

    def mark_down(self):
        self.state  = PEER_DOWN
        self.uptime = None


# ── Менеджер анонсов ─────────────────────────────────────────────────────────

class BgpManager:
    '''
    Управляет набором анонсируемых префиксов.
    Отправляет команды в ExaBGP через stdout.
    '''

    def __init__(self, router_id, local_as, dry_run=False):
        self.router_id  = router_id
        self.local_as   = local_as
        self.dry_run    = dry_run
        self.peers      = {}      # peer_ip → PeerState
        self.announced  = set()   # префиксы, которые сейчас анонсируются
        self._out       = sys.stdout

    # ── команды ExaBGP ────────────────────────────────────────────────────────

    def _send(self, cmd):
        if self.dry_run:
            logger.info('[dry-run] → %s', cmd)
            return
        print(cmd, flush=True)
        logger.debug('→ %s', cmd)

    def announce(self, prefix, next_hop='self', community=None):
        '''Анонсировать IPv4/IPv6 префикс.'''
        if prefix in self.announced:
            return

        community_str = ''
        if community:
            community_str = f' community [{" ".join(community)}]'

        self._send(
            f'announce route {prefix} next-hop {next_hop}{community_str}'
        )
        self.announced.add(prefix)
        logger.info('анонс: %s  nh=%s  community=%s', prefix, next_hop, community)

    def withdraw(self, prefix):
        '''Отозвать анонс префикса.'''
        if prefix not in self.announced:
            return

        self._send(f'withdraw route {prefix}')
        self.announced.discard(prefix)
        logger.info('отзыв: %s', prefix)

    def withdraw_all(self):
        for prefix in list(self.announced):
            self.withdraw(prefix)

    # ── blackhole / RTBH ─────────────────────────────────────────────────────

    def blackhole(self, ip):
        '''
        Remote Triggered Black Hole — анонсировать /32 или /128
        с community blackhole (RFC 7999: 65535:666).
        Используется для защиты от DDoS: аплинк дропает трафик
        к атакуемому IP ещё на своей стороне.
        '''
        if ':' in ip:
            prefix = f'{ip}/128'
        else:
            prefix = f'{ip}/32'

        self.announce(prefix, next_hop='self',
                      community=['65535:666', f'{self.local_as}:666'])
        logger.warning('BLACKHOLE: %s', ip)

    def unblackhole(self, ip):
        prefix = f'{ip}/128' if ':' in ip else f'{ip}/32'
        self.withdraw(prefix)
        logger.info('blackhole снят: %s', ip)

    # ── парсинг событий ExaBGP ────────────────────────────────────────────────

    def handle_event(self, line):
        line = line.strip()
        if not line:
            return

        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            logger.debug('не-JSON: %s', line)
            return

        ev_type  = ev.get('type', '')
        neighbor = ev.get('neighbor', {})
        peer_ip  = neighbor.get('address', {}).get('peer', 'unknown')

        if ev_type == 'state' and neighbor.get('state') == 'up':
            self.peers.setdefault(peer_ip, PeerState(peer_ip)).mark_up()
            logger.info('пир UP:   %s', peer_ip)
            self._on_peer_up(peer_ip)

        elif ev_type == 'state' and neighbor.get('state') == 'down':
            self.peers.setdefault(peer_ip, PeerState(peer_ip)).mark_down()
            logger.warning('пир DOWN: %s', peer_ip)

        elif ev_type == 'update':
            announce = neighbor.get('message', {}).get('update', {}).get('announce', {})
            for _afi, prefixes in announce.items():
                for nh, pfx_list in prefixes.items():
                    for pfx in pfx_list:
                        logger.debug('получен маршрут от %s: %s via %s', peer_ip, pfx, nh)

    def _on_peer_up(self, peer_ip):
        '''При поднятии пира — сразу переанонсировать все префиксы.'''
        saved = list(self.announced)
        self.announced.clear()
        for prefix in saved:
            self.announce(prefix)

    # ── статус ────────────────────────────────────────────────────────────────

    def status(self):
        lines = [f'router-id={self.router_id}  AS{self.local_as}']
        lines.append(f'анонсов: {len(self.announced)}')
        for prefix in sorted(self.announced):
            lines.append(f'  + {prefix}')
        lines.append(f'пиров: {len(self.peers)}')
        for peer_ip, state in self.peers.items():
            uptime = ''
            if state.uptime:
                secs   = int(time.time() - state.uptime)
                uptime = f'  up {secs//3600}h{(secs%3600)//60}m'
            lines.append(f'  {state.state.upper()}  {peer_ip}{uptime}')
        return '\n'.join(lines)


# ── Основной цикл (запускается ExaBGP'ом) ────────────────────────────────────

async def exabgp_loop(manager, prefixes_to_announce):
    '''Читаем события из stdin, в начале анонсируем наши префиксы.'''

    # даём ExaBGP время поднять соединение
    await asyncio.sleep(2)

    for prefix, nh in prefixes_to_announce:
        manager.announce(prefix, next_hop=nh)

    loop = asyncio.get_running_loop()

    while True:
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            manager.handle_event(line)
        except KeyboardInterrupt:
            break

    manager.withdraw_all()


# ── CLI / dry-run ─────────────────────────────────────────────────────────────

def main():
    import argparse

    ap = argparse.ArgumentParser(description='ISP BGP daemon (ExaBGP controller)')
    ap.add_argument('--dry-run',    action='store_true', help='не слать команды ExaBGP')
    ap.add_argument('--router-id',  default=os.getenv('BGP_ROUTER_ID', '192.168.1.1'))
    ap.add_argument('--local-as',   default=int(os.getenv('BGP_LOCAL_AS', '65001')), type=int)
    ap.add_argument('--announce',   nargs='+', metavar='PREFIX/MASK',
                    default=os.getenv('BGP_PREFIXES', '').split(),
                    help='префиксы для анонса, напр. 203.0.113.0/24')
    ap.add_argument('--next-hop',   default=os.getenv('BGP_NEXT_HOP', 'self'))
    ap.add_argument('--status',     action='store_true', help='показать статус и выйти')
    args = ap.parse_args()

    logging.basicConfig(
        level   = logging.INFO,
        format  = '%(asctime)s  %(levelname)-7s  %(name)s — %(message)s',
        stream  = sys.stderr,   # stdout занят командами ExaBGP
    )

    manager = BgpManager(args.router_id, args.local_as, dry_run=args.dry_run)

    if args.status:
        print(manager.status())
        return

    prefixes = [(p, args.next_hop) for p in args.announce]

    if args.dry_run:
        logger.info('dry-run режим — команды пойдут в лог, не в ExaBGP')
        asyncio.run(exabgp_loop(manager, prefixes))
    else:
        asyncio.run(exabgp_loop(manager, prefixes))


if __name__ == '__main__':
    main()
