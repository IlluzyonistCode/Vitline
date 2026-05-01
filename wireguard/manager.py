'''
WireGuard-менеджер.

Что делает:
  - генерирует ключи (приватный/публичный/preshared) через wg(1)
  - добавляет/удаляет пиров через `wg set` без перезапуска интерфейса
  - синхронизирует конфиг wg0.conf на диске
  - раздаёт IP из /24-пула (один IP на пира)
  - хранит пиров в MySQL (таблица wg_peers)

Требования:
  apt install wireguard-tools   (пакет wg и wg-quick)
  Скрипт должен запускаться от root (или с CAP_NET_ADMIN).
'''
import asyncio
import ipaddress
import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger('wireguard')


# ── Утилиты wg ───────────────────────────────────────────────────────────────

def wg(*args, input=None):
    '''Обёртка вокруг команды wg. Возвращает stdout.'''
    result = subprocess.run(
        ['wg', *args],
        input      = input,
        capture_output = True,
        text       = True,
    )
    if result.returncode != 0:
        raise RuntimeError(f'wg {" ".join(args)} → {result.stderr.strip()}')
    return result.stdout.strip()


def genkey():
    return wg('genkey')


def pubkey(private_key):
    return wg('pubkey', input=private_key)


def genpsk():
    return wg('genpsk')


# ── Генерация конфига интерфейса ──────────────────────────────────────────────

def render_interface_conf(private_key, address, listen_port, dns=None, peers=None):
    '''
    Генерирует текст wg0.conf.
    peers — список словарей {public_key, preshared_key, allowed_ips, endpoint}
    '''
    lines = [
        '[Interface]',
        f'PrivateKey = {private_key}',
        f'Address    = {address}',
        f'ListenPort = {listen_port}',
    ]

    if dns:
        lines.append(f'DNS        = {", ".join(dns) if isinstance(dns, list) else dns}')

    lines += [
        'PostUp   = iptables -A FORWARD -i %i -j ACCEPT; '
                   'iptables -A FORWARD -o %i -j ACCEPT; '
                   'iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE',
        'PostDown = iptables -D FORWARD -i %i -j ACCEPT; '
                   'iptables -D FORWARD -o %i -j ACCEPT; '
                   'iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE',
        '',
    ]

    for peer in (peers or []):
        lines += [
            '[Peer]',
            f'PublicKey  = {peer["public_key"]}',
        ]
        if peer.get('preshared_key'):
            lines.append(f'PresharedKey = {peer["preshared_key"]}')
        lines.append(f'AllowedIPs = {peer["allowed_ips"]}')
        if peer.get('endpoint'):
            lines.append(f'Endpoint   = {peer["endpoint"]}')
        if peer.get('keepalive'):
            lines.append(f'PersistentKeepalive = {peer["keepalive"]}')
        lines.append('')

    return '\n'.join(lines)


def render_client_conf(private_key, address, server_public_key,
                       server_endpoint, preshared_key=None,
                       dns=None, allowed_ips='0.0.0.0/0, ::/0'):
    '''Конфиг для клиента (абонента).'''
    lines = [
        '[Interface]',
        f'PrivateKey = {private_key}',
        f'Address    = {address}',
    ]
    if dns:
        lines.append(f'DNS        = {", ".join(dns) if isinstance(dns, list) else dns}')
    lines += [
        '',
        '[Peer]',
        f'PublicKey  = {server_public_key}',
        f'Endpoint   = {server_endpoint}',
        f'AllowedIPs = {allowed_ips}',
        'PersistentKeepalive = 25',
    ]
    if preshared_key:
        lines.append(f'PresharedKey = {preshared_key}')
    return '\n'.join(lines)


# ── Менеджер ──────────────────────────────────────────────────────────────────

class WireguardManager:
    '''
    Управляет WireGuard-интерфейсом и пирами.
    pool_cidr — подсеть для абонентов, напр. '10.20.0.0/24'
    '''

    def __init__(self, db, interface='wg0', pool_cidr='10.20.0.0/24',
                 listen_port=51820, conf_dir='/etc/wireguard',
                 server_endpoint=None, dns=None):

        self.db              = db
        self.interface       = interface
        self.pool            = ipaddress.ip_network(pool_cidr, strict=False)
        self.listen_port     = listen_port
        self.conf_dir        = Path(conf_dir)
        self.server_endpoint = server_endpoint  # 'X.X.X.X:51820'
        self.dns             = dns or ['1.1.1.1', '1.0.0.1']
        self.conf_path       = self.conf_dir / f'{interface}.conf'

        # приватный ключ сервера — хранится отдельным файлом
        self._key_path       = self.conf_dir / f'{interface}.key'
        self._private_key    = None
        self._public_key     = None

    # ── инициализация ─────────────────────────────────────────────────────────

    async def setup(self):
        '''Создать схему БД, загрузить или сгенерировать ключи сервера.'''
        await self._ensure_schema()
        self._load_or_generate_keys()
        logger.info('WireGuard  interface=%s  pubkey=%s...',
                    self.interface, self._public_key[:12])

    async def _ensure_schema(self):
        await self.db._execute('''
            CREATE TABLE IF NOT EXISTS wg_peers (
                id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                username     VARCHAR(64)  NOT NULL,
                public_key   VARCHAR(64)  NOT NULL UNIQUE,
                preshared_key VARCHAR(64) DEFAULT NULL,
                client_ip    VARCHAR(45)  NOT NULL UNIQUE,
                enabled      TINYINT(1)   NOT NULL DEFAULT 1,
                created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen    DATETIME     DEFAULT NULL,
                label        VARCHAR(128) DEFAULT NULL,
                INDEX idx_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ''')

    def _load_or_generate_keys(self):
        if self._key_path.exists():
            self._private_key = self._key_path.read_text().strip()
            logger.info('приватный ключ загружен из %s', self._key_path)
        else:
            self._private_key = genkey()
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self._private_key)
            self._key_path.chmod(0o600)
            logger.info('приватный ключ сгенерирован → %s', self._key_path)

        self._public_key = pubkey(self._private_key)

    @property
    def public_key(self):
        return self._public_key

    # ── пул IP ────────────────────────────────────────────────────────────────

    async def _next_free_ip(self):
        used = set()
        rows = await self.db._fetchall('SELECT client_ip FROM wg_peers')
        for row in rows:
            used.add(row['client_ip'])

        # .0 — сеть, .1 — сервер — пропускаем
        for host in self.pool.hosts():
            ip = str(host)
            if ip.endswith('.1'):
                continue
            if ip not in used:
                return ip

        raise RuntimeError(f'IP-пул WireGuard исчерпан ({self.pool})')

    # ── добавить пира ─────────────────────────────────────────────────────────

    async def add_peer(self, username, public_key, label=None):
        '''
        Добавить нового абонента.
        Возвращает словарь с конфигом клиента.
        '''
        existing = await self.db._fetchone(
            'SELECT * FROM wg_peers WHERE public_key = %s', public_key
        )
        if existing:
            logger.info('пир уже существует: %s', public_key[:12])
            return await self._build_client_config(existing)

        client_ip   = await self._next_free_ip()
        psk         = genpsk()
        allowed_ips = f'{client_ip}/32'

        await self.db._execute(
            'INSERT INTO wg_peers (username, public_key, preshared_key, client_ip, label) '
            'VALUES (%s,%s,%s,%s,%s)',
            username, public_key, psk, client_ip, label
        )

        # горячее добавление без перезапуска интерфейса
        await self._wg_set_peer(public_key, psk, allowed_ips)

        # синхронизируем wg0.conf
        await self.write_conf()

        peer = await self.db._fetchone(
            'SELECT * FROM wg_peers WHERE public_key = %s', public_key
        )
        cfg = await self._build_client_config(peer)

        logger.info('пир добавлен: %s  ip=%s  user=%s', public_key[:12], client_ip, username)
        return cfg

    # ── создать пира с нуля (генерируем ключи за клиента) ───────────────────

    async def provision_peer(self, username, label=None):
        '''
        Сгенерировать ключи, добавить пира, вернуть готовый конфиг клиента.
        Удобно для выдачи конфига через личный кабинет.
        '''
        client_priv = genkey()
        client_pub  = pubkey(client_priv)

        cfg = await self.add_peer(username, client_pub, label=label)
        cfg['client_private_key'] = client_priv
        cfg['config_text']        = render_client_conf(
            private_key      = client_priv,
            address          = f'{cfg["client_ip"]}/32',
            server_public_key = self._public_key,
            server_endpoint  = self.server_endpoint or f'YOUR_SERVER_IP:{self.listen_port}',
            preshared_key    = cfg.get('preshared_key'),
            dns              = self.dns,
        )
        return cfg

    # ── удалить / отключить пира ─────────────────────────────────────────────

    async def remove_peer(self, public_key):
        await self._wg_remove_peer(public_key)
        await self.db._execute(
            'DELETE FROM wg_peers WHERE public_key = %s', public_key
        )
        await self.write_conf()
        logger.info('пир удалён: %s', public_key[:12])

    async def disable_peer(self, public_key):
        '''Отключить без удаления из БД — легко включить обратно.'''
        await self._wg_remove_peer(public_key)
        await self.db._execute(
            'UPDATE wg_peers SET enabled=0 WHERE public_key=%s', public_key
        )
        logger.info('пир отключён: %s', public_key[:12])

    async def enable_peer(self, public_key):
        peer = await self.db._fetchone(
            'SELECT * FROM wg_peers WHERE public_key=%s', public_key
        )
        if not peer:
            raise ValueError(f'пир не найден: {public_key}')
        await self._wg_set_peer(peer['public_key'], peer['preshared_key'],
                                f'{peer["client_ip"]}/32')
        await self.db._execute(
            'UPDATE wg_peers SET enabled=1 WHERE public_key=%s', public_key
        )
        logger.info('пир включён: %s', public_key[:12])

    # ── список пиров ─────────────────────────────────────────────────────────

    async def list_peers(self, username=None):
        if username:
            return await self.db._fetchall(
                'SELECT * FROM wg_peers WHERE username=%s ORDER BY created_at', username
            )
        return await self.db._fetchall(
            'SELECT * FROM wg_peers ORDER BY created_at'
        )

    async def peer_stats(self):
        '''Парсит вывод wg show и возвращает статистику по пирам.'''
        try:
            output = wg('show', self.interface, 'dump')
        except RuntimeError as e:
            logger.warning('wg show: %s', e)
            return {}

        stats = {}
        for line in output.splitlines()[1:]:   # первая строка — интерфейс
            parts = line.split('\t')
            if len(parts) < 7:
                continue
            pub, psk, endpoint, allowed, last_handshake, rx, tx, *_ = parts
            stats[pub] = {
                'endpoint':       endpoint,
                'allowed_ips':    allowed,
                'last_handshake': int(last_handshake) if last_handshake.isdigit() else 0,
                'rx_bytes':       int(rx),
                'tx_bytes':       int(tx),
            }
        return stats

    # ── запись конфига ────────────────────────────────────────────────────────

    async def write_conf(self):
        peers = await self.db._fetchall(
            'SELECT * FROM wg_peers WHERE enabled=1'
        )
        peer_dicts = [
            {
                'public_key':    p['public_key'],
                'preshared_key': p['preshared_key'],
                'allowed_ips':   f'{p["client_ip"]}/32',
            }
            for p in peers
        ]

        # IP сервера — первый хост в пуле
        server_ip = str(list(self.pool.hosts())[0])

        conf = render_interface_conf(
            private_key  = self._private_key,
            address      = f'{server_ip}/{self.pool.prefixlen}',
            listen_port  = self.listen_port,
            dns          = None,   # DNS сервер не нужен на стороне сервера
            peers        = peer_dicts,
        )

        self.conf_path.parent.mkdir(parents=True, exist_ok=True)
        self.conf_path.write_text(conf)
        self.conf_path.chmod(0o600)
        logger.debug('конфиг записан: %s  (%d пиров)', self.conf_path, len(peer_dicts))

    # ── wg set / wg del ──────────────────────────────────────────────────────

    async def _wg_set_peer(self, public_key, psk, allowed_ips):
        loop = asyncio.get_running_loop()
        try:
            args = ['set', self.interface, 'peer', public_key,
                    'preshared-key', '/dev/stdin',
                    'allowed-ips', allowed_ips]
            await loop.run_in_executor(
                None,
                lambda: wg(*args, input=psk)
            )
        except RuntimeError as e:
            logger.warning('wg set: %s (интерфейс не поднят?)', e)

    async def _wg_remove_peer(self, public_key):
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: wg('set', self.interface, 'peer', public_key, 'remove')
            )
        except RuntimeError as e:
            logger.warning('wg remove: %s', e)

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _build_client_config(self, peer):
        return {
            'username':     peer['username'],
            'public_key':   peer['public_key'],
            'preshared_key': peer['preshared_key'],
            'client_ip':    peer['client_ip'],
            'enabled':      bool(peer['enabled']),
        }
