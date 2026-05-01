'''
Vitline — клиентский туннель.

Запускается на машине абонента рядом с WireGuard.
Принимает локальный UDP :51820, оборачивает в WebSocket,
отправляет на сервер Vitline по wss://vpn.vitline.net/wg.

Использование:
  python tunnel/client.py --server wss://vpn.vitline.net/wg

Затем в WireGuard-конфиге абонента:
  [Peer]
  Endpoint = 127.0.0.1:51820   ← локальный клиентский туннель
  ...

Windows: использовать готовый wstunnel.exe (см. README_TUNNEL.md)
'''
import asyncio
import hashlib
import base64
import logging
import os
import struct
import argparse
import urllib.parse

logger = logging.getLogger('tunnel.client')

LOCAL_PORT  = int(os.getenv('LOCAL_WG_PORT',  '51820'))
RECONNECT_S = int(os.getenv('RECONNECT_DELAY', '5'))


# ── WebSocket клиент ──────────────────────────────────────────────────────────

def _make_ws_key():
    return base64.b64encode(os.urandom(16)).decode()


def _ws_client_frame(data, opcode=0x2):
    '''Фрейм клиента — с маской (RFC 6455 требует).'''
    mask    = os.urandom(4)
    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    length  = len(data)
    if length < 126:
        header = struct.pack('BB', 0x80 | opcode, 0x80 | length)
    elif length < 65536:
        header = struct.pack('!BBH', 0x80 | opcode, 0x80 | 126, length)
    else:
        header = struct.pack('!BBQ', 0x80 | opcode, 0x80 | 127, length)
    return header + mask + payload


def _parse_server_frame(buf):
    '''Парсить фрейм от сервера (без маски).'''
    if len(buf) < 2:
        return None, 0
    b1     = buf[1] & 0x7f
    pos    = 2
    if b1 == 126:
        if len(buf) < 4: return None, 0
        length = struct.unpack_from('>H', buf, 2)[0]; pos = 4
    elif b1 == 127:
        if len(buf) < 10: return None, 0
        length = struct.unpack_from('>Q', buf, 2)[0]; pos = 10
    else:
        length = b1
    if len(buf) < pos + length: return None, 0
    return buf[pos:pos+length], pos + length


async def _ws_connect(url):
    parsed = urllib.parse.urlparse(url)
    host   = parsed.hostname
    port   = parsed.port or (443 if parsed.scheme == 'wss' else 80)
    path   = parsed.path or '/wg'
    ssl    = parsed.scheme == 'wss'

    if ssl:
        import ssl as _ssl
        ctx = _ssl.create_default_context()
    else:
        ctx = None

    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)

    key = _make_ws_key()
    writer.write(
        f'GET {path} HTTP/1.1\r\n'
        f'Host: {host}\r\n'
        f'Upgrade: websocket\r\n'
        f'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Key: {key}\r\n'
        f'Sec-WebSocket-Version: 13\r\n'
        f'\r\n'.encode()
    )
    await writer.drain()

    # читаем HTTP-ответ
    response = b''
    while b'\r\n\r\n' not in response:
        chunk = await reader.read(4096)
        if not chunk:
            raise ConnectionError('сервер закрыл соединение при handshake')
        response += chunk

    if b'101' not in response:
        raise ConnectionError(f'WS handshake провален: {response[:80]}')

    logger.info('ws соединение установлено: %s', url)
    return reader, writer


# ── UDP↔WS мост (клиентская сторона) ─────────────────────────────────────────

class ClientBridge:

    def __init__(self, server_url):
        self.server_url = server_url
        self._reader    = None
        self._writer    = None
        self._transport = None   # UDP сервер (принимает от WG-клиента)
        self._peer      = None   # адрес WG-клиента (первый пакет)
        self._buf       = b''

    async def run(self):
        while True:
            try:
                await self._connect_and_serve()
            except Exception as e:
                logger.warning('переподключение через %ds: %s', RECONNECT_S, e)
                await asyncio.sleep(RECONNECT_S)

    async def _connect_and_serve(self):
        self._reader, self._writer = await _ws_connect(self.server_url)

        loop = asyncio.get_running_loop()
        if not self._transport:
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: _LocalUdp(self),
                local_addr=('127.0.0.1', LOCAL_PORT),
            )
            logger.info('udp listener  127.0.0.1:%d', LOCAL_PORT)

        # читаем из WS → отправляем в UDP WG-клиенту
        while True:
            chunk = await self._reader.read(65536)
            if not chunk:
                break
            self._buf += chunk
            while True:
                payload, consumed = _parse_server_frame(self._buf)
                if consumed == 0:
                    break
                self._buf = self._buf[consumed:]
                if payload and self._peer and self._transport:
                    self._transport.sendto(payload, self._peer)

    async def send_to_server(self, data, addr):
        '''UDP-пакет от WG-клиента → WS → сервер.'''
        self._peer = addr
        if self._writer and not self._writer.is_closing():
            self._writer.write(_ws_client_frame(data))
            await self._writer.drain()


class _LocalUdp(asyncio.DatagramProtocol):

    def __init__(self, bridge):
        self.bridge = bridge
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.bridge._transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self.bridge.send_to_server(data, addr))


# ── CLI ───────────────────────────────────────────────────────────────────────

async def main(server_url):
    logging.basicConfig(
        level  = logging.INFO,
        format = '%(asctime)s  %(levelname)-7s  %(name)s — %(message)s',
    )
    bridge = ClientBridge(server_url)
    logger.info('vitline tunnel client → %s', server_url)
    await bridge.run()


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Vitline tunnel client')
    ap.add_argument('--server', default='wss://vpn.vitline.net/wg',
                    help='URL сервера, например wss://vpn.vitline.net/wg')
    ap.add_argument('--port', type=int, default=LOCAL_PORT,
                    help='Локальный UDP порт для WireGuard')
    args = ap.parse_args()
    asyncio.run(main(args.server))
