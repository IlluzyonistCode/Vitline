'''
Vitline — WS-туннель для маскировки WireGuard под HTTPS.

Схема:
  [Абонент WG-клиент]
       ↓ UDP :51820
  [wstunnel-client на машине абонента]
       ↓ WebSocket wss://server:443/wg
  [Nginx (TLS termination)]
       ↓ ws://127.0.0.1:8443/wg
  [wstunnel-server / этот скрипт]
       ↓ UDP → 127.0.0.1:51820
  [WireGuard wg0]

DPI видит: обычное TLS-соединение на 443 с WebSocket upgrade.
Заблокировать без ложных срабатываний — очень сложно.

Этот файл — Python-реализация WS↔UDP моста.
Для продакшна рекомендуем готовый бинарник wstunnel:
  https://github.com/erebe/wstunnel/releases
'''
import asyncio
import logging
import os
import struct

logger = logging.getLogger('tunnel.ws')

WS_HOST    = os.getenv('WS_HOST',    '0.0.0.0')
WS_PORT    = int(os.getenv('WS_PORT', '8443'))
WG_HOST    = os.getenv('WG_TARGET_HOST', '127.0.0.1')
WG_PORT    = int(os.getenv('WG_TARGET_PORT', '51820'))
MAX_CLIENTS = int(os.getenv('MAX_CLIENTS', '500'))


# ── WireGuard UDP ↔ WebSocket мост ───────────────────────────────────────────

class WsUdpBridge:
    '''
    Один экземпляр = одно WebSocket-соединение ↔ один UDP-сокет до WG.
    '''

    def __init__(self, ws_writer, wg_addr):
        self.ws_writer  = ws_writer
        self.wg_addr    = wg_addr        # (host, port)
        self.transport  = None
        self.protocol   = None
        self._closed    = False

    async def start(self):
        loop = asyncio.get_running_loop()
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: _UdpReceiver(self),
            remote_addr=self.wg_addr,
        )

    async def from_client(self, data):
        '''Данные пришли от WS-клиента → отправляем в WireGuard UDP.'''
        if self.transport and not self._closed:
            self.transport.sendto(data)

    async def from_wg(self, data):
        '''Данные пришли от WireGuard → отправляем клиенту по WS.'''
        if self._closed:
            return
        try:
            frame = _ws_frame(data, opcode=0x2)   # binary frame
            self.ws_writer.write(frame)
            await self.ws_writer.drain()
        except Exception as e:
            logger.debug('ws write: %s', e)
            self.close()

    def close(self):
        self._closed = True
        if self.transport:
            self.transport.close()


class _UdpReceiver(asyncio.DatagramProtocol):

    def __init__(self, bridge):
        self.bridge = bridge

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self.bridge.from_wg(data))

    def error_received(self, exc):
        logger.debug('udp error: %s', exc)


# ── минимальный WebSocket парсер / сериализатор ───────────────────────────────

def _ws_handshake_response(key):
    import base64, hashlib
    magic   = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    accept  = base64.b64encode(
        hashlib.sha1((key + magic).encode()).digest()
    ).decode()
    return (
        'HTTP/1.1 101 Switching Protocols\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        f'Sec-WebSocket-Accept: {accept}\r\n'
        '\r\n'
    ).encode()


def _ws_frame(data, opcode=0x2):
    '''Сериализовать бинарный WebSocket-фрейм (сервер → клиент, без маски).'''
    length = len(data)
    if length < 126:
        header = struct.pack('BB', 0x80 | opcode, length)
    elif length < 65536:
        header = struct.pack('!BBH', 0x80 | opcode, 126, length)
    else:
        header = struct.pack('!BBQ', 0x80 | opcode, 127, length)
    return header + data


def _ws_parse_frame(buf):
    '''
    Разобрать входящий WebSocket-фрейм (клиент → сервер, с маской).
    Возвращает (payload_bytes, bytes_consumed) или (None, 0).
    '''
    if len(buf) < 2:
        return None, 0

    b0, b1  = buf[0], buf[1]
    masked  = bool(b1 & 0x80)
    length  = b1 & 0x7f
    pos     = 2

    if length == 126:
        if len(buf) < 4:
            return None, 0
        length = struct.unpack_from('>H', buf, 2)[0]
        pos    = 4
    elif length == 127:
        if len(buf) < 10:
            return None, 0
        length = struct.unpack_from('>Q', buf, 2)[0]
        pos    = 10

    if masked:
        if len(buf) < pos + 4:
            return None, 0
        mask = buf[pos:pos+4]
        pos += 4

    if len(buf) < pos + length:
        return None, 0

    payload = bytearray(buf[pos:pos+length])
    if masked:
        for i in range(length):
            payload[i] ^= mask[i % 4]

    return bytes(payload), pos + length


# ── TCP-сервер (принимает WebSocket-соединения) ───────────────────────────────

class _WsServerProtocol(asyncio.Protocol):

    def __init__(self):
        self.transport  = None
        self.bridge     = None
        self._buf       = b''
        self._upgraded  = False
        self._ws_key    = None

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info('peername')
        logger.debug('ws connect: %s', peer)

    def data_received(self, data):
        self._buf += data
        if not self._upgraded:
            self._try_upgrade()
        else:
            asyncio.ensure_future(self._handle_frames())

    def _try_upgrade(self):
        if b'\r\n\r\n' not in self._buf:
            return
        head, rest = self._buf.split(b'\r\n\r\n', 1)
        headers    = {}
        for line in head.split(b'\r\n')[1:]:
            if b':' in line:
                k, v = line.split(b':', 1)
                headers[k.strip().lower()] = v.strip().decode()

        key = headers.get(b'sec-websocket-key', headers.get('sec-websocket-key', ''))
        if not key:
            self.transport.close()
            return

        self.transport.write(_ws_handshake_response(key))
        self._upgraded = True
        self._buf      = rest

        # создать UDP-мост до WG
        asyncio.ensure_future(self._start_bridge())

    async def _start_bridge(self):
        loop = asyncio.get_running_loop()

        writer_transport = self.transport

        class _FakeWriter:
            def write(self, data):
                writer_transport.write(data)
            async def drain(self):
                pass

        self.bridge = WsUdpBridge(_FakeWriter(), (WG_HOST, WG_PORT))
        await self.bridge.start()

        # обработать накопившиеся данные
        if self._buf:
            await self._handle_frames()

    async def _handle_frames(self):
        while self._buf:
            payload, consumed = _ws_parse_frame(self._buf)
            if consumed == 0:
                break
            self._buf = self._buf[consumed:]
            if payload and self.bridge:
                await self.bridge.from_client(payload)

    def connection_lost(self, exc):
        if self.bridge:
            self.bridge.close()
        logger.debug('ws disconnect')


# ── запуск сервера ────────────────────────────────────────────────────────────

async def run_ws_tunnel():
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        _WsServerProtocol,
        host = WS_HOST,
        port = WS_PORT,
    )
    logger.info('ws-tunnel  %s:%d  →  wg %s:%d', WS_HOST, WS_PORT, WG_HOST, WG_PORT)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    logging.basicConfig(
        level  = logging.INFO,
        format = '%(asctime)s  %(levelname)-7s  %(name)s — %(message)s',
    )
    asyncio.run(run_ws_tunnel())
