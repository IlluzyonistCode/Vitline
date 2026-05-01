'''
Vitline DNS — приватный резолвер без цензуры.

Два режима (выбери один):

  1. CoreDNS (рекомендую) — конфиг ниже, запускается одной командой.
     Форвардит через DNS-over-TLS на Quad9 / Cloudflare / AdGuard.
     Не логирует запросы абонентов.

  2. Python DoH-прокси (этот файл) — если нет CoreDNS.
     Принимает UDP DNS на :5353, форвардит через HTTPS (DoH).
     Запуск: python dns/resolver.py

Установка CoreDNS:
  # Скачать бинарник с github.com/coredns/coredns/releases
  wget https://github.com/coredns/coredns/releases/download/v1.11.3/coredns_1.11.3_linux_amd64.tgz
  tar xzf coredns_*.tgz
  mv coredns /usr/local/bin/
  coredns -conf /etc/vitline/Corefile
'''
import asyncio
import logging
import os
import struct
import time
import urllib.request

logger = logging.getLogger('dns')

LISTEN_PORT  = int(os.getenv('DNS_PORT',   '5353'))
DOH_ENDPOINT = os.getenv('DOH_URL', 'https://dns.quad9.net/dns-query')
CACHE_TTL    = int(os.getenv('DNS_CACHE_TTL', '60'))


# ── простой DNS-кэш ───────────────────────────────────────────────────────────

class DnsCache:

    def __init__(self, ttl=CACHE_TTL):
        self.ttl   = ttl
        self._data = {}

    def get(self, key):
        entry = self._data.get(key)
        if entry and time.time() - entry['ts'] < self.ttl:
            return entry['data']
        return None

    def set(self, key, data):
        self._data[key] = {'data': data, 'ts': time.time()}

    def size(self):
        return len(self._data)

    def evict_expired(self):
        now    = time.time()
        stale  = [k for k, v in self._data.items() if now - v['ts'] >= self.ttl]
        for k in stale:
            del self._data[k]
        return len(stale)


cache = DnsCache()


# ── DoH-запрос (DNS over HTTPS) ───────────────────────────────────────────────

def doh_query(dns_wire):
    '''Отправить DNS-запрос через HTTPS, вернуть ответ в wire-формате.'''
    req = urllib.request.Request(
        DOH_ENDPOINT,
        data    = dns_wire,
        method  = 'POST',
        headers = {
            'Content-Type': 'application/dns-message',
            'Accept':       'application/dns-message',
        }
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read()


# ── парсинг DNS-заголовка для кэш-ключа ──────────────────────────────────────

def dns_cache_key(wire):
    '''Извлечь (QNAME, QTYPE) для ключа кэша.'''
    try:
        pos    = 12
        labels = []
        while pos < len(wire):
            length = wire[pos]
            if length == 0:
                pos += 1
                break
            labels.append(wire[pos+1:pos+1+length].decode('ascii', errors='replace'))
            pos += 1 + length
        qname  = '.'.join(labels).lower()
        qtype  = struct.unpack_from('>H', wire, pos)[0] if pos + 2 <= len(wire) else 0
        return f'{qname}:{qtype}'
    except Exception:
        return None


def patch_transaction_id(response, txid):
    '''Подменить transaction ID в ответе на ID из запроса.'''
    return struct.pack('>H', txid) + response[2:]


# ── UDP-сервер ────────────────────────────────────────────────────────────────

class DnsProxyProtocol(asyncio.DatagramProtocol):

    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data, addr):
        if len(data) < 12:
            return

        txid     = struct.unpack_from('>H', data, 0)[0]
        cache_key = dns_cache_key(data)

        # проверяем кэш (без transaction ID)
        if cache_key:
            cached = cache.get(cache_key)
            if cached:
                self.transport.sendto(patch_transaction_id(cached, txid), addr)
                return

        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(None, doh_query, data)
        except Exception as e:
            logger.warning('DoH ошибка: %s', e)
            # SERVFAIL
            self.transport.sendto(
                data[:2] + b'\x81\x82' + data[4:], addr
            )
            return

        if cache_key and response:
            cache.set(cache_key, response)

        self.transport.sendto(response, addr)


# ── периодическая очистка кэша ────────────────────────────────────────────────

async def cache_evict_loop():
    while True:
        await asyncio.sleep(120)
        evicted = cache.evict_expired()
        if evicted:
            logger.debug('кэш: убрано %d записей, осталось %d', evicted, cache.size())


# ── запуск ────────────────────────────────────────────────────────────────────

async def run_dns():
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        DnsProxyProtocol,
        local_addr=('0.0.0.0', LISTEN_PORT)
    )
    asyncio.create_task(cache_evict_loop())
    logger.info('dns proxy  0.0.0.0:%d  →  %s', LISTEN_PORT, DOH_ENDPOINT)
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        transport.close()


if __name__ == '__main__':
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    logging.basicConfig(
        level  = logging.INFO,
        format = '%(asctime)s  %(levelname)-7s  %(name)s — %(message)s',
    )
    asyncio.run(run_dns())
