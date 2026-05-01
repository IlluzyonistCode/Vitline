'''
Vitline — коллектор трафика.

Слушает NetFlow v5/v9 на UDP :2055 и sFlow v5 на UDP :6343.
Агрегирует по абоненту и пишет в InfluxDB (для Grafana).
Параллельно обновляет MySQL счётчики в реальном времени.

Запуск:
  python monitor/collector.py

Требования:
  pip install influxdb-client
  На роутере Mikrotik включить:
    /ip traffic-flow set enabled=yes targets=<IP сервера>:2055
'''
import asyncio
import logging
import os
import struct
import time
from collections import defaultdict

logger = logging.getLogger('collector')

NETFLOW_PORT = int(os.getenv('NETFLOW_PORT', '2055'))
SFLOW_PORT   = int(os.getenv('SFLOW_PORT',   '6343'))
INFLUX_URL   = os.getenv('INFLUX_URL',   'http://localhost:8086')
INFLUX_TOKEN = os.getenv('INFLUX_TOKEN', '')
INFLUX_ORG   = os.getenv('INFLUX_ORG',  'vitline')
INFLUX_BUCKET = os.getenv('INFLUX_BUCKET', 'netflow')
FLUSH_INTERVAL = int(os.getenv('FLUSH_INTERVAL', '10'))   # секунды


# ── структура потока ──────────────────────────────────────────────────────────

class Flow:
    __slots__ = ('src_ip', 'dst_ip', 'src_port', 'dst_port',
                 'proto', 'bytes', 'packets', 'ts')

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto, nbytes, pkts):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto    = proto
        self.bytes    = nbytes
        self.packets  = pkts
        self.ts       = time.time()


# ── NetFlow v5 парсер ─────────────────────────────────────────────────────────

# NF5 header: 24 bytes
# version(2) count(2) uptime(4) unix_secs(4) unix_nsecs(4) flow_seq(4) engine_type(1) engine_id(1) sampling(2)
NF5_HEADER = '>HHIIIIBbH'

# NF5 record: 48 bytes
# srcaddr(4) dstaddr(4) nexthop(4) input(2) output(2) dPkts(4) dOctets(4)
# First(4) Last(4) srcport(2) dstport(2) pad(1) tcp_flags(1) prot(1) tos(1)
# src_as(2) dst_as(2) src_mask(1) dst_mask(1) pad2(2)
NF5_RECORD = '>4s4s4sHHIIIIHHBBBBHHBBH'

def parse_netflow_v5(data):
    if len(data) < 24:
        return []
    version = struct.unpack_from('>H', data, 0)[0]
    count   = struct.unpack_from('>H', data, 2)[0]
    if version != 5:
        return []

    flows  = []
    offset = 24
    for _ in range(min(count, 30)):
        if offset + 48 > len(data):
            break
        rec      = struct.unpack_from(NF5_RECORD, data, offset)
        src_ip   = '.'.join(str(b) for b in rec[0])
        dst_ip   = '.'.join(str(b) for b in rec[1])
        src_port = rec[9]
        dst_port = rec[10]
        nbytes   = rec[6]
        pkts     = rec[5]
        proto    = rec[13]
        flows.append(Flow(src_ip, dst_ip, src_port, dst_port, proto, nbytes, pkts))
        offset += 48

    return flows


# ── NetFlow v9 / IPFIX — упрощённый парсер ────────────────────────────────────

def parse_netflow_v9(data):
    '''
    Минимальный парсер v9: возвращаем пустой список если не можем разобрать.
    Полный парсер требует хранить шаблоны по (source_id, template_id).
    Для продакшна используй python-netflow или pmacct.
    '''
    if len(data) < 20:
        return []
    version = struct.unpack_from('>H', data, 0)[0]
    if version != 9:
        return []
    return []   # TODO: реализовать шаблонный движок v9


# ── sFlow v5 — упрощённый парсер ─────────────────────────────────────────────

def parse_sflow(data):
    '''
    Базовый парсер sFlow v5. Извлекаем sampled packet headers.
    '''
    if len(data) < 28:
        return []
    version = struct.unpack_from('>I', data, 0)[0]
    if version != 5:
        return []
    return []   # TODO: разобрать flow samples


# ── агрегатор ─────────────────────────────────────────────────────────────────

class FlowAggregator:
    '''
    Агрегирует потоки по абонентскому IP.
    Каждые FLUSH_INTERVAL секунд сбрасывает в InfluxDB и MySQL.
    '''

    def __init__(self, db, ip_to_user):
        self.db          = db
        self.ip_to_user  = ip_to_user    # dict: client_ip → username (кэш из MySQL)
        self._rx         = defaultdict(int)   # username → bytes
        self._tx         = defaultdict(int)
        self._lock       = asyncio.Lock()

    async def ingest(self, flows):
        async with self._lock:
            for f in flows:
                src_user = self.ip_to_user.get(f.src_ip)
                dst_user = self.ip_to_user.get(f.dst_ip)
                if src_user:
                    self._tx[src_user] += f.bytes
                if dst_user:
                    self._rx[dst_user] += f.bytes

    async def flush(self):
        async with self._lock:
            rx_snap = dict(self._rx)
            tx_snap = dict(self._tx)
            self._rx.clear()
            self._tx.clear()

        if not rx_snap and not tx_snap:
            return

        # пишем в InfluxDB
        await self._write_influx(rx_snap, tx_snap)

        # обновляем сессии в MySQL (живой счётчик)
        for username, rx in rx_snap.items():
            tx = tx_snap.get(username, 0)
            if self.db and self.db.pool:
                try:
                    await self.db._execute(
                        'UPDATE sessions SET rx_bytes = rx_bytes + %s, '
                        'tx_bytes = tx_bytes + %s WHERE username = %s',
                        rx, tx, username
                    )
                except Exception as e:
                    logger.debug('mysql update: %s', e)

    async def _write_influx(self, rx, tx):
        if not INFLUX_TOKEN:
            return

        lines = []
        ts_ns = int(time.time() * 1e9)
        all_users = set(rx) | set(tx)

        for user in all_users:
            r = rx.get(user, 0)
            t = tx.get(user, 0)
            safe_user = user.replace(' ', '_')
            lines.append(
                f'traffic,username={safe_user} rx_bytes={r}i,tx_bytes={t}i {ts_ns}'
            )

        if not lines:
            return

        payload = '\n'.join(lines).encode()
        url     = f'{INFLUX_URL}/api/v2/write?org={INFLUX_ORG}&bucket={INFLUX_BUCKET}&precision=ns'

        try:
            import urllib.request
            req = urllib.request.Request(
                url, data=payload, method='POST',
                headers={'Authorization': f'Token {INFLUX_TOKEN}',
                         'Content-Type': 'text/plain; charset=utf-8'}
            )
            urllib.request.urlopen(req, timeout=3)
            logger.debug('influx: записано %d метрик', len(lines))
        except Exception as e:
            logger.warning('influx write: %s', e)

    async def refresh_ip_map(self):
        '''Обновить кэш IP → username из MySQL.'''
        if not self.db or not self.db.pool:
            return
        try:
            rows = await self.db._fetchall(
                'SELECT ip_address, assigned_to FROM ip_pools WHERE in_use = 1'
            )
            for row in rows:
                if row['assigned_to']:
                    self.ip_to_user[row['ip_address']] = row['assigned_to']
        except Exception as e:
            logger.debug('refresh_ip_map: %s', e)


# ── UDP серверы ───────────────────────────────────────────────────────────────

class NetflowProtocol(asyncio.DatagramProtocol):

    def __init__(self, aggregator):
        self.agg = aggregator

    def datagram_received(self, data, addr):
        version = struct.unpack_from('>H', data, 0)[0] if len(data) >= 2 else 0
        if version == 5:
            flows = parse_netflow_v5(data)
        elif version == 9:
            flows = parse_netflow_v9(data)
        else:
            flows = []
        if flows:
            asyncio.ensure_future(self.agg.ingest(flows))


class SflowProtocol(asyncio.DatagramProtocol):

    def __init__(self, aggregator):
        self.agg = aggregator

    def datagram_received(self, data, addr):
        flows = parse_sflow(data)
        if flows:
            asyncio.ensure_future(self.agg.ingest(flows))


# ── главный цикл ──────────────────────────────────────────────────────────────

async def run_collector(db=None):
    loop = aggregator = FlowAggregator(db, {})

    if db and db.pool:
        await aggregator.refresh_ip_map()

    loop = asyncio.get_running_loop()

    nf_t, _ = await loop.create_datagram_endpoint(
        lambda: NetflowProtocol(aggregator),
        local_addr=('0.0.0.0', NETFLOW_PORT)
    )
    sf_t, _ = await loop.create_datagram_endpoint(
        lambda: SflowProtocol(aggregator),
        local_addr=('0.0.0.0', SFLOW_PORT)
    )

    logger.info('netflow  0.0.0.0:%d', NETFLOW_PORT)
    logger.info('sflow    0.0.0.0:%d', SFLOW_PORT)

    async def _flush_loop():
        while True:
            await asyncio.sleep(FLUSH_INTERVAL)
            await aggregator.flush()
            await aggregator.refresh_ip_map()

    asyncio.create_task(_flush_loop())

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        nf_t.close()
        sf_t.close()


if __name__ == '__main__':
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    logging.basicConfig(
        level  = logging.INFO,
        format = '%(asctime)s  %(levelname)-7s  %(name)s — %(message)s',
    )
    asyncio.run(run_collector())
