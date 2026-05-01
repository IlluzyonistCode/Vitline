'''
ISP RADIUS Server
RFC 2865 (Auth :1812) + RFC 2866 (Accounting :1813)

Privacy-first — нет логирования MAC-адресов и NAS-идентификаторов абонентов
в постоянное хранилище. Только счётчики трафика и время сессии.
'''
import asyncio
import hashlib
import hmac
import logging
import struct

logger = logging.getLogger(__name__)


# ── Коды пакетов ─────────────────────────────────────────────────────────────

ACCESS_REQUEST      = 1
ACCESS_ACCEPT       = 2
ACCESS_REJECT       = 3
ACCOUNTING_REQUEST  = 4
ACCOUNTING_RESPONSE = 5

# ── Атрибуты (RFC 2865 / 2866) ───────────────────────────────────────────────

ATTR_USER_NAME             = 1
ATTR_USER_PASSWORD         = 2
ATTR_NAS_IP_ADDRESS        = 4
ATTR_NAS_PORT              = 5
ATTR_FRAMED_IP_ADDRESS     = 8
ATTR_FRAMED_IP_NETMASK     = 9
ATTR_REPLY_MESSAGE         = 18
ATTR_SESSION_TIMEOUT       = 27
ATTR_CALLING_STATION_ID    = 31
ATTR_ACCT_STATUS_TYPE      = 40
ATTR_ACCT_INPUT_OCTETS     = 42
ATTR_ACCT_OUTPUT_OCTETS    = 43
ATTR_ACCT_SESSION_ID       = 44
ATTR_ACCT_SESSION_TIME     = 46
ATTR_ACCT_INPUT_GIGAWORDS  = 52
ATTR_ACCT_OUTPUT_GIGAWORDS = 53
ATTR_VENDOR_SPECIFIC       = 26

ACCT_START   = 1
ACCT_STOP    = 2
ACCT_INTERIM = 3

MIKROTIK_VENDOR_ID = 14988


# ── Разбор пакета ─────────────────────────────────────────────────────────────

def parse_packet(data):
    if len(data) < 20:
        raise ValueError('слишком короткий пакет')

    code, identifier, length = struct.unpack('!BBH', data[:4])
    authenticator = data[4:20]
    attributes = {}

    pos = 20
    while pos + 2 <= length:
        attr_type = data[pos]
        attr_len  = data[pos + 1]
        if attr_len < 2 or pos + attr_len > length:
            break
        value = data[pos + 2 : pos + attr_len]
        attributes.setdefault(attr_type, []).append(value)
        pos += attr_len

    return {
        'code':          code,
        'identifier':    identifier,
        'authenticator': authenticator,
        'attributes':    attributes,
    }


def get_str(pkt, attr):
    vals = pkt['attributes'].get(attr)
    return vals[0].decode('utf-8', errors='replace') if vals else None


def get_bytes(pkt, attr):
    vals = pkt['attributes'].get(attr)
    return vals[0] if vals else None


def get_int(pkt, attr):
    val = get_bytes(pkt, attr)
    return struct.unpack('!I', val)[0] if val and len(val) == 4 else None


# ── Сборка пакета ─────────────────────────────────────────────────────────────

def build_response(code, identifier, req_auth, secret, attrs):
    body = b''
    for attr_type, value in attrs:
        body += struct.pack('BB', attr_type, 2 + len(value)) + value

    length    = 20 + len(body)
    auth_data = struct.pack('!BBH', code, identifier, length) + req_auth + body + secret
    resp_auth = hashlib.md5(auth_data).digest()

    return struct.pack('!BBH16s', code, identifier, length, resp_auth) + body


# ── PAP шифрование ───────────────────────────────────────────────────────────

def decrypt_password(encrypted, secret, authenticator):
    result = b''
    prev   = authenticator

    for i in range(0, len(encrypted), 16):
        digest  = hashlib.md5(secret + prev).digest()
        chunk   = bytes(a ^ b for a, b in zip(encrypted[i:i+16], digest))
        result += chunk
        prev    = encrypted[i:i+16]

    return result.rstrip(b'\x00').decode('utf-8', errors='replace')


def encrypt_password(password, secret, authenticator):
    pw      = password.encode('utf-8')
    pad_len = ((len(pw) + 15) // 16) * 16
    pw      = pw.ljust(pad_len, b'\x00')

    result = b''
    prev   = authenticator

    for i in range(0, pad_len, 16):
        digest  = hashlib.md5(secret + prev).digest()
        chunk   = bytes(a ^ b for a, b in zip(pw[i:i+16], digest))
        result += chunk
        prev    = chunk

    return result


# ── Mikrotik VSA для rate-limit ──────────────────────────────────────────────

def mikrotik_rate_limit(down_kbps, up_kbps):
    rate_str  = f'{up_kbps}k/{down_kbps}k'.encode('ascii')
    vendor_id = struct.pack('!I', MIKROTIK_VENDOR_ID)
    vsa_data  = vendor_id + struct.pack('BB', 8, 2 + len(rate_str)) + rate_str
    return (ATTR_VENDOR_SPECIFIC, vsa_data)


# ── Протокол ─────────────────────────────────────────────────────────────────

class RadiusProtocol(asyncio.DatagramProtocol):

    def __init__(self, secret, db, sessions):
        self.secret    = secret
        self.db        = db
        self.sessions  = sessions
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data, addr):
        try:
            pkt = parse_packet(data)
        except Exception as e:
            logger.warning('не удалось разобрать пакет от %s: %s', addr, e)
            return

        if pkt['code'] == ACCESS_REQUEST:
            response = await self._auth(pkt, addr)
        elif pkt['code'] == ACCOUNTING_REQUEST:
            response = await self._acct(pkt, addr)
        else:
            return

        if response:
            self.transport.sendto(response, addr)

    # ── Auth ──────────────────────────────────────────────────────────────────

    async def _auth(self, pkt, addr):
        username = get_str(pkt, ATTR_USER_NAME) or ''
        enc_pass = get_bytes(pkt, ATTR_USER_PASSWORD)

        logger.info('auth: user=%s from=%s', username, addr[0])

        if not enc_pass:
            return self._reject(pkt, 'no password')

        password   = decrypt_password(enc_pass, self.secret, pkt['authenticator'])
        subscriber = await self.db.get_subscriber(username)

        if not subscriber:
            logger.warning('неизвестный абонент: %s', username)
            return self._reject(pkt, 'unknown user')

        if not subscriber['active']:
            logger.warning('заблокирован: %s', username)
            return self._reject(pkt, 'account disabled')

        if not hmac.compare_digest(subscriber['password'], password):
            logger.warning('неверный пароль: %s', username)
            return self._reject(pkt, 'wrong password')

        ip     = await self.db.allocate_ip(username, subscriber['tariff_id'])
        tariff = await self.db.get_tariff(subscriber['tariff_id'])

        logger.info('accept: %s  ip=%s  tariff=%s', username, ip, tariff['name'])

        attrs = []

        if ip:
            ip_bytes = bytes(int(x) for x in ip.split('.'))
            attrs.append((ATTR_FRAMED_IP_ADDRESS, ip_bytes))
            attrs.append((ATTR_FRAMED_IP_NETMASK, bytes([255, 255, 255, 255])))

        if tariff.get('session_timeout'):
            attrs.append((ATTR_SESSION_TIMEOUT,
                          struct.pack('!I', tariff['session_timeout'])))

        if tariff.get('rate_down_kbps') and tariff.get('rate_up_kbps'):
            attrs.append(mikrotik_rate_limit(
                tariff['rate_down_kbps'], tariff['rate_up_kbps']
            ))

        return build_response(
            ACCESS_ACCEPT, pkt['identifier'], pkt['authenticator'], self.secret, attrs
        )

    def _reject(self, pkt, reason):
        attrs = [(ATTR_REPLY_MESSAGE, reason.encode('utf-8'))]
        return build_response(
            ACCESS_REJECT, pkt['identifier'], pkt['authenticator'], self.secret, attrs
        )

    # ── Accounting ────────────────────────────────────────────────────────────

    async def _acct(self, pkt, addr):
        status   = get_int(pkt, ATTR_ACCT_STATUS_TYPE)
        username = get_str(pkt, ATTR_USER_NAME) or ''
        sess_id  = get_str(pkt, ATTR_ACCT_SESSION_ID) or ''

        rx = (get_int(pkt, ATTR_ACCT_INPUT_OCTETS)       or 0) + \
             (get_int(pkt, ATTR_ACCT_INPUT_GIGAWORDS)     or 0) * 2**32
        tx = (get_int(pkt, ATTR_ACCT_OUTPUT_OCTETS)      or 0) + \
             (get_int(pkt, ATTR_ACCT_OUTPUT_GIGAWORDS)    or 0) * 2**32
        duration = get_int(pkt, ATTR_ACCT_SESSION_TIME) or 0

        if status == ACCT_START:
            logger.info('acct start: %s  sess=%s', username, sess_id)
            await self.sessions.start(username, sess_id, addr[0])

        elif status == ACCT_STOP:
            logger.info('acct stop:  %s  rx=%d  tx=%d  dur=%ds',
                        username, rx, tx, duration)
            await self.sessions.stop(username, sess_id, rx, tx, duration)
            await self.db.record_usage(username, rx, tx, duration)

        elif status == ACCT_INTERIM:
            logger.debug('acct interim: %s  rx=%d  tx=%d', username, rx, tx)
            await self.sessions.update(sess_id, rx, tx)

        return build_response(
            ACCOUNTING_RESPONSE, pkt['identifier'],
            pkt['authenticator'], self.secret, []
        )


# ── Запуск ────────────────────────────────────────────────────────────────────

async def start_radius(host, auth_port, acct_port, secret, db, sessions):
    loop = asyncio.get_running_loop()

    auth_t, _ = await loop.create_datagram_endpoint(
        lambda: RadiusProtocol(secret, db, sessions),
        local_addr=(host, auth_port)
    )
    acct_t, _ = await loop.create_datagram_endpoint(
        lambda: RadiusProtocol(secret, db, sessions),
        local_addr=(host, acct_port)
    )

    logger.info('radius auth  %s:%d', host, auth_port)
    logger.info('radius acct  %s:%d', host, acct_port)

    return auth_t, acct_t
