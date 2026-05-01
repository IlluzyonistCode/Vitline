'''
Vitline — симулятор NAS (роутера).
Тестирует RADIUS Auth + Accounting без реального железа.

Запуск (пока main.py запущен в другом терминале):
  python tests/sim_nas.py
'''
import hashlib, os, socket, struct, time

SECRET    = os.getenv('RADIUS_SECRET', 'testing123').encode()
AUTH_ADDR = ('127.0.0.1', 1812)
ACCT_ADDR = ('127.0.0.1', 1813)


def encrypt_password(password, secret, authenticator):
    pw     = password.encode().ljust(((len(password)+15)//16)*16, b'\x00')
    result = b''
    prev   = authenticator
    for i in range(0, len(pw), 16):
        digest  = hashlib.md5(secret + prev).digest()
        chunk   = bytes(a ^ b for a, b in zip(pw[i:i+16], digest))
        result += chunk
        prev    = chunk
    return result


def build_access_request(username, password):
    auth  = os.urandom(16)
    un    = username.encode()
    enc   = encrypt_password(password, SECRET, auth)
    nas   = bytes([192, 168, 1, 1])
    attrs = b''
    attrs += struct.pack('BB', 1, 2+len(un)) + un
    attrs += struct.pack('BB', 2, 2+len(enc)) + enc
    attrs += struct.pack('BB', 4, 6) + nas
    attrs += struct.pack('BBI', 5, 6, 1)
    length = 20 + len(attrs)
    return struct.pack('!BBH16s', 1, 42, length, auth) + attrs


def build_accounting(username, session_id, status, rx=0, tx=0, duration=0):
    auth  = b'\x00' * 16
    un    = username.encode()
    sid   = session_id.encode()
    attrs = b''
    attrs += struct.pack('BB', 1,  2+len(un))  + un
    attrs += struct.pack('BB', 44, 2+len(sid)) + sid
    attrs += struct.pack('BBI', 40, 6, status)
    if rx:       attrs += struct.pack('BBI', 42, 6, rx % 2**32)
    if tx:       attrs += struct.pack('BBI', 43, 6, tx % 2**32)
    if duration: attrs += struct.pack('BBI', 46, 6, duration)
    length    = 20 + len(attrs)
    auth_data = struct.pack('!BBH', 4, 99, length) + auth + attrs + SECRET
    auth      = hashlib.md5(auth_data).digest()
    return struct.pack('!BBH16s', 4, 99, length, auth) + attrs


def udp(data, addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(data, addr)
    resp, _ = s.recvfrom(4096)
    s.close()
    return resp


CODES = {2: 'Accept ✓', 3: 'Reject ✗', 5: 'Acct-Response ✓'}


def run():
    sep = '─' * 52
    print(sep)
    print('Vitline — Auth тесты')
    print(sep)
    for user, pw, expect, label in [
        ('test1', 'password123', True,  'верный пароль'),
        ('test1', 'wrongpass',   False, 'неверный пароль'),
        ('ghost', 'anything',    False, 'неизвестный пользователь'),
        ('test2', 'qwerty456',   True,  'второй абонент'),
    ]:
        try:
            resp   = udp(build_access_request(user, pw), AUTH_ADDR)
            actual = resp[0] == 2
            status = 'OK  ' if actual == expect else 'FAIL'
            print(f'  [{status}]  {label:<35}  {CODES.get(resp[0], str(resp[0]))}')
        except Exception as e:
            print(f'  [ERR]  {label:<35}  {e}')

    print()
    print(sep)
    print('Vitline — Accounting тесты')
    print(sep)
    sess = f'vitline-{int(time.time())}'
    for status, label, kw in [
        (1, 'START',   {}),
        (3, 'INTERIM', {'rx': 50*1024*1024, 'tx': 10*1024*1024, 'duration': 300}),
        (2, 'STOP',    {'rx': 200*1024*1024, 'tx': 40*1024*1024, 'duration': 1800}),
    ]:
        try:
            resp = udp(build_accounting('test1', sess, status, **kw), ACCT_ADDR)
            print(f'  [OK  ]  Acct {label:<8}  {CODES.get(resp[0], str(resp[0]))}')
        except Exception as e:
            print(f'  [ERR]  Acct {label:<8}  {e}')
    print()


if __name__ == '__main__':
    run()
