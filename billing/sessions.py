'''
Менеджер активных сессий.
In-memory словарь + синхронизация с MySQL.
'''
import asyncio
import logging
import time

logger = logging.getLogger(__name__)


class Session:

    def __init__(self, username, session_id, nas_ip):
        self.username   = username
        self.session_id = session_id
        self.nas_ip     = nas_ip
        self.started_at = time.time()
        self.rx_bytes   = 0
        self.tx_bytes   = 0


class SessionManager:

    def __init__(self, db):
        self.db       = db
        self._store   = {}   # session_id → Session
        self._lock    = asyncio.Lock()

    async def start(self, username, session_id, nas_ip):
        async with self._lock:
            self._store[session_id] = Session(username, session_id, nas_ip)

        await self.db._execute(
            'INSERT IGNORE INTO sessions (username, session_id, nas_ip) '
            'VALUES (%s,%s,%s)',
            username, session_id, nas_ip
        )

    async def update(self, session_id, rx, tx):
        async with self._lock:
            sess = self._store.get(session_id)
            if sess:
                sess.rx_bytes = rx
                sess.tx_bytes = tx

        await self.db._execute(
            'UPDATE sessions SET rx_bytes=%s, tx_bytes=%s '
            'WHERE session_id=%s',
            rx, tx, session_id
        )

    async def stop(self, username, session_id, rx, tx, duration):
        async with self._lock:
            self._store.pop(session_id, None)

        await self.db.release_ip(username)
        await self.db._execute(
            'DELETE FROM sessions WHERE session_id=%s', session_id
        )

    async def count(self):
        async with self._lock:
            return len(self._store)

    async def list_all(self):
        async with self._lock:
            return list(self._store.values())

    async def cleanup_stale(self, max_idle=3600):
        now    = time.time()
        stale  = []

        async with self._lock:
            for sess in list(self._store.values()):
                if now - sess.started_at > max_idle:
                    stale.append(sess)

        for sess in stale:
            logger.warning('зависшая сессия: %s  sess=%s', sess.username, sess.session_id)
            await self.stop(
                sess.username, sess.session_id,
                sess.rx_bytes, sess.tx_bytes,
                int(now - sess.started_at)
            )
