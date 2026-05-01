'''
Слой БД — MySQL через aiomysql.
Таблицы: tariffs, ip_pools, subscribers, sessions, usage_log
'''
import logging

import aiomysql

logger = logging.getLogger(__name__)


SCHEMA = [

    '''
    CREATE TABLE IF NOT EXISTS tariffs (
        id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name             VARCHAR(64)  NOT NULL UNIQUE,
        rate_down_kbps   INT UNSIGNED NOT NULL DEFAULT 102400,
        rate_up_kbps     INT UNSIGNED NOT NULL DEFAULT 102400,
        session_timeout  INT UNSIGNED DEFAULT NULL,
        monthly_gb       FLOAT        DEFAULT NULL,
        active           TINYINT(1)   NOT NULL DEFAULT 1
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ''',

    '''
    CREATE TABLE IF NOT EXISTS ip_pools (
        id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        tariff_id   INT UNSIGNED NOT NULL,
        ip_address  VARCHAR(45)  NOT NULL UNIQUE,
        in_use      TINYINT(1)   NOT NULL DEFAULT 0,
        assigned_to VARCHAR(64)  DEFAULT NULL,
        assigned_at DATETIME     DEFAULT NULL,
        FOREIGN KEY (tariff_id) REFERENCES tariffs(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ''',

    '''
    CREATE TABLE IF NOT EXISTS subscribers (
        id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        username    VARCHAR(64)  NOT NULL UNIQUE,
        password    VARCHAR(255) NOT NULL,
        tariff_id   INT UNSIGNED NOT NULL,
        active      TINYINT(1)   NOT NULL DEFAULT 1,
        created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        notes       TEXT         DEFAULT NULL,
        FOREIGN KEY (tariff_id) REFERENCES tariffs(id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ''',

    '''
    CREATE TABLE IF NOT EXISTS sessions (
        id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        username    VARCHAR(64)  NOT NULL,
        session_id  VARCHAR(64)  NOT NULL UNIQUE,
        nas_ip      VARCHAR(45)  DEFAULT NULL,
        started_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_update DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
                                 ON UPDATE CURRENT_TIMESTAMP,
        rx_bytes    BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tx_bytes    BIGINT UNSIGNED NOT NULL DEFAULT 0,
        INDEX idx_username (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ''',

    '''
    CREATE TABLE IF NOT EXISTS usage_log (
        id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        username    VARCHAR(64)     NOT NULL,
        rx_bytes    BIGINT UNSIGNED NOT NULL DEFAULT 0,
        tx_bytes    BIGINT UNSIGNED NOT NULL DEFAULT 0,
        duration_s  INT UNSIGNED    NOT NULL DEFAULT 0,
        logged_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_username_date (username, logged_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    ''',

]


SEED = '''
INSERT IGNORE INTO tariffs (name, rate_down_kbps, rate_up_kbps, monthly_gb) VALUES
    ('Старт 30',      30720,   10240, 30),
    ('Стандарт 100', 102400,   51200, NULL),
    ('Турбо 500',    512000,  102400, NULL);

INSERT IGNORE INTO subscribers (username, password, tariff_id) VALUES
    ('test1', 'password123', 1),
    ('test2', 'qwerty456',   2);

INSERT IGNORE INTO ip_pools (tariff_id, ip_address) VALUES
    (1, '10.10.1.1'), (1, '10.10.1.2'), (1, '10.10.1.3'),
    (2, '10.10.2.1'), (2, '10.10.2.2'), (2, '10.10.2.3'),
    (3, '10.10.3.1'), (3, '10.10.3.2');
'''


class Database:

    def __init__(self, host, port, user, password, db):
        self._cfg  = dict(host=host, port=port, user=user, password=password, db=db,
                          charset='utf8mb4', autocommit=True)
        self.pool  = None

    async def connect(self):
        self.pool = await aiomysql.create_pool(minsize=2, maxsize=10, **self._cfg)

        async with self.pool.acquire() as conn:
            async with conn.cursor() as cur:
                for stmt in SCHEMA:
                    await cur.execute(stmt)

        logger.info('mysql подключена  %s:%d/%s',
                    self._cfg['host'], self._cfg['port'], self._cfg['db'])

    async def close(self):
        if self.pool:
            self.pool.close()
            await self.pool.wait_closed()

    # ── internal helpers ──────────────────────────────────────────────────────

    async def _fetchone(self, sql, *args):
        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(sql, args)
                return await cur.fetchone()

    async def _fetchall(self, sql, *args):
        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(sql, args)
                return await cur.fetchall()

    async def _execute(self, sql, *args):
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(sql, args)
                return cur.rowcount

    # ── абоненты ──────────────────────────────────────────────────────────────

    async def get_subscriber(self, username):
        return await self._fetchone(
            'SELECT * FROM subscribers WHERE username = %s', username
        )

    async def add_subscriber(self, username, password, tariff_id):
        await self._execute(
            'INSERT INTO subscribers (username, password, tariff_id) VALUES (%s,%s,%s)',
            username, password, tariff_id
        )

    async def set_active(self, username, active):
        await self._execute(
            'UPDATE subscribers SET active = %s WHERE username = %s',
            int(active), username
        )

    # ── тарифы ────────────────────────────────────────────────────────────────

    async def get_tariff(self, tariff_id):
        return await self._fetchone(
            'SELECT * FROM tariffs WHERE id = %s', tariff_id
        ) or {}

    async def list_tariffs(self):
        return await self._fetchall(
            'SELECT * FROM tariffs WHERE active = 1 ORDER BY id'
        )

    # ── IP-пул ────────────────────────────────────────────────────────────────

    async def allocate_ip(self, username, tariff_id):
        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cur:

                # уже выдан?
                await cur.execute(
                    'SELECT ip_address FROM ip_pools '
                    'WHERE assigned_to = %s AND in_use = 1 LIMIT 1',
                    (username,)
                )
                row = await cur.fetchone()
                if row:
                    return row['ip_address']

                # берём свободный — SELECT ... FOR UPDATE без SKIP LOCKED
                # (MySQL 8+  поддерживает SKIP LOCKED)
                await cur.execute(
                    'SELECT id, ip_address FROM ip_pools '
                    'WHERE tariff_id = %s AND in_use = 0 '
                    'ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED',
                    (tariff_id,)
                )
                row = await cur.fetchone()
                if not row:
                    logger.warning('IP-пул тарифа %d исчерпан', tariff_id)
                    return None

                await cur.execute(
                    'UPDATE ip_pools SET in_use=1, assigned_to=%s, '
                    'assigned_at=NOW() WHERE id=%s',
                    (username, row['id'])
                )
                await conn.commit()
                return row['ip_address']

    async def release_ip(self, username):
        await self._execute(
            'UPDATE ip_pools SET in_use=0, assigned_to=NULL, assigned_at=NULL '
            'WHERE assigned_to = %s',
            username
        )

    # ── статистика ────────────────────────────────────────────────────────────

    async def record_usage(self, username, rx, tx, duration):
        await self._execute(
            'INSERT INTO usage_log (username, rx_bytes, tx_bytes, duration_s) '
            'VALUES (%s,%s,%s,%s)',
            username, rx, tx, duration
        )

    async def monthly_usage(self, username):
        row = await self._fetchone(
            'SELECT COALESCE(SUM(rx_bytes),0) rx, COALESCE(SUM(tx_bytes),0) tx '
            'FROM usage_log '
            'WHERE username=%s AND logged_at >= DATE_FORMAT(NOW(), "%%Y-%%m-01")',
            username
        )
        return row or {'rx': 0, 'tx': 0}

    async def active_sessions(self):
        return await self._fetchall(
            'SELECT s.*, sub.tariff_id '
            'FROM sessions s '
            'JOIN subscribers sub ON sub.username = s.username '
            'ORDER BY s.started_at DESC'
        )

    async def seed(self):
        async with self.pool.acquire() as conn:
            async with conn.cursor() as cur:
                for stmt in SEED.strip().split(';'):
                    stmt = stmt.strip()
                    if stmt:
                        await cur.execute(stmt)
        logger.info('тестовые данные загружены')
