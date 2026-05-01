'''
Конфиг — редактируй здесь или переопредели переменными окружения.
'''
import os

# ── MySQL ─────────────────────────────────────────────────────────────────────
DB_HOST     = os.getenv('DB_HOST',     '127.0.0.1')
DB_PORT     = int(os.getenv('DB_PORT', '3306'))
DB_USER     = os.getenv('DB_USER',     'isp')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'isp')
DB_NAME     = os.getenv('DB_NAME',     'isp')

# ── RADIUS ────────────────────────────────────────────────────────────────────
RADIUS_SECRET    = os.getenv('RADIUS_SECRET',    'testing123').encode()
RADIUS_HOST      = os.getenv('RADIUS_HOST',      '0.0.0.0')
RADIUS_AUTH_PORT = int(os.getenv('RADIUS_AUTH_PORT', '1812'))
RADIUS_ACCT_PORT = int(os.getenv('RADIUS_ACCT_PORT', '1813'))

# ── WireGuard ─────────────────────────────────────────────────────────────────
WG_INTERFACE = os.getenv('WG_INTERFACE', 'wg0')
WG_PORT      = int(os.getenv('WG_PORT',  '51820'))
WG_POOL_CIDR = os.getenv('WG_POOL_CIDR', '10.20.0.0/24')
WG_CONF_DIR  = os.getenv('WG_CONF_DIR',  '/etc/wireguard')
WG_ENDPOINT  = os.getenv('WG_ENDPOINT',  None)          # 'x.x.x.x:51820'
WG_DNS       = os.getenv('WG_DNS',       '1.1.1.1,1.0.0.1').split(',')

# ── BGP ───────────────────────────────────────────────────────────────────────
BGP_ROUTER_ID = os.getenv('BGP_ROUTER_ID', '192.168.1.1')
BGP_LOCAL_AS  = int(os.getenv('BGP_LOCAL_AS', '65001'))
BGP_PREFIXES  = os.getenv('BGP_PREFIXES',  '').split()   # '203.0.113.0/24 ...'
BGP_NEXT_HOP  = os.getenv('BGP_NEXT_HOP',  'self')

# ── Прочее ───────────────────────────────────────────────────────────────────
CLEANUP_INTERVAL = int(os.getenv('CLEANUP_INTERVAL', '300'))   # секунды
MAX_IDLE_SESSION = int(os.getenv('MAX_IDLE_SESSION',  '3600'))  # секунды
