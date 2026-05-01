'''
Фильтр BGP-префиксов.

Две задачи:
  1. Не анонсировать наружу bogon/private-адреса (RFC 1918, 6598, loopback...)
  2. Не принимать от пиров слишком специфичные префиксы (длиннее /24 для IPv4)
     и сами bogon-маршруты — защита от route leak и route hijack.
'''
import ipaddress
import logging

logger = logging.getLogger('bgp.filter')


# ── Bogon-блоки (никогда не должны появляться в глобальной таблице) ──────────

IPV4_BOGONS = [
    '0.0.0.0/8',         # "this" network
    '10.0.0.0/8',        # RFC 1918
    '100.64.0.0/10',     # RFC 6598 shared address
    '127.0.0.0/8',       # loopback
    '169.254.0.0/16',    # link-local
    '172.16.0.0/12',     # RFC 1918
    '192.0.0.0/24',      # IETF protocol
    '192.0.2.0/24',      # TEST-NET-1
    '192.168.0.0/16',    # RFC 1918
    '198.18.0.0/15',     # benchmarking
    '198.51.100.0/24',   # TEST-NET-2
    '203.0.113.0/24',    # TEST-NET-3
    '224.0.0.0/4',       # multicast
    '240.0.0.0/4',       # reserved
    '255.255.255.255/32',
]

IPV6_BOGONS = [
    '::/128',            # unspecified
    '::1/128',           # loopback
    '::ffff:0:0/96',     # IPv4-mapped
    '64:ff9b::/96',      # IPv4-IPv6 translation
    '100::/64',          # discard
    '2001::/23',         # IETF protocol (включает 2001:db8 documentation)
    '2001:db8::/32',     # documentation
    'fc00::/7',          # ULA (unique local)
    'fe80::/10',         # link-local
    'ff00::/8',          # multicast
]

# максимальная длина префикса для приёма от пиров
MAX_PREFIX_LEN_V4 = 24
MAX_PREFIX_LEN_V6 = 48


class PrefixFilter:

    def __init__(self, max_v4=MAX_PREFIX_LEN_V4, max_v6=MAX_PREFIX_LEN_V6):
        self.max_v4   = max_v4
        self.max_v6   = max_v6
        self._bogon4  = [ipaddress.ip_network(p) for p in IPV4_BOGONS]
        self._bogon6  = [ipaddress.ip_network(p) for p in IPV6_BOGONS]

    def is_bogon(self, prefix_str):
        try:
            net = ipaddress.ip_network(prefix_str, strict=False)
        except ValueError:
            return True   # непарсируемый → отклоняем

        bogons = self._bogon4 if net.version == 4 else self._bogon6

        for bogon in bogons:
            if net.overlaps(bogon):
                return True

        return False

    def is_too_specific(self, prefix_str):
        try:
            net = ipaddress.ip_network(prefix_str, strict=False)
        except ValueError:
            return True

        if net.version == 4 and net.prefixlen > self.max_v4:
            return True
        if net.version == 6 and net.prefixlen > self.max_v6:
            return True

        return False

    def allow_announce(self, prefix_str):
        '''Проверить, можно ли анонсировать этот префикс наружу.'''
        if self.is_bogon(prefix_str):
            logger.warning('анонс отклонён (bogon): %s', prefix_str)
            return False
        return True

    def allow_receive(self, prefix_str):
        '''Проверить, принимать ли полученный от пира маршрут.'''
        if self.is_bogon(prefix_str):
            logger.warning('маршрут отклонён (bogon): %s', prefix_str)
            return False
        if self.is_too_specific(prefix_str):
            logger.warning('маршрут отклонён (слишком специфичный): %s', prefix_str)
            return False
        return True

    def filter_announce_list(self, prefixes):
        return [p for p in prefixes if self.allow_announce(p)]

    def filter_receive_list(self, prefixes):
        return [p for p in prefixes if self.allow_receive(p)]
