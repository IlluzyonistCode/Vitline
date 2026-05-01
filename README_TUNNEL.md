# Vitline — туннель WireGuard поверх HTTPS

## Зачем

WireGuard работает по UDP. ТСПУ и DPI умеют блокировать
нестандартный UDP-трафик — особенно порт 51820.

Решение: завернуть WireGuard-пакеты в WebSocket поверх TLS (порт 443).
Для DPI это выглядит как обычный HTTPS-сайт.

## Архитектура

```
Абонент                              Сервер Vitline
─────────────────────────────────────────────────────
[WG app] ──UDP──► [tunnel/client.py] ──wss://──► [Nginx :443]
:51820             :51820 (loopback)    /wg           │
                                                  [tunnel/ws_bridge.py :8443]
                                                       │ UDP
                                                  [WireGuard wg0 :51820]
```

## Сервер — установка

### Вариант A: Python (уже есть в проекте)

```bash
# добавить в main.py или запустить отдельно
python tunnel/ws_bridge.py

# systemd unit
cp deploy/vitline-tunnel.service /etc/systemd/system/
systemctl enable --now vitline-tunnel
```

### Вариант B: wstunnel (рекомендую для продакшна — написан на Rust, быстрее)

```bash
# на сервере
wget https://github.com/erebe/wstunnel/releases/latest/download/wstunnel_linux_amd64.tar.gz
tar xzf wstunnel_*.tar.gz
mv wstunnel /usr/local/bin/

# запустить сервер (WS → UDP WireGuard)
wstunnel server --restrict-to 127.0.0.1:51820 wss://0.0.0.0:8443
```

## Клиент — Windows

### Вариант A: wstunnel.exe (рекомендую)

1. Скачать `wstunnel_windows_amd64.zip` с:
   https://github.com/erebe/wstunnel/releases

2. Распаковать, запустить в PowerShell:
```powershell
.\wstunnel.exe client `
  --local-to-remote "udp://127.0.0.1:51820/127.0.0.1:51820" `
  wss://vpn.vitline.net/wg
```

3. В WireGuard-конфиге изменить Endpoint:
```ini
[Peer]
Endpoint = 127.0.0.1:51820   # ← туннель, не реальный сервер
```

### Вариант B: Python-клиент (tunnel/client.py)

```cmd
python tunnel\client.py --server wss://vpn.vitline.net/wg
```

## Клиент — Linux / macOS

```bash
# wstunnel
wstunnel client \
  --local-to-remote "udp://127.0.0.1:51820/127.0.0.1:51820" \
  wss://vpn.vitline.net/wg &

# или Python
python tunnel/client.py --server wss://vpn.vitline.net/wg &

# затем wg-quick up wg0
```

## Nginx

Скопировать tunnel/nginx.conf в /etc/nginx/sites-available/vitline,
заменить vpn.yourdomain.com на свой домен, получить сертификат:

```bash
certbot --nginx -d vpn.yourdomain.com
```

## Почему это сложно заблокировать

- Трафик идёт на порт 443 (HTTPS)
- TLS-сертификат настоящий (Let's Encrypt)
- WebSocket handshake — стандартный HTTP Upgrade
- Содержимое зашифровано — DPI не видит WG-пакеты внутри
- Домен выглядит как обычный сайт (личный кабинет на том же домене)

Заблокировать можно только заблокировав весь домен целиком,
но тогда блокируется и личный кабинет — шум и жалобы.
