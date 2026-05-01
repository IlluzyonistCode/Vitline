# Vitline ISP

Приватный интернет-провайдер без цензуры и DPI.

## Компоненты

| Модуль | Описание | Порт |
|---|---|---|
| `radius/` | RADIUS авторизация RFC 2865/2866 | 1812/1813 UDP |
| `billing/` | MySQL: абоненты, тарифы, IP-пулы, статистика | — |
| `wireguard/` | WireGuard: ключи, пиры, конфиги | 51820 UDP |
| `bgp/` | BGP-демон (ExaBGP-контроллер) | — |
| `portal/` | Личный кабинет абонента (FastAPI) | 8080 TCP |
| `monitor/` | NetFlow/sFlow коллектор → InfluxDB | 2055/6343 UDP |
| `dns/` | DoH-прокси / CoreDNS без цензуры | 5353 UDP |
| `tunnel/` | WireGuard поверх WebSocket/HTTPS | 8443 TCP |
| `deploy/` | Systemd unit-файлы, env-конфиг | — |

## Быстрый старт

```bash
# 1. Зависимости
pip install -r requirements.txt
sudo apt install wireguard-tools mysql-server

# 2. MySQL
sudo mysql -e "CREATE DATABASE vitline; \
  CREATE USER 'vitline'@'localhost' IDENTIFIED BY 'ПАРОЛЬ'; \
  GRANT ALL ON vitline.* TO 'vitline'@'localhost';"

# 3. Конфиг
cp deploy/systemd.conf /etc/vitline/env   # отредактировать пароли!

# 4. Тестовые данные + запуск
python main.py seed
python main.py

# 5. Портал (отдельный процесс)
python main.py portal   # → http://localhost:8080
```

## CLI

```bash
python main.py adduser LOGIN PASS TARIFF_ID
python main.py block   LOGIN
python main.py unblock LOGIN
python main.py sessions
python main.py tariffs
python main.py usage   LOGIN
python main.py wg-add  LOGIN       # выдать WireGuard-конфиг
python main.py wg-list
python main.py wg-stats
```

## Тест на Windows (WSL2)

```powershell
wsl --install -d Ubuntu
# затем в WSL:
sudo apt install python3-pip mysql-server wireguard-tools
pip3 install -r requirements.txt
sudo service mysql start
python3 main.py seed
python3 tests/sim_nas.py   # симулятор NAS
python3 main.py portal     # портал на http://localhost:8080
```

## Схема обхода DPI/ТСПУ

```
Абонент → WireGuard → WebSocket/TLS :443 → Nginx → ws_bridge → wg0 → Интернет
```

DPI видит обычный HTTPS. Подробнее: tunnel/README_TUNNEL.md
