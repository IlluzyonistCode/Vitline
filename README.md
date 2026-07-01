# Vitline

> *Run your network. Own every connection.*

![JSON](https://img.shields.io/badge/JSON-000000.svg?style=flat-square&logo=JSON&logoColor=white)  ![FastAPI](https://img.shields.io/badge/FastAPI-009688.svg?style=flat-square&logo=FastAPI&logoColor=white)  ![Python](https://img.shields.io/badge/Python-3776AB.svg?style=flat-square&logo=Python&logoColor=white)

## Overview

Vitline is a private ISP stack designed for censorship-resistant network operation. It unifies a FastAPI captive portal, RADIUS authentication, WireGuard peer management, ExaBGP route injection, DNS-over-HTTPS resolution, NetFlow monitoring with Grafana, and a WebSocket-over-TLS tunnel for DPI evasion — all launched from a single entry point.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Contributing](#contributing)
- [License](#license)

---

## Features

|      | Component         | Details                                                                                                                                                                                                                                          |
| :--- | :---------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ⚙️  | **Architecture**  | <ul><li>Async Python web service built on **FastAPI** + **Uvicorn** ASGI server</li><li>BGP anycast routing layer via **ExaBGP** for network-level traffic steering</li><li>MySQL backend accessed through fully async `aiomysql` driver</li><li>Reverse-proxied behind **Nginx** (`nginx.conf`)</li><li>Managed as a long-running **systemd** unit (`systemd.conf`)</li></ul> |
| 🔩 | **Code Quality**  | <ul><li>Pure Python (`*.py`) source with Jinja2 templating for HTML rendering</li><li>Dependencies pinned in `requirements.txt` for reproducible installs</li><li>No linter/formatter config detected (e.g., no `.flake8`, `pyproject.toml`, or `ruff.toml`)</li><li>No type-checking tooling (e.g., `mypy`) observed</li></ul> |
| 📄 | **Documentation** | <ul><li>License file present — baseline legal coverage</li><li>No dedicated docs site, wiki, or `docs/` directory detected</li><li>FastAPI provides **auto-generated OpenAPI/Swagger UI** at `/docs` out of the box</li><li>Grafana dashboard JSON (`grafana_dashboard.json`) serves as implicit operational documentation</li></ul> |
| 🔌 | **Integrations**  | <ul><li>**ExaBGP** (`exabgp.conf`) — BGP route injection for anycast/failover</li><li>**Grafana** (`grafana_dashboard.json`) — pre-built observability dashboard</li><li>**Nginx** (`nginx.conf`) — TLS termination & reverse proxy</li><li>**MySQL** — persistent data store via `aiomysql`</li><li>**systemd** — process supervision & service lifecycle</li></ul> |
| 🧩 | **Modularity**    | <ul><li>Clear separation of concerns: routing (ExaBGP), serving (FastAPI/Uvicorn), proxying (Nginx), persistence (MySQL)</li><li>Jinja2 templates (`*.html`) decoupled from business logic</li><li>Config files (`*.conf`, `*.json`) externalized from application code</li><li>No evidence of internal Python package/module structure (e.g., no `__init__.py` hierarchy detected)</li></ul> |

---

## Project Structure

```
└── Vitline/
    ├── __init__.py
    ├── bgp
    │   ├── __init__.py
    │   ├── daemon.py
    │   ├── exabgp.conf
    │   └── filters.py
    ├── billing
    │   ├── __init__.py
    │   ├── database.py
    │   └── sessions.py
    ├── config.py
    ├── deploy
    │   ├── __init__.py
    │   └── systemd.conf
    ├── dns
    │   ├── __init__.py
    │   ├── Corefile
    │   └── resolver.py
    ├── LICENSE
    ├── main.py
    ├── monitor
    │   ├── __init__.py
    │   ├── collector.py
    │   └── grafana_dashboard.json
    ├── portal
    │   ├── __init__.py
    │   ├── app.py
    │   └── templates
    ├── radius
    │   ├── __init__.py
    │   └── server.py
    ├── README.md
    ├── requirements.txt
    ├── tests
    │   ├── __init__.py
    │   └── sim_nas.py
    ├── tunnel
    │   ├── __init__.py
    │   ├── client.py
    │   ├── nginx.conf
    │   └── ws_bridge.py
    └── wireguard
        ├── __init__.py
        ├── manager.py
        └── output.py
```

---

## Getting Started

### Prerequisites

- Python 3.10+ / Node.js 18+ *(depending on the stack above)*

### Installation

```sh
git clone "https://github.com/IlluzyonistCode/Vitline
cd Vitline"
pip install -r requirements.txt
```

### Usage

```sh
python main.py
```

---

## Contributing

- [Report Issues](https://github.com/IlluzyonistCode/Vitline/issues)
- [Submit Pull Requests](https://github.com/IlluzyonistCode/Vitline/pulls)
- [Discussions](https://github.com/IlluzyonistCode/Vitline/discussions)

---

## License

Distributed under the [AGPL-3.0](LICENSE) license.
