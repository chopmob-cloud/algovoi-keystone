# AlgoVoi Keystone Control

Browser panel for installed AlgoVoi keystone packages. Auto-detects which keystone steps are present in the environment, shows their current settings, and lets operators edit them with a pin-gated editor.

Runs over HTTPS out of the box. A self-signed TLS certificate is generated on first start and reused on subsequent runs. Bring your own cert by setting `ALGV_TLS_CERT` and `ALGV_TLS_KEY`.

## Requirements

- Python 3.11+, Linux x86_64
- At least one AlgoVoi keystone package installed in the same environment

## Install

```bash
pip install algovoi-keystone-control
```

## Run

```bash
ALGV_ADMIN_TOKEN=<your-token> algv-keystone
```

The panel starts on `https://0.0.0.0:8077`. Open it in a browser and accept the self-signed certificate, or point your browser at a trusted cert with `ALGV_TLS_CERT`.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ALGV_ADMIN_TOKEN` | (required) | Bearer token for panel access |
| `ALGV_PORT` | `8077` | Listening port |
| `ALGV_HOST` | `0.0.0.0` | Listening address |
| `ALGV_DATA_DIR` | `~/.algv/keystone` | TLS cert and settings storage |
| `ALGV_TLS_CERT` | (auto) | Path to a BYO TLS certificate |
| `ALGV_TLS_KEY` | (auto) | Path to a BYO TLS private key |

### Systemd example

```ini
[Unit]
Description=AlgoVoi Keystone Control
After=network.target

[Service]
User=algv
EnvironmentFile=/etc/algv/keystone.env
ExecStart=/opt/algv/.venv/bin/algv-keystone
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`/etc/algv/keystone.env` (mode 0600):

```
ALGV_ADMIN_TOKEN=<your-token>
ALGV_DATA_DIR=/var/lib/algv/keystone
```

## API

All endpoints require `Authorization: Bearer <token>`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/steps` | Installed keystone steps and their current settings |
| `GET` | `/v1/all-known` | All known keystone steps, installed and uninstalled |
| `PUT` | `/v1/settings/{step}` | Update settings for a step (pin-gated) |
| `POST` | `/v1/reset/{step}` | Reset a step to defaults (pin-gated) |

## License

Apache-2.0. See [NOTICE](NOTICE).
