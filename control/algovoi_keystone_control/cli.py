"""Entry point for algovoi-keystone-control. Auto-generates TLS cert on first run."""
from __future__ import annotations
import os
from pathlib import Path


def main() -> None:
    import uvicorn
    from algovoi_keystone_control.tls import ensure_tls

    data_dir = Path(os.environ.get("ALGV_DATA_DIR", Path.home() / ".algv" / "keystone"))
    host = os.environ.get("ALGV_HOST", "0.0.0.0")
    port = int(os.environ.get("ALGV_PORT", "8077"))

    cert = os.environ.get("ALGV_TLS_CERT")
    key = os.environ.get("ALGV_TLS_KEY")

    if not cert or not key:
        cert_path, key_path = ensure_tls(data_dir)
        cert, key = str(cert_path), str(key_path)

    print(f"\n  AlgoVoi Keystone Control  https://{host}:{port}\n", flush=True)

    uvicorn.run(
        "algovoi_keystone_control.api:app",
        host=host,
        port=port,
        ssl_certfile=cert,
        ssl_keyfile=key,
    )


if __name__ == "__main__":
    main()
