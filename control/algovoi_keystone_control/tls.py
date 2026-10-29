"""Auto-generate a self-signed TLS cert on first run. Reuses on subsequent starts."""
from __future__ import annotations
import datetime
import ipaddress
import socket
from pathlib import Path


def _local_ips() -> list:
    ips = [ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")]
    try:
        local = socket.gethostbyname(socket.gethostname())
        candidate = ipaddress.ip_address(local)
        if candidate not in ips:
            ips.append(candidate)
    except Exception:
        pass
    return ips


def ensure_tls(data_dir: Path) -> tuple[Path, Path]:
    """Return (cert_path, key_path). Generates a self-signed cert if none exists."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    tls_dir = data_dir / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    try:
        tls_dir.chmod(0o700)
    except OSError:
        pass
    cert_path = tls_dir / "cert.pem"
    key_path = tls_dir / "key.pem"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    print("  Generating self-signed TLS certificate...", flush=True)

    key = ec.generate_private_key(ec.SECP256R1())
    hostname = socket.gethostname()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AlgoVoi Keystone Control"),
    ])

    san = x509.SubjectAlternativeName(
        [x509.DNSName("localhost"), x509.DNSName(hostname)]
        + [x509.IPAddress(ip) for ip in _local_ips()]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(san, critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print(f"  TLS cert written to {tls_dir}", flush=True)
    return cert_path, key_path
