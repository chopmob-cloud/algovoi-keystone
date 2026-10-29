#!/bin/bash
# Generate a self-signed TLS certificate for the keystone control panel.
# Run once per deployment. Outputs key.pem + cert.pem in ./ssl/
#
# Usage:
#   bash scripts/generate_ssl.sh [hostname-or-ip]
#
# Examples:
#   bash scripts/generate_ssl.sh                  # defaults to localhost
#   bash scripts/generate_ssl.sh keystone.local
#   bash scripts/generate_ssl.sh 192.168.1.50

set -e

HOST="${1:-localhost}"
SSL_DIR="$(dirname "$0")/../ssl"
mkdir -p "$SSL_DIR"

# Detect whether HOST looks like an IP address.
if [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN="DNS:localhost,IP:127.0.0.1,IP:${HOST}"
else
    SAN="DNS:localhost,DNS:${HOST},IP:127.0.0.1"
fi

openssl req -x509 -newkey rsa:4096 \
    -keyout "$SSL_DIR/key.pem" \
    -out    "$SSL_DIR/cert.pem" \
    -days 3650 -nodes \
    -subj "/CN=${HOST}" \
    -addext "subjectAltName=${SAN}"

chmod 600 "$SSL_DIR/key.pem"

echo ""
echo "Certificate generated:"
echo "  $SSL_DIR/cert.pem"
echo "  $SSL_DIR/key.pem"
echo ""
echo "Start with:"
echo "  uvicorn algovoi_keystone_control.api:app \\"
echo "    --host 0.0.0.0 --port 8077 \\"
echo "    --ssl-keyfile ssl/key.pem \\"
echo "    --ssl-certfile ssl/cert.pem"
echo ""
echo "Browser: accept the self-signed certificate warning on first visit."
echo "To trust it permanently, import ssl/cert.pem into your OS trust store."
