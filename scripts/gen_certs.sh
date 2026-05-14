#!/usr/bin/env bash
# gen_certs.sh — Generate self-signed CA, sender cert, and receiver cert for mTLS
# Usage: bash scripts/gen_certs.sh
# Outputs: certs/{ca,sender,receiver}.{key,crt,pem}

set -euo pipefail

CERT_DIR="$(dirname "$0")/../certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

DAYS=3650
KEYLEN=4096

echo "[*] Generating CA key and self-signed certificate..."
openssl genrsa -out ca.key "$KEYLEN" 2>/dev/null
openssl req -new -x509 -days "$DAYS" -key ca.key -out ca.crt \
  -subj "/CN=SecureTransfer-CA/O=Assessment/C=US" 2>/dev/null

echo "[*] Generating sender key and CSR..."
openssl genrsa -out sender.key "$KEYLEN" 2>/dev/null
openssl req -new -key sender.key -out sender.csr \
  -subj "/CN=sender/O=Assessment/C=US" 2>/dev/null
openssl x509 -req -days "$DAYS" -in sender.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out sender.crt 2>/dev/null

echo "[*] Generating receiver key and CSR..."
openssl genrsa -out receiver.key "$KEYLEN" 2>/dev/null
openssl req -new -key receiver.key -out receiver.csr \
  -subj "/CN=receiver/O=Assessment/C=US" 2>/dev/null
openssl x509 -req -days "$DAYS" -in receiver.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out receiver.crt 2>/dev/null

# Clean up CSRs
rm -f sender.csr receiver.csr ca.srl

echo "[*] Certificate generation complete."
echo "    certs/ca.{key,crt}"
echo "    certs/sender.{key,crt}"
echo "    certs/receiver.{key,crt}"
