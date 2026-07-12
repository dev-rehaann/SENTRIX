#!/usr/bin/env bash
# Sentrix — project CA + per-node cert generator.
# NOT production-hardened as-is: no revocation, no HSM, no passphrase on keys.
# Good enough for v0.1 bring-up; revisit before any real deployment.
set -euo pipefail

CERT_DIR="$(dirname "$0")"
cd "$CERT_DIR"

if [ ! -f ca.key ]; then
  echo "[*] Generating project root CA..."
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -key ca.key -days 3650 -out ca.crt \
    -subj "/CN=Sentrix Root CA"
else
  echo "[*] Root CA already exists, skipping."
fi

NODE_ID="${1:-}"
if [ -z "$NODE_ID" ]; then
  echo "Usage: $0 <node-id>   (e.g. $0 node-07)"
  exit 0
fi

echo "[*] Issuing cert for ${NODE_ID}..."
openssl genrsa -out "${NODE_ID}.key" 2048
openssl req -new -key "${NODE_ID}.key" -out "${NODE_ID}.csr" \
  -subj "/CN=${NODE_ID}"
openssl x509 -req -in "${NODE_ID}.csr" -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out "${NODE_ID}.crt" -days 365

echo "[*] Done. Files: ${NODE_ID}.key ${NODE_ID}.crt (keep .key off the node's filesystem in plaintext where possible)."
