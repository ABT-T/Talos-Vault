#!/bin/bash
set -e
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

DIR="certs"
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
CERT_DIR="$REPO_ROOT/$DIR"

echo -e "${BLUE}Talos-Vault — Secure Certificate Generation${NC}"

mkdir -p "$CERT_DIR"
touch "$CERT_DIR/.gitkeep"

cat > "$CERT_DIR/.gitignore" << 'INNER'
*-key.pem
*.key
*.csr
*.srl
INNER

echo -e "${BLUE}[1/3] تولید CA...${NC}"
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -keyout "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/ca-cert.pem" \
    -subj "/C=US/ST=State/L=City/O=TalosVault/OU=Root/CN=TalosRootCA" 2>/dev/null
chmod 600 "$CERT_DIR/ca-key.pem"
chmod 644 "$CERT_DIR/ca-cert.pem"

echo -e "${BLUE}[2/3] تولید Server Cert...${NC}"
openssl genrsa -out "$CERT_DIR/server-key.pem" 4096 2>/dev/null
openssl req -new -key "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=State/L=City/O=TalosVault/OU=Server/CN=controller" 2>/dev/null

cat > "$CERT_DIR/server-ext.cnf" << 'EXT'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = controller
IP.1 = 127.0.0.1
EXT

openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial \
    -out "$CERT_DIR/server-cert.pem" -days 365 -sha256 \
    -extfile "$CERT_DIR/server-ext.cnf" 2>/dev/null
chmod 600 "$CERT_DIR/server-key.pem"
rm -f "$CERT_DIR/server.csr"

echo -e "${BLUE}[3/3] تولید Client Cert...${NC}"
openssl genrsa -out "$CERT_DIR/client-key.pem" 4096 2>/dev/null
openssl req -new -key "$CERT_DIR/client-key.pem" -out "$CERT_DIR/client.csr" \
    -subj "/C=US/ST=State/L=City/O=TalosVault/OU=Client/CN=sidecar-1" 2>/dev/null
openssl x509 -req -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca-cert.pem" -CAkey "$CERT_DIR/ca-key.pem" -CAcreateserial \
    -out "$CERT_DIR/client-cert.pem" -days 365 -sha256 2>/dev/null
chmod 600 "$CERT_DIR/client-key.pem"
rm -f "$CERT_DIR/client.csr" "$CERT_DIR/ca-cert.srl"

echo -e "${GREEN}✅ Certificate های جدید تولید شدند${NC}"
echo "Public certs: ca-cert.pem, server-cert.pem, client-cert.pem"
echo "Private keys: gitignore شده‌اند"
