#!/bin/bash
set -e

DIR="certs"
mkdir -p $DIR

echo "🔒 Generating CA (Certificate Authority)..."
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -keyout $DIR/ca-key.pem -out $DIR/ca-cert.pem \
    -subj "/C=US/ST=State/L=City/O=TalosVault/OU=Root/CN=TalosRootCA"

echo "🔒 Generating Server Certs (Control Plane)..."
openssl genrsa -out $DIR/server-key.pem 4096

openssl req -new -key $DIR/server-key.pem -out $DIR/server.csr \
    -subj "/C=US/ST=State/L=City/O=TalosVault/OU=Server/CN=controller"

# CRITICAL: Adding 'DNS:controller' for Docker networking
cat <<EOT > $DIR/server-ext.cnf
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = controller
IP.1 = 127.0.0.1
EOT

openssl x509 -req -in $DIR/server.csr -CA $DIR/ca-cert.pem -CAkey $DIR/ca-key.pem \
    -CAcreateserial -out $DIR/server-cert.pem -days 365 -sha256 -extfile $DIR/server-ext.cnf

echo "🔒 Generating Client Certs (Sidecar)..."
openssl genrsa -out $DIR/client-key.pem 4096
openssl req -new -key $DIR/client-key.pem -out $DIR/client.csr \
    -subj "/C=US/ST=State/L=City/O=TalosVault/OU=Client/CN=sidecar-1"

openssl x509 -req -in $DIR/client.csr -CA $DIR/ca-cert.pem -CAkey $DIR/ca-key.pem \
    -CAcreateserial -out $DIR/client-cert.pem -days 365 -sha256

chmod 600 $DIR/*-key.pem
echo "✅ All certificates generated (Docker Ready) in '$DIR/'"
