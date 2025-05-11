#!/bin/bash
# This is an example script demonstrating how to use OpenSSL 3.5 to generate Hybrid PQC signatures (ML-DSA-87 + ECDSA-P521) certificates,
# and ensure that both Server/Client can use these certificates to complete authentication under TLS 1.3 with hybrid key exchange (X25519MLKEM768) + traditional X25519 transport channel.
set -e

OPENSSL="/usr/local/opt/openssl@3.5/bin/openssl"  # Use full path
CERTS_DIR="./certs"
CA_DIR="${CERTS_DIR}/hybrid-ca"
SERVER_DIR="${CERTS_DIR}/hybrid-server"
CLIENT_DIR="${CERTS_DIR}/hybrid-client"

# Create directories
mkdir -p "${CA_DIR}" "${SERVER_DIR}" "${CLIENT_DIR}"

echo "1️⃣ Generate PQC CA (ML-DSA-87)"
"$OPENSSL" genpkey -algorithm ML-DSA-87 -out "${CA_DIR}/ca.key"
"$OPENSSL" req -new -x509 -key "${CA_DIR}/ca.key" -out "${CA_DIR}/ca.crt" \
    -days 3650 -subj "/CN=Hybrid-PQC-CA"

echo "2️⃣ Generate Server private key and CSR"
"$OPENSSL" genpkey -algorithm ML-DSA-87 -out "${SERVER_DIR}/server.key"
"$OPENSSL" req -new -key "${SERVER_DIR}/server.key" \
    -out "${SERVER_DIR}/server.csr" -subj "/CN=localhost"

cat > "${SERVER_DIR}/server_ext.cnf" <<EOF
[ server_ext ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

echo "3️⃣ Sign Server CSR with Hybrid CA → Hybrid Server Cert"
"$OPENSSL" x509 -req \
    -in "${SERVER_DIR}/server.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" -CAcreateserial \
    -out "${SERVER_DIR}/server.crt" -days 365 \
    -extfile "${SERVER_DIR}/server_ext.cnf" -extensions server_ext

echo "4️⃣ Generate Client private key and CSR"
"$OPENSSL" genpkey -algorithm ML-DSA-87 -out "${CLIENT_DIR}/client.key"
"$OPENSSL" req -new -key "${CLIENT_DIR}/client.key" \
    -out "${CLIENT_DIR}/client.csr" -subj "/CN=client"

cat > "${CLIENT_DIR}/client_ext.cnf" <<EOF
[ client_ext ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

echo "5️⃣ Sign Client CSR with Hybrid CA → Hybrid Client Cert"
"$OPENSSL" x509 -req \
    -in "${CLIENT_DIR}/client.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" -CAcreateserial \
    -out "${CLIENT_DIR}/client.crt" -days 365 \
    -extfile "${CLIENT_DIR}/client_ext.cnf" -extensions client_ext

echo "✅ All certificates have been generated:"
echo "  CA    → ${CA_DIR}/ca.crt"
echo "  Server→ ${SERVER_DIR}/server.crt, ${SERVER_DIR}/server.key"
echo "  Client→ ${CLIENT_DIR}/client.crt, ${CLIENT_DIR}/client.key"


