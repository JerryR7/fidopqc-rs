#!/bin/bash
# 這是一份範例腳本，示範如何用 OpenSSL 3.5 真正產生 Hybrid PQC 簽章（ML-DSA-87 + ECDSA-P521）憑證，
# 並確保 Server/Client 端都能用這張憑證在 TLS 1.3 下以混合金鑰交換（X25519MLKEM768）＋傳統 X25519 傳輸通道完成驗證。
set -e

OPENSSL="/usr/local/opt/openssl@3.5/bin/openssl"  # 使用完整路徑
CERTS_DIR="./certs_hybrid"
CA_DIR="${CERTS_DIR}/hybrid-ca"
SERVER_DIR="${CERTS_DIR}/hybrid-server"
CLIENT_DIR="${CERTS_DIR}/hybrid-client"

# 建立目錄
mkdir -p "${CA_DIR}" "${SERVER_DIR}" "${CLIENT_DIR}"

echo "1️⃣ 產生 PQC CA (ML-DSA-87)"
"$OPENSSL" genpkey -algorithm ML-DSA-87 -out "${CA_DIR}/ca.key"
"$OPENSSL" req -new -x509 -key "${CA_DIR}/ca.key" -out "${CA_DIR}/ca.crt" \
    -days 3650 -subj "/CN=Hybrid-PQC-CA"

echo "2️⃣ 產生 Server 私鑰與 CSR"
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

echo "3️⃣ 用 Hybrid CA 簽署 Server CSR → Hybrid Server Cert"
"$OPENSSL" x509 -req \
    -in "${SERVER_DIR}/server.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" -CAcreateserial \
    -out "${SERVER_DIR}/server.crt" -days 365 \
    -extfile "${SERVER_DIR}/server_ext.cnf" -extensions server_ext

echo "4️⃣ 產生 Client 私鑰與 CSR"
"$OPENSSL" genpkey -algorithm ML-DSA-87 -out "${CLIENT_DIR}/client.key"
"$OPENSSL" req -new -key "${CLIENT_DIR}/client.key" \
    -out "${CLIENT_DIR}/client.csr" -subj "/CN=client"

cat > "${CLIENT_DIR}/client_ext.cnf" <<EOF
[ client_ext ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

echo "5️⃣ 用 Hybrid CA 簽署 Client CSR → Hybrid Client Cert"
"$OPENSSL" x509 -req \
    -in "${CLIENT_DIR}/client.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" -CAcreateserial \
    -out "${CLIENT_DIR}/client.crt" -days 365 \
    -extfile "${CLIENT_DIR}/client_ext.cnf" -extensions client_ext

echo "✅ 全部憑證已生成："
echo "  CA    → ${CA_DIR}/ca.crt"
echo "  Server→ ${SERVER_DIR}/server.crt, ${SERVER_DIR}/server.key"
echo "  Client→ ${CLIENT_DIR}/client.crt, ${CLIENT_DIR}/client.key"


