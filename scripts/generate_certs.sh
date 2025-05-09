#!/bin/bash
# 在 Docker 容器中生成證書的腳本
# 使用 OpenSSL 3.5 生成真正的 PQC 混合證書

set -e  # 遇到錯誤立即退出

# 設置 OpenSSL 3.5 配置
OPENSSL_PQC="openssl"  # 在容器中使用標準 openssl 命令
OPENSSL_PQC_CONF="/etc/ssl/openssl.cnf"  # OpenSSL 配置文件路徑

# 設置目錄
CERTS_DIR="/app/certs"
TRADITIONAL_DIR="${CERTS_DIR}/traditional/rsa"
HYBRID_DIR="${CERTS_DIR}/hybrid/ml-dsa-87"

# 確保目錄存在
mkdir -p ${TRADITIONAL_DIR}
mkdir -p ${HYBRID_DIR}

echo "生成證書..."

# 生成根 CA 證書
echo "生成根 CA 證書..."
openssl genrsa -out ${CERTS_DIR}/root-ca.key 4096
openssl req -new -x509 -days 3650 -key ${CERTS_DIR}/root-ca.key -out ${CERTS_DIR}/root-ca.crt -subj "/CN=Root CA" -extensions v3_ca

# 生成服務器 CA 證書
echo "生成服務器 CA 證書..."
openssl genrsa -out ${CERTS_DIR}/server-ca.key 3072
openssl req -new -key ${CERTS_DIR}/server-ca.key -out ${CERTS_DIR}/server-ca.csr -subj "/CN=Server CA"
openssl x509 -req -days 1825 -in ${CERTS_DIR}/server-ca.csr -CA ${CERTS_DIR}/root-ca.crt -CAkey ${CERTS_DIR}/root-ca.key -CAcreateserial -out ${CERTS_DIR}/server-ca.crt -extensions v3_ca
rm -f ${CERTS_DIR}/server-ca.csr

# 生成客戶端 CA 證書
echo "生成客戶端 CA 證書..."
openssl genrsa -out ${CERTS_DIR}/client-ca.key 3072
openssl req -new -key ${CERTS_DIR}/client-ca.key -out ${CERTS_DIR}/client-ca.csr -subj "/CN=Client CA"
openssl x509 -req -days 1825 -in ${CERTS_DIR}/client-ca.csr -CA ${CERTS_DIR}/root-ca.crt -CAkey ${CERTS_DIR}/root-ca.key -CAcreateserial -out ${CERTS_DIR}/client-ca.crt -extensions v3_ca
rm -f ${CERTS_DIR}/client-ca.csr

# 創建 CA 鏈（包含根 CA 和中間 CA）
cat ${CERTS_DIR}/server-ca.crt ${CERTS_DIR}/root-ca.crt > ${CERTS_DIR}/server-ca-chain.pem
cat ${CERTS_DIR}/client-ca.crt ${CERTS_DIR}/root-ca.crt > ${CERTS_DIR}/client-ca-chain.pem

# 生成傳統 RSA CA 證書
echo "生成傳統 RSA CA 證書..."
openssl genrsa -out ${TRADITIONAL_DIR}/ca.key 2048
openssl req -new -x509 -key ${TRADITIONAL_DIR}/ca.key -out ${TRADITIONAL_DIR}/ca.crt -days 1825 -subj "/CN=Traditional CA"

# 生成 RSA 服務器證書
echo "生成 RSA 服務器證書..."
openssl genrsa -out ${TRADITIONAL_DIR}/server.key 2048
openssl req -new -key ${TRADITIONAL_DIR}/server.key -out ${TRADITIONAL_DIR}/server.csr -subj "/CN=localhost"
openssl x509 -req -in ${TRADITIONAL_DIR}/server.csr -CA ${CERTS_DIR}/server-ca.crt -CAkey ${CERTS_DIR}/server-ca.key -CAcreateserial -out ${TRADITIONAL_DIR}/server.crt -days 365 -extfile <(printf "subjectAltName=DNS:localhost,DNS:quantum-safe-proxy,IP:127.0.0.1\nextendedKeyUsage=serverAuth")
rm -f ${TRADITIONAL_DIR}/server.csr

# 生成真正的 PQC 混合服務器證書
echo "生成真正的 PQC 混合服務器證書..."

# 生成 ML-DSA-87 + RSA 混合私鑰
echo "生成 ML-DSA-87 + RSA 混合私鑰..."
${OPENSSL_PQC} genpkey -algorithm ML-DSA-87 -out ${HYBRID_DIR}/server_ml_dsa_87.key
openssl genpkey -algorithm RSA -out ${HYBRID_DIR}/server_rsa.key -pkeyopt rsa_keygen_bits:2048

# 生成混合 CSR
echo "生成混合 CSR..."
${OPENSSL_PQC} req -new -key ${HYBRID_DIR}/server_ml_dsa_87.key -out ${HYBRID_DIR}/server_ml_dsa_87.csr -subj "/CN=localhost" -config ${OPENSSL_PQC_CONF}

# 使用服務器 CA 簽署 PQC 證書
echo "簽署 PQC 服務器證書..."
${OPENSSL_PQC} x509 -req -days 365 -in ${HYBRID_DIR}/server_ml_dsa_87.csr -CA ${CERTS_DIR}/server-ca.crt -CAkey ${CERTS_DIR}/server-ca.key -CAcreateserial -out ${HYBRID_DIR}/server_ml_dsa_87.crt -extfile <(printf "subjectAltName=DNS:localhost,DNS:quantum-safe-proxy,IP:127.0.0.1\nextendedKeyUsage=serverAuth")

# 創建混合證書
echo "創建混合證書..."
cat ${HYBRID_DIR}/server_ml_dsa_87.crt > ${HYBRID_DIR}/server_hybrid.crt

# 為方便使用，複製主私鑰作為服務器私鑰
cp ${HYBRID_DIR}/server_ml_dsa_87.key ${HYBRID_DIR}/server.key

# 清理臨時文件
rm -f ${HYBRID_DIR}/server_ml_dsa_87.csr

echo "證書生成完成。"
echo "已使用 OpenSSL 3.5 生成真正的 PQC 混合證書。"
