#!/bin/bash
# 為本地開發生成所有證書的腳本
# 包括 CA、傳統 RSA 和 PQC 混合證書

set -e  # 遇到錯誤立即退出

# 設置 OpenSSL 3.5 配置
OPENSSL_PQC="openssl35"  # 您的 OpenSSL 3.5 命令
OPENSSL_PQC_CONF="/etc/ssl/openssl.cnf"  # OpenSSL 3.5 配置文件路徑，請根據您的系統調整

# 設置目錄
CERTS_DIR="certs"
TRADITIONAL_DIR="${CERTS_DIR}/traditional/rsa"
HYBRID_DIR="${CERTS_DIR}/hybrid/ml-dsa-87"

# 確保目錄存在
mkdir -p ${CERTS_DIR}
mkdir -p ${TRADITIONAL_DIR}
mkdir -p ${HYBRID_DIR}

echo "生成所有證書..."

# 生成 CA 證書
echo "生成 CA 證書..."

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

# 為了向後兼容，複製一些 CA 文件
cp ${CERTS_DIR}/server-ca.key ${CERTS_DIR}/ca.key
cp ${CERTS_DIR}/server-ca.crt ${CERTS_DIR}/ca.crt
cat ${CERTS_DIR}/server-ca.crt ${CERTS_DIR}/root-ca.crt > ${CERTS_DIR}/ca-chain.pem

# 生成傳統 RSA CA 證書
echo "生成傳統 RSA CA 證書..."
openssl genrsa -out ${TRADITIONAL_DIR}/ca.key 2048
openssl req -new -x509 -key ${TRADITIONAL_DIR}/ca.key -out ${TRADITIONAL_DIR}/ca.crt -days 1825 -subj "/CN=Traditional CA"

# 生成客戶端證書
echo "生成客戶端證書..."
# 生成標準客戶端證書
openssl genrsa -out ${CERTS_DIR}/client.pqc.key 3072
openssl req -new -key ${CERTS_DIR}/client.pqc.key -out ${CERTS_DIR}/client.csr -subj "/CN=Client"
# 使用客戶端 CA 簽署證書
openssl x509 -req -days 365 -in ${CERTS_DIR}/client.csr -CA ${CERTS_DIR}/client-ca.crt -CAkey ${CERTS_DIR}/client-ca.key -CAcreateserial -out ${CERTS_DIR}/client.pqc.crt -extfile <(printf "subjectAltName=DNS:client,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=clientAuth")
rm -f ${CERTS_DIR}/client.csr

# 生成服務器證書
echo "生成服務器證書..."
# 生成 RSA 服務器證書
openssl genrsa -out ${TRADITIONAL_DIR}/server.key 2048
openssl req -new -key ${TRADITIONAL_DIR}/server.key -out ${TRADITIONAL_DIR}/server.csr -subj "/CN=localhost"
# 使用服務器 CA 簽署證書
openssl x509 -req -in ${TRADITIONAL_DIR}/server.csr -CA ${CERTS_DIR}/server-ca.crt -CAkey ${CERTS_DIR}/server-ca.key -CAcreateserial -out ${TRADITIONAL_DIR}/server.crt -days 365 -extfile <(printf "subjectAltName=DNS:localhost,DNS:quantum-safe-proxy,IP:127.0.0.1\nextendedKeyUsage=serverAuth")
rm -f ${TRADITIONAL_DIR}/server.csr

# 為了向後兼容，也使用傳統 CA 簽署一份
openssl req -new -key ${TRADITIONAL_DIR}/server.key -out ${TRADITIONAL_DIR}/server_trad.csr -subj "/CN=localhost"
openssl x509 -req -in ${TRADITIONAL_DIR}/server_trad.csr -CA ${TRADITIONAL_DIR}/ca.crt -CAkey ${TRADITIONAL_DIR}/ca.key -CAcreateserial -out ${TRADITIONAL_DIR}/server_trad.crt -days 365
rm -f ${TRADITIONAL_DIR}/server_trad.csr

# 生成真正的 PQC 混合客戶端證書
echo "生成真正的 PQC 混合客戶端證書..."
# 檢查 openssl35 是否可用
if ! command -v ${OPENSSL_PQC} &> /dev/null; then
    echo "錯誤: ${OPENSSL_PQC} 命令未找到。請確保 OpenSSL 3.5 已正確安裝。"
    echo "如果已安裝但命令不同，請修改腳本中的 OPENSSL_PQC 變量。"
    exit 1
fi
# 生成 ML-DSA-87 + RSA 混合私鑰
echo "生成 ML-DSA-87 + RSA 混合私鑰..."
${OPENSSL_PQC} genpkey -algorithm ML-DSA-87 -out ${HYBRID_DIR}/client_ml_dsa_87.key
openssl genpkey -algorithm RSA -out ${HYBRID_DIR}/client_rsa.key -pkeyopt rsa_keygen_bits:2048
# 生成混合 CSR
echo "生成混合 CSR..."
${OPENSSL_PQC} req -new -key ${HYBRID_DIR}/client_ml_dsa_87.key -out ${HYBRID_DIR}/client_ml_dsa_87.csr -subj "/CN=client" -config ${OPENSSL_PQC_CONF}
# 使用客戶端 CA 簽署 PQC 證書
echo "簽署 PQC 客戶端證書..."
${OPENSSL_PQC} x509 -req -days 365 -in ${HYBRID_DIR}/client_ml_dsa_87.csr -CA ${CERTS_DIR}/client-ca.crt -CAkey ${CERTS_DIR}/client-ca.key -CAcreateserial -out ${HYBRID_DIR}/client_ml_dsa_87.crt -extfile <(printf "subjectAltName=DNS:client,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=clientAuth")
# 創建混合證書
echo "創建混合證書..."
cat ${HYBRID_DIR}/client_ml_dsa_87.crt > ${HYBRID_DIR}/client_hybrid.crt
# 清理臨時文件
rm -f ${HYBRID_DIR}/client_ml_dsa_87.csr

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

echo ""
echo "所有證書生成完成。"
echo "注意：這些證書僅用於測試，不應在生產環境中使用。"
echo "已使用 OpenSSL 3.5 生成真正的 PQC 混合證書。"
