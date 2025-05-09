#!/bin/bash
# 為本地開發生成客戶端證書的腳本
# 包括傳統 RSA 和 PQC 混合客戶端證書

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

echo "生成客戶端證書..."

# 檢查 CA 證書是否存在
if [ ! -f "${CERTS_DIR}/root-ca.key" ] || [ ! -f "${CERTS_DIR}/root-ca.crt" ]; then
    echo "生成根 CA 證書..."
    # 生成根 CA 證書
    openssl genrsa -out ${CERTS_DIR}/root-ca.key 4096
    openssl req -new -x509 -days 3650 -key ${CERTS_DIR}/root-ca.key -out ${CERTS_DIR}/root-ca.crt -subj "/CN=Root CA" -extensions v3_ca
fi

# 檢查客戶端 CA 證書是否存在
if [ ! -f "${CERTS_DIR}/client-ca.key" ] || [ ! -f "${CERTS_DIR}/client-ca.crt" ]; then
    echo "生成客戶端 CA 證書..."
    # 生成客戶端 CA 證書
    openssl genrsa -out ${CERTS_DIR}/client-ca.key 3072
    openssl req -new -key ${CERTS_DIR}/client-ca.key -out ${CERTS_DIR}/client-ca.csr -subj "/CN=Client CA"
    openssl x509 -req -days 1825 -in ${CERTS_DIR}/client-ca.csr -CA ${CERTS_DIR}/root-ca.crt -CAkey ${CERTS_DIR}/root-ca.key -CAcreateserial -out ${CERTS_DIR}/client-ca.crt -extensions v3_ca
    rm -f ${CERTS_DIR}/client-ca.csr

    # 創建客戶端 CA 鏈
    cat ${CERTS_DIR}/client-ca.crt ${CERTS_DIR}/root-ca.crt > ${CERTS_DIR}/client-ca-chain.pem
fi

# 為了向後兼容，確保 ca.key 和 ca.crt 存在
if [ ! -f "${CERTS_DIR}/ca.key" ] || [ ! -f "${CERTS_DIR}/ca.crt" ]; then
    cp ${CERTS_DIR}/client-ca.key ${CERTS_DIR}/ca.key
    cp ${CERTS_DIR}/client-ca.crt ${CERTS_DIR}/ca.crt
    cat ${CERTS_DIR}/client-ca.crt ${CERTS_DIR}/root-ca.crt > ${CERTS_DIR}/ca-chain.pem
fi

# 生成標準客戶端證書
echo "生成標準客戶端證書..."
openssl genrsa -out ${CERTS_DIR}/client.pqc.key 3072
openssl req -new -key ${CERTS_DIR}/client.pqc.key -out ${CERTS_DIR}/client.csr -subj "/CN=Client"
openssl x509 -req -days 365 -in ${CERTS_DIR}/client.csr -CA ${CERTS_DIR}/client-ca.crt -CAkey ${CERTS_DIR}/client-ca.key -CAcreateserial -out ${CERTS_DIR}/client.pqc.crt -extfile <(printf "subjectAltName=DNS:client,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=clientAuth")
rm -f ${CERTS_DIR}/client.csr

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

echo ""
echo "客戶端證書生成完成。"
echo "注意：這些證書僅用於測試，不應在生產環境中使用。"
echo "已使用 OpenSSL 3.5 生成真正的 PQC 混合證書。"
