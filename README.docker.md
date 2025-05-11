# FIDO2 與 PQC mTLS 演示環境

這個 Docker Compose 設置提供了一個完整的演示環境，用於展示 FIDO2 無密碼認證與後量子密碼學 mTLS 連接的整合。它特別展示了如何通過 Quantum-Safe-Proxy 使不支援 PQC 的後端服務能夠接收 PQC TLS 連接。

## 演示架構

```
+-------------------+      +---------------------+      +-------------------+
|                   |      |                     |      |                   |
|  PasskeyMesh      | PQC  |  Quantum-Safe-      | TLS  |  Backend          |
|  Gateway          +----->+  Proxy              +----->+  Service          |
|  (FIDO2 + PQC)    | mTLS |  (OpenSSL 3.5)      |      |  (JWT 驗證)       |
|                   |      |                     |      |                   |
+-------------------+      +---------------------+      +-------------------+
        ^
        |
        | WebAuthn
        |
+-------v---------+
|                 |
|  Web Browser    |
|  (FIDO2 Client) |
|                 |
+-----------------+
```

在這個架構中：

1. **PasskeyMesh Gateway**：Rust 應用，處理 WebAuthn 認證和 PQC mTLS 連接
2. **Quantum-Safe-Proxy**：使用 OpenSSL 3.5 的代理，將 PQC TLS 連接轉換為標準 TLS
3. **Backend Service**：模擬的後端服務，處理 JWT 驗證

## 快速開始

### 1. 準備證書

```bash
# 啟動 Quantum-Safe-Proxy 容器
docker compose up -d quantum-safe-proxy

# 執行證書生成腳本
docker exec -it fidopqc-rs-quantum-safe-proxy-1 /app/scripts/generate_certs.sh
```

### 2. 啟動所有服務

```bash
# 構建並啟動所有服務
docker compose up -d

# 查看日誌
docker compose logs -f
```

### 3. 訪問演示

- 訪問 http://localhost:3001 進行 WebAuthn 註冊和登錄
- 訪問 http://localhost:3001/api/auth/verify 查看 PQC TLS 握手信息

## 服務說明

### PasskeyMesh Gateway (Rust 應用)

- **端口**：3001
- **功能**：WebAuthn 認證、JWT 生成、PQC mTLS 連接
- **配置**：通過 Docker Compose 中的環境變量配置

### Quantum-Safe-Proxy

- **端口**：8443 (僅內部訪問)
- **功能**：將 PQC TLS 連接轉換為標準 TLS
- **配置**：通過 config.json 文件配置

### Backend Service

- **端口**：6000 (僅內部訪問)
- **功能**：處理 API 請求和 JWT 驗證
- **配置**：通過 OpenResty 配置文件配置

## 演示重點

這個演示環境特別展示了：

1. **PQC 與傳統系統的整合**：如何使不支援 PQC 的後端服務能夠接收 PQC TLS 連接
2. **完整的認證流程**：從 WebAuthn 註冊、登錄到 JWT 驗證的完整流程
3. **PQC TLS 握手信息**：展示 PQC TLS 連接的詳細信息

## 環境變量

Docker Compose 設置中包含以下主要環境變量：

| 環境變量 | 說明 | 默認值 |
|---------|------|-------|
| `JWT_SECRET` | JWT 簽名密鑰 | `your-jwt-secret-key-for-production` |
| `QUANTUM_SAFE_PROXY_URL` | Quantum-Safe-Proxy 的 URL | `https://quantum-safe-proxy:8443` |
| `CLIENT_CERT_PATH` | 客戶端憑證路徑 | `/app/certs/hybrid-client/client.crt` |
| `CLIENT_KEY_PATH` | 客戶端私鑰路徑 | `/app/certs/hybrid-client/client_pkcs8.key` |
| `CA_CERT_PATH` | CA 憑證路徑 | `/app/certs/hybrid-ca/ca.crt` |

## 故障排除

```bash
# 查看所有服務的日誌
docker compose logs -f

# 查看特定服務的日誌
docker compose logs -f passkeymesh-gateway
docker compose logs -f quantum-safe-proxy
docker compose logs -f backend-service
```

## 注意事項

- 這是一個演示環境，不建議在生產環境中直接使用
- 證書是自簽名的，僅用於演示目的
- JWT 密鑰是預設的，在生產環境中應使用強隨機值
