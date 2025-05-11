# PasskeyMesh Gateway

PasskeyMesh Gateway 是一個結合 WebAuthn 無密碼登入和後量子密碼學 mTLS 的網關應用。它提供了一個安全的方式來驗證用戶身份，並通過量子安全的 TLS 連接與後端服務通信。

## 功能

- **WebAuthn 無密碼登入（FIDO2）**：使用 WebAuthn 標準實現無密碼身份驗證
- **JWT 令牌生成**：成功身份驗證後生成 JWT 令牌
- **後量子密碼學 mTLS 連接**：使用混合 PQC 證書與後端服務建立量子安全的 mTLS 連接
- **安全代理到後端 API**：通過 Quantum-Safe-Proxy 安全地代理請求到後端服務

## 系統架構

```ascii
+-------------------+      +---------------------+      +-------------------+
|                   |      |                     |      |                   |
|  PasskeyMesh      | PQC  |  Quantum-Safe-      | TLS  |  Backend          |
|  Gateway          +----->+  Proxy              +----->+  Service          |
|  (FIDO2)          | mTLS |  (OpenSSL 3.5)      |      |  (JWT 驗證)       |
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

在這個架構中，Quantum-Safe-Proxy 作為後端服務的 sidecar，處理所有的 PQC TLS 連接，而JWT驗證則由後端服務負責。

## 先決條件

- Rust 工具鏈（版本 >= 1.70）
- Docker 和 Docker Compose（用於運行整個系統）
- OpenSSL 3.5 + OQS Provider（已在 Docker 映像中配置）
- 支持 WebAuthn 的瀏覽器（Chrome / Firefox / Safari）

## 目錄結構

```text
fidopqc-rs/
├── Cargo.toml                # Rust 項目配置
├── Cargo.lock                # 依賴鎖定文件
├── docker-compose.yml        # Docker Compose 配置
├── Dockerfile.gateway        # PasskeyMesh Gateway 的 Dockerfile
├── Dockerfile.openresty      # Backend Service 的 Dockerfile
├── config.json               # Quantum-Safe-Proxy 配置
├── src/
│   ├── main.rs               # 程序入口
│   ├── webauthn.rs           # WebAuthn 註冊和登錄邏輯
│   ├── call_proxy.rs         # 代理請求邏輯（PQC mTLS）
│   ├── jwt.rs                # JWT 處理
│   └── error.rs              # 錯誤處理
├── scripts/                  # 腳本目錄
│   ├── generate_certs.sh     # 生成 PQC 證書的腳本
│   ├── clean_certs.sh        # 清理證書的腳本
│   └── docker-entrypoint.sh  # Docker 容器入口腳本
├── docker/                   # Docker 相關文件
│   └── nginx/                # Nginx 配置
│       ├── html/             # 靜態文件
│       └── openresty.conf    # OpenResty 配置
├── index.html                # 前端演示頁面
├── .env                      # 環境變量配置
├── .env.example              # 環境變量示例
└── certs/             # 證書目錄 (由腳本生成)
    ├── hybrid-ca/            # CA 證書目錄
    │   └── ca.crt            # CA 證書 (用於 mTLS 驗證服務器)
    ├── hybrid-server/        # 服務器證書目錄
    │   ├── server.crt        # 服務器證書
    │   └── server.key        # 服務器私鑰
    └── hybrid-client/        # 客戶端證書目錄
        ├── client.crt        # 客戶端證書 (用於 mTLS 客戶端身份)
        └── client.key  # 客戶端私鑰 (用於 mTLS 客戶端簽名)
```

## 安裝和運行

### 方法 1：使用 Docker Compose（推薦）

1. 確保您已安裝 Docker 和 Docker Compose
2. 克隆此存儲庫
3. 在項目根目錄運行：

```bash
# 構建並啟動所有服務
docker compose up -d

# 查看日誌
docker compose logs -f
```

這將啟動三個容器：

- **passkeymesh-gateway**：WebAuthn 服務和 PQC mTLS 客戶端（http://localhost:3001）
- **quantum-safe-proxy**：支持後量子密碼學的 TLS 代理（https://localhost:8443）
- **backend-service**：模擬的後端 API 服務（http://localhost:6000，僅內部訪問）

### 方法 2：本地開發環境

步驟如下：

1. 確保您已安裝 Rust 和 Cargo
2. 克隆此存儲庫
3. 安裝依賴並構建項目：

   ```bash
   # 安裝 OpenSSL 開發庫
   sudo apt-get install pkg-config libssl-dev

   # 構建項目
   cargo build
   ```

4. 運行應用程序：

   ```bash
   cargo run
   ```

注意：本地運行時，您需要單獨設置 Quantum-Safe-Proxy 和後端服務。

## 使用方法

### WebAuthn 身份驗證流程

#### 1. 註冊新用戶

```bash
curl -X POST http://localhost:3001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}'
```

#### 2. 完成註冊（在瀏覽器中）

訪問 `http://localhost:3001` 並使用返回的挑戰完成註冊過程。系統將提示您使用生物識別（如指紋）或安全密鑰來創建 FIDO2 憑證。

#### 3. 登錄

```bash
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}'
```

#### 4. 完成登錄（在瀏覽器中）

訪問 `http://localhost:3001` 並使用返回的挑戰完成登錄過程。系統將提示您使用之前註冊的生物識別或安全密鑰進行身份驗證。

#### 5. 訪問 API

系統提供統一的 API 端點 `/api/auth/verify`，支援 GET 和 POST 請求，並使用 HTTP 標頭傳遞 JWT 令牌：

##### 方式一：未登錄訪問（訪客模式）

未登錄用戶可以直接訪問 API，但會被標記為未認證用戶：

```bash
# 使用 API 端點
curl "http://localhost:3001/api/auth/verify"
```

響應示例：

```json
{
  "result": "{\"status\":\"success\",\"message\":\"Backend API is working!\"}",
  "proxy_status": "200 OK",
  "authenticated": false,
  "user_info": null,
  "tls_info": "TLS Connection: Successful\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\nServer Temp Key: X25519, 253 bits\nPost-Quantum Cryptography: Enabled\nClient Certificate: certs/hybrid-client/client.crt\nCA Certificate: certs/hybrid-ca/ca.crt\nOpenSSL Version: OpenSSL 3.5.0 (with post-quantum support)"
}
```

##### 方式二：使用 JWT 令牌訪問（已認證模式）

成功登錄後，系統將返回 JWT 令牌，可用於訪問 API 並獲取用戶信息：

```bash
# GET 請求
curl "http://localhost:3001/api/auth/verify" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

或者使用 POST 請求：

```bash
# POST 請求
curl -X POST "http://localhost:3001/api/auth/verify" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

響應示例：

```json
{
  "result": "{\"status\":\"success\",\"message\":\"Backend API is working!\",\"authenticated\":true,\"user_info\":\"testuser (1234-5678-9012)\"}",
  "proxy_status": "200 OK",
  "authenticated": true,
  "user_info": "\"testuser (1234-5678-9012)\"",
  "tls_info": "TLS Connection: Successful\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\nServer Temp Key: X25519, 253 bits\nPost-Quantum Cryptography: Enabled\nClient Certificate: certs/hybrid-client/client.crt\nCA Certificate: certs/hybrid-ca/ca.crt\nOpenSSL Version: OpenSSL 3.5.0 (with post-quantum support)"
}
```

響應中的 `tls_info` 字段包含了 PQC TLS 連接的詳細信息，包括使用的密碼套件、密鑰交換算法和 OpenSSL 版本等。

### PQC TLS 握手信息

系統會在每次 API 請求時返回 PQC TLS 握手的詳細信息，包括：

1. **TLS 連接狀態**：顯示連接是否成功建立
2. **TLS 協議版本**：使用的 TLS 版本（TLSv1.3）
3. **密碼套件**：使用的加密算法（如 TLS_AES_256_GCM_SHA384）
4. **密鑰交換算法**：使用的混合密鑰交換算法（X25519MLKEM768）
5. **PQC 狀態**：確認後量子密碼學是否啟用
6. **憑證信息**：使用的客戶端和 CA 憑證路徑
7. **OpenSSL 版本**：使用的 OpenSSL 版本和 PQC 支持狀態

這些信息可以幫助您確認系統是否正確使用了 PQC 算法進行 TLS 握手。

```json
"tls_info": "TLS Connection: Successful\nProtocol  : TLSv1.3\nCipher    : TLS_AES_256_GCM_SHA384\nServer Temp Key: X25519, 253 bits\nPost-Quantum Cryptography: Enabled\nClient Certificate: certs/hybrid-client/client.crt\nCA Certificate: certs/hybrid-ca/ca.crt\nOpenSSL Version: OpenSSL 3.5.0 (with post-quantum support)"
```

您可以通過訪問 `/api/auth/verify` 端點來測試 PQC TLS 連接，無論是否提供 JWT 令牌，系統都會返回 TLS 握手信息。

## 證書管理

### 證書目錄結構

本項目使用以下目錄結構來組織 PQC 憑證：

```text
certs/
├── hybrid-ca/            # CA 證書目錄
│   └── ca.crt            # CA 證書 (用於 mTLS 驗證服務器)
├── hybrid-server/        # 服務器證書目錄
│   ├── server.crt        # 服務器證書
│   └── server.key        # 服務器私鑰
└── hybrid-client/        # 客戶端證書目錄
    ├── client.crt        # 客戶端證書 (用於 mTLS 客戶端身份)
    └── client_pkcs8.key  # 客戶端私鑰 (用於 mTLS 客戶端簽名)
```

### 證書生成腳本

本項目包含用於生成證書的腳本，位於 `scripts/` 目錄下：

- `generate_certs.sh`：使用 OpenSSL 3.5 生成所有 PQC 混合證書
- `clean_certs.sh`：清理所有證書

#### 使用 Docker 生成證書（推薦）

最簡單的方法是使用 Docker 容器中的 OpenSSL 3.5 生成證書：

```bash
# 啟動容器
docker compose up -d quantum-safe-proxy

# 執行證書生成腳本
docker exec -it fidopqc-rs-quantum-safe-proxy-1 /app/scripts/generate_certs.sh
```

#### 在本地生成證書

如果您已安裝 OpenSSL 3.5，可以直接在本地生成證書：

```bash
# 確保腳本有執行權限
chmod +x scripts/generate_certs.sh

# 執行腳本
./scripts/generate_certs.sh
```

### 混合 PQC 證書說明

系統使用 OpenSSL 3.5 原生支援的 PQC 算法生成混合證書，用於 mTLS 連接：

1. **CA 證書**：使用 ML-DSA-87 算法生成，用於簽署服務器和客戶端證書
2. **服務器證書**：使用 ML-DSA-87 算法生成，並由 CA 簽署
3. **客戶端證書**：使用 ML-DSA-87 算法生成，並由 CA 簽署

在 TLS 握手過程中，系統使用 X25519MLKEM768 混合密鑰交換算法，這是一種結合了傳統橢圓曲線密碼學 (X25519) 和後量子密碼學 (MLKEM768) 的混合算法。

## 環境變量配置

系統支持以下環境變量：

| 環境變量 | 說明 | 默認值 |
|---------|------|-------|
| `JWT_SECRET` | JWT 簽名密鑰 | `your-jwt-secret-key-for-production` |
| `JWT_ISSUER` | JWT 發行者 | `passkeymesh-gateway` |
| `JWT_AUDIENCE` | JWT 受眾 | `backend-service` |
| `ENVIRONMENT` | 運行環境 | `development` |
| `RUST_LOG` | 日誌級別 | `info,tower_http=debug,passkeymesh_gateway=trace` |
| `QUANTUM_SAFE_PROXY_URL` | 量子安全代理的 URL | `https://localhost:8443` |
| `PORT` | 服務器監聽端口 | `3001` |
| `CLIENT_CERT_PATH` | 客戶端憑證路徑 (mTLS) | `certs/hybrid-client/client.crt` |
| `CLIENT_KEY_PATH` | 客戶端私鑰路徑 (mTLS) | `certs/hybrid-client/client_pkcs8.key` |
| `CA_CERT_PATH` | CA 憑證路徑 (mTLS) | `certs/hybrid-ca/ca.crt` |
| `OPENSSL_PATH` | OpenSSL 3.5 可執行文件路徑 | 自動檢測 |

您可以通過以下方式設置環境變量：

1. 在 `.env` 文件中設置（推薦用於開發環境）：

```bash
# .env 文件示例
JWT_SECRET=your-secure-jwt-secret
ENVIRONMENT=production
```

2. 在 `docker-compose.yml` 文件中設置（已預配置）

3. 在命令行中設置（適用於臨時測試）：

```bash
JWT_SECRET=your-secure-jwt-secret docker compose up
```

## 安全注意事項

- 此演示應用使用內存存儲，在生產環境中應使用數據庫
- JWT 密鑰應使用強隨機值，並通過環境變量或安全存儲提供
- 在生產環境中，應設置 `ENVIRONMENT=production` 以啟用額外的安全標頭
- 所有 API 端點都應使用 HTTPS
- PQC 算法仍在標準化過程中，應定期更新以使用最新的安全算法

## 許可證

MIT
