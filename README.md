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
passkeymesh-gateway/
├── Cargo.toml                # Rust 項目配置
├── Cargo.lock                # 依賴鎖定文件
├── docker-compose.yml        # Docker Compose 配置
├── Dockerfile.gateway        # PasskeyMesh Gateway 的 Dockerfile
├── src/
│   ├── main.rs               # 程序入口
│   ├── webauthn.rs           # WebAuthn 註冊和登錄邏輯
│   ├── call_proxy.rs         # 代理請求邏輯（PQC mTLS）
│   ├── jwt.rs                # JWT 處理
│   └── error.rs              # 錯誤處理
├── index.html                # 前端演示頁面
└── certs_hybrid/             # 證書目錄
    ├── hybrid-ca/            # CA 證書目錄
    │   └── ca.crt            # CA 證書 (用於 mTLS 驗證服務器)
    ├── hybrid-server/        # 服務器證書目錄
    │   ├── server.crt        # 服務器證書
    │   └── server.key        # 服務器私鑰
    └── hybrid-client/        # 客戶端證書目錄
        ├── client.crt        # 客戶端證書 (用於 mTLS 客戶端身份)
        └── client.key        # 客戶端私鑰 (用於 mTLS 客戶端簽名)
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

- **passkeymesh-gateway**：WebAuthn 服務和 PQC mTLS 客戶端
- **quantum-safe-proxy**：支持後量子密碼學的 TLS 代理
- **backend-service**：模擬的後端 API 服務

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
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}'
```

#### 2. 完成註冊（在瀏覽器中）

訪問 `http://localhost:3000` 並使用返回的挑戰完成註冊過程。系統將提示您使用生物識別（如指紋）或安全密鑰來創建 FIDO2 憑證。

#### 3. 登錄

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}'
```

#### 4. 完成登錄（在瀏覽器中）

訪問 `http://localhost:3000` 並使用返回的挑戰完成登錄過程。系統將提示您使用之前註冊的生物識別或安全密鑰進行身份驗證。

#### 5. 訪問 API

系統提供統一的 API 端點 `/api/auth/verify`，支援 GET 和 POST 請求，並使用 HTTP 標頭傳遞 JWT 令牌：

##### 方式一：未登錄訪問（訪客模式）

未登錄用戶可以直接訪問 API，但會被標記為未認證用戶：

```bash
# 使用 API 端點
curl "http://localhost:3000/api/auth/verify"
```

響應示例：

```json
{
  "result": "{\"status\":\"success\",\"message\":\"Backend API is working!\"}",
  "proxy_status": "200 OK",
  "authenticated": false,
  "user_info": null
}
```

##### 方式二：使用 JWT 令牌訪問（已認證模式）

成功登錄後，系統將返回 JWT 令牌，可用於訪問 API 並獲取用戶信息：

```bash
# GET 請求
curl "http://localhost:3000/api/auth/verify" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

或者使用 POST 請求：

```bash
# POST 請求
curl -X POST "http://localhost:3000/api/auth/verify" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

響應示例：

```json
{
  "result": "{\"status\":\"success\",\"message\":\"Backend API is working!\"}",
  "proxy_status": "200 OK",
  "authenticated": true,
  "user_info": "用戶名 (用戶ID)"
}
```

### PQC mTLS 連接測試

測試與 Quantum-Safe-Proxy 的 PQC mTLS 連接：

```bash
# GET 請求
curl "http://localhost:3000/api/auth/verify" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 或 POST 請求
curl -X POST "http://localhost:3000/api/auth/verify" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{}'
```

如果一切正常，您將收到類似以下的響應：

```json
{
  "result": "{\"status\":\"success\",\"message\":\"Backend API is working!\"}",
  "proxy_status": "200 OK",
  "authenticated": true,
  "user_info": "用戶名 (用戶ID)"
}
```

如果未提供有效的 JWT 令牌，響應將顯示 `"authenticated": false` 和 `"user_info": null`。

## 證書管理

### 證書生成腳本

本項目包含多個用於生成證書的腳本，所有腳本都位於 `scripts/` 目錄下：

- `generate_certs.sh`：在 Docker 容器中生成所有證書（推薦使用）
- `generate_local_certs.sh`：在本地環境生成所有證書（需要 OpenSSL 3.5）
- `generate_local_client_certs.sh`：僅生成客戶端證書
- `generate_local_server_certs.sh`：僅生成服務器證書
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
chmod +x scripts/generate_local_certs.sh

# 執行腳本
./scripts/generate_local_certs.sh
```

### 混合 PQC 證書

系統使用混合 PQC 證書進行 mTLS 連接，這些證書結合了傳統密碼學（RSA/ECC）和後量子密碼學算法（如 ML-DSA-87）。

生成的證書將位於 `certs/hybrid/ml-dsa-87/` 目錄中：

- `client_hybrid.crt`：混合客戶端證書
- `client_rsa.key`：客戶端 RSA 私鑰
- `server_hybrid.crt`：混合服務器證書
- `server.key`：服務器私鑰

## 環境變量配置

系統支持以下環境變量：

| 環境變量 | 說明 | 默認值 |
|---------|------|-------|
| `JWT_SECRET` | JWT 簽名密鑰 | `your-jwt-secret-key-for-production` |
| `JWT_ISSUER` | JWT 發行者 | `passkeymesh-gateway` |
| `JWT_AUDIENCE` | JWT 受眾 | `backend-service` |
| `ENVIRONMENT` | 運行環境 | `development` |
| `RUST_LOG` | 日誌級別 | `info,tower_http=debug,passkeymesh_gateway=trace` |
| `QUANTUM_SAFE_PROXY_URL` | 量子安全代理的 URL | `https://quantum-safe-proxy:8443` |
| `CLIENT_CERT_PATH` | 客戶端憑證路徑 (mTLS) | `certs_hybrid/hybrid-client/client.crt` |
| `CLIENT_KEY_PATH` | 客戶端私鑰路徑 (mTLS) | `certs_hybrid/hybrid-client/client.key` |
| `CA_CERT_PATH` | CA 憑證路徑 (mTLS) | `certs_hybrid/hybrid-ca/ca.crt` |

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
