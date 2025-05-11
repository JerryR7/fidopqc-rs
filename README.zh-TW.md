# fidopqc-rs

[English](README.md) | [繁體中文](README.zh-TW.md)

一個使用 Rust 開發的服務，結合了 FIDO2 (WebAuthn) 無密碼認證與後量子密碼學 (PQC) mTLS 連接功能。它提供了一個安全的方式來驗證用戶身份，並通過量子安全的 TLS 連接與後端服務通信。

## 專案概述

fidopqc-rs 是一個輕量級、高效能的 Rust 應用程序，專注於兩個關鍵安全技術的整合：

1. **FIDO2/WebAuthn 無密碼認證**：使用生物識別（如指紋）或安全密鑰進行身份驗證，消除密碼相關的風險
2. **後量子密碼學 (PQC) mTLS**：使用抵抗量子計算攻擊的密碼學算法進行安全通信

這個專案旨在展示如何在現代 Web 應用中實現這兩種先進的安全技術，並提供一個可擴展的基礎，可以整合到各種後端系統中。

## 系統架構

```
+-------------------+              +-------------------+
|                   |              |                   |
|  fidopqc-rs       |     PQC      |  Backend          |
|  (FIDO2 + PQC)    +------------->+  Service          |
|                   |     mTLS     |                   |
+-------------------+              +-------------------+
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

## 核心功能

- **WebAuthn 無密碼登入**：完整實現 WebAuthn 標準的註冊和登錄流程
- **JWT 令牌生成與驗證**：成功身份驗證後生成 JWT 令牌，用於後續請求的授權
- **後量子密碼學 mTLS**：使用 OpenSSL 3.5 實現 PQC mTLS 連接，保護通信免受量子計算攻擊
- **TLS 握手信息展示**：詳細顯示 PQC TLS 握手的信息，包括使用的算法和密碼套件
- **統一 API 端點**：提供簡潔的 API 端點，用於驗證用戶身份和訪問後端服務

## 技術特點

- **Rust 語言**：使用 Rust 的所有權模型和類型系統確保內存安全和線程安全
- **Axum 框架**：基於 Tokio 的高效能 Web 框架，提供異步處理能力
- **OpenSSL 3.5**：使用最新的 OpenSSL 3.5 版本，原生支持後量子密碼學算法
- **X25519MLKEM768**：使用混合密鑰交換算法，結合傳統橢圓曲線密碼學和後量子密碼學
- **ML-DSA-87**：使用後量子數字簽名算法生成混合證書
- **WebAuthn-rs**：使用 Rust 實現的 WebAuthn 庫，支持所有主流瀏覽器和平台
- **JWT 認證**：使用 JSON Web Token 進行安全的用戶會話管理

## 先決條件

- Rust 工具鏈（版本 >= 1.86.0）
- OpenSSL 3.5（支援後量子密碼學）
- 支持 WebAuthn 的瀏覽器（Chrome / Firefox / Safari）

## 安裝與運行

### 1. 克隆專案

```bash
git clone https://github.com/yourusername/fidopqc-rs.git
cd fidopqc-rs
```

### 2. 安裝依賴

```bash
# 在 Ubuntu/Debian 上安裝 OpenSSL 開發庫
sudo apt-get install pkg-config libssl-dev

# 或在 macOS 上
brew install openssl@3.5
```

### 3. 生成 PQC 證書

```bash
# 確保腳本有執行權限
chmod +x scripts/generate_certs.sh

# 執行腳本生成證書
./scripts/generate_certs.sh
```

### 4. 設置環境變量

創建 `.env` 文件或設置環境變量：

```bash
# 必要的環境變量
JWT_SECRET=your-secure-jwt-secret
PORT=3001

# 可選的環境變量
RUST_LOG=info,tower_http=debug,passkeymesh_gateway=trace
```

### 5. 構建和運行

```bash
# 構建項目
cargo build

# 運行服務
cargo run
```

服務將在 http://localhost:3001 上啟動。

## 詳細使用方法

### WebAuthn 註冊流程

1. **發送註冊請求**：

```bash
curl -X POST http://localhost:3001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}'
```

2. **獲取註冊挑戰**：

服務將返回一個包含註冊挑戰的 JSON 響應：

```json
{
  "status": "success",
  "challenge": "base64_encoded_challenge_data",
  "message": "Please complete registration in browser"
}
```

3. **完成註冊**：

在瀏覽器中訪問 http://localhost:3001，使用返回的挑戰完成註冊過程。系統將提示您使用生物識別（如指紋）或安全密鑰來創建 FIDO2 憑證。

### WebAuthn 登錄流程

1. **發送登錄請求**：

```bash
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}'
```

2. **獲取登錄挑戰**：

服務將返回一個包含登錄挑戰的 JSON 響應：

```json
{
  "status": "success",
  "challenge": "base64_encoded_challenge_data",
  "message": "Please complete authentication in browser"
}
```

3. **完成登錄**：

在瀏覽器中訪問 http://localhost:3001，使用返回的挑戰完成登錄過程。系統將提示您使用之前註冊的生物識別或安全密鑰進行身份驗證。

4. **獲取 JWT 令牌**：

成功登錄後，系統將返回一個 JWT 令牌：

```json
{
  "status": "success",
  "token": "your.jwt.token",
  "message": "Authentication successful"
}
```

### 使用 JWT 令牌訪問 API

使用獲取的 JWT 令牌訪問 API 端點：

```bash
curl http://localhost:3001/api/auth/verify \
  -H "Authorization: Bearer your.jwt.token"
```

響應示例：

```json
{
  "result": "{\"status\":\"success\",\"message\":\"Backend API is working!\",\"authenticated\":true,\"user_info\":\"testuser (1234-5678-9012)\"}",
  "proxy_status": "200 OK",
  "authenticated": true,
  "user_info": "\"testuser (1234-5678-9012)\"",
  "tls_info": "TLS Connection: Successful\nProtocol: TLSv1.3\nCipher: TLS_AES_256_GCM_SHA384\nKey Exchange: X25519MLKEM768 (Hybrid)\nPost-Quantum Cryptography: Enabled\nCert: certs/hybrid-client/client.crt\nCA: certs/hybrid-ca/ca.crt\nOpenSSL: OpenSSL 3.5.0 (PQC)"
}
```

## 詳細項目結構

```
fidopqc-rs/
├── Cargo.toml                # Rust 項目配置
├── Cargo.lock                # 依賴鎖定文件
├── src/                      # 源代碼目錄
│   ├── main.rs               # 程序入口點
│   ├── webauthn.rs           # WebAuthn 註冊和登錄邏輯
│   ├── call_proxy.rs         # PQC mTLS 連接邏輯
│   ├── jwt.rs                # JWT 令牌生成和驗證
│   └── error.rs              # 錯誤處理
├── scripts/                  # 腳本目錄
│   ├── generate_certs.sh     # 生成 PQC 證書的腳本
│   └── clean_certs.sh        # 清理證書的腳本
├── certs/                    # 證書目錄 (由腳本生成)
│   ├── hybrid-ca/            # CA 證書目錄
│   ├── hybrid-server/        # 服務器證書目錄
│   └── hybrid-client/        # 客戶端證書目錄
├── index.html                # 前端演示頁面
├── .env                      # 環境變量配置
└── .env.example              # 環境變量示例
```

## 核心模塊詳細說明

### main.rs

程序的入口點，負責：
- 設置 Axum 路由和中間件
- 配置 CORS 和日誌
- 初始化 WebAuthn 實例
- 創建 PQC mTLS 客戶端
- 啟動 HTTP 服務器

### webauthn.rs

實現 WebAuthn 註冊和登錄功能：
- 創建註冊和登錄挑戰
- 驗證註冊和登錄響應
- 管理用戶憑證
- 生成 JWT 令牌

### call_proxy.rs

實現 PQC mTLS 連接和 TLS 握手信息獲取：
- 使用 OpenSSL 3.5 建立 PQC mTLS 連接
- 獲取 TLS 握手信息
- 發送 HTTP 請求到後端服務
- 解析 HTTP 響應

### jwt.rs

處理 JWT 令牌的生成和驗證：
- 生成包含用戶信息的 JWT 令牌
- 驗證 JWT 令牌的有效性
- 從 JWT 令牌中提取用戶信息

### error.rs

定義應用程序錯誤類型和處理邏輯：
- 定義各種錯誤類型
- 實現錯誤轉換
- 提供友好的錯誤消息

## PQC mTLS 實現詳細說明

fidopqc-rs 使用 OpenSSL 3.5 實現後量子密碼學 mTLS 連接，主要特點：

### 混合密鑰交換算法

使用 X25519MLKEM768 混合密鑰交換算法，結合：
- **X25519**：傳統橢圓曲線密碼學，提供當前的安全性
- **MLKEM768**：後量子密碼學算法，提供抵抗量子計算攻擊的安全性

這種混合方法確保即使其中一種算法被破解，整體安全性仍然得到保障。

### PQC 證書

使用 ML-DSA-87 算法生成的混合證書：
- **CA 證書**：用於簽署服務器和客戶端證書
- **服務器證書**：用於服務器身份驗證
- **客戶端證書**：用於客戶端身份驗證

### TLS 1.3 協議

使用最新的 TLS 1.3 協議，提供：
- 更快的握手速度
- 更好的安全性
- 更少的往返次數
- 更好的隱私保護

## 環境變量詳細配置

| 環境變量 | 說明 | 默認值 | 必須? |
|---------|------|-------|------|
| `JWT_SECRET` | JWT 簽名密鑰 | 無 | 是 |
| `JWT_ISSUER` | JWT 發行者 | `passkeymesh-gateway` | 否 |
| `JWT_AUDIENCE` | JWT 受眾 | `backend-service` | 否 |
| `PORT` | 服務器監聽端口 | `3001` | 否 |
| `ENVIRONMENT` | 運行環境 | `development` | 否 |
| `RUST_LOG` | 日誌級別 | `info` | 否 |
| `CLIENT_CERT_PATH` | 客戶端憑證路徑 | `certs/hybrid-client/client.crt` | 否 |
| `CLIENT_KEY_PATH` | 客戶端私鑰路徑 | `certs/hybrid-client/client_pkcs8.key` | 否 |
| `CA_CERT_PATH` | CA 憑證路徑 | `certs/hybrid-ca/ca.crt` | 否 |
| `OPENSSL_PATH` | OpenSSL 3.5 路徑 | 自動檢測 | 否 |
| `QUANTUM_SAFE_PROXY_URL` | 量子安全代理的 URL | `https://localhost:8443` | 否 |

## 安全最佳實踐

- **JWT 密鑰**：使用強隨機值，並通過環境變量或安全存儲提供
- **證書管理**：定期更新證書，使用安全的密鑰長度
- **數據存儲**：在生產環境中使用數據庫而非內存存儲
- **日誌處理**：不要記錄敏感信息，如 JWT 令牌或密碼
- **錯誤處理**：不要向客戶端暴露詳細的錯誤信息
- **定期更新**：PQC 算法仍在標準化過程中，應定期更新以使用最新的安全算法

## 擴展與整合

fidopqc-rs 設計為可擴展的，可以與各種後端系統整合：

### 直接連接

如果後端服務支援 PQC TLS，可以直接連接：

```
fidopqc-rs <-- PQC mTLS --> PQC-enabled Backend
```

### 通過代理連接

如果後端服務不支援 PQC TLS，可以通過 Quantum-Safe-Proxy 連接：

```
fidopqc-rs <-- PQC mTLS --> Quantum-Safe-Proxy <-- TLS --> Legacy Backend
```

### 混合部署

可以同時支援傳統 TLS 和 PQC TLS 連接，實現平滑過渡：

```
fidopqc-rs <-- PQC mTLS --> PQC-enabled Services
fidopqc-rs <-- TLS --> Legacy Services
```

## 貢獻指南

歡迎貢獻！請遵循以下步驟：

1. Fork 專案
2. 創建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 開啟 Pull Request

## 許可證

MIT
