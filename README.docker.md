# PasskeyMesh Gateway with Quantum-Safe-Proxy

這個項目包含了 PasskeyMesh Gateway 和 Quantum-Safe-Proxy 的 Docker Compose 設置，用於演示 WebAuthn 無密碼登錄、JWT 生成和 PQC mTLS 連接。

## 架構

系統由以下幾個部分組成：

1. **PasskeyMesh Gateway**：處理 WebAuthn 無密碼登錄、JWT 生成和 PQC mTLS 連接到 Quantum-Safe-Proxy。
2. **Quantum-Safe-Proxy**：提供後量子密碼學 (PQC) 支持的 TLS 代理。
3. **Backend Service**：一個簡單的 Nginx 服務，作為後端 API。

## 前提條件

- Docker 和 Docker Compose
- Quantum-Safe-Proxy 的 Docker 映像（quantum-safe-proxy:openssl35 或 quantum-safe-proxy:oqs）

## 目錄結構

```
.
├── Cargo.toml
├── Cargo.lock
├── config.json
├── docker-compose.yml
├── Dockerfile.gateway
├── index.html
├── src/
│   └── ...
├── certs/
│   ├── hybrid/
│   │   └── ml-dsa-87/
│   │       ├── server_hybrid.crt
│   │       └── server.key
│   └── traditional/
│       └── rsa/
│           ├── ca.crt
│           ├── server.crt
│           └── server.key
└── docker/
    └── nginx/
        ├── html/
        │   └── index.html
        └── nginx.conf
```

## 使用方法

### 1. 準備證書

在啟動服務之前，請確保 `certs` 目錄中有必要的證書。如果設置了 `AUTO_GENERATE_CERTS=true`，Quantum-Safe-Proxy 將自動生成證書。

### 2. 構建和啟動服務

```bash
docker-compose up -d
```

### 3. 訪問服務

- PasskeyMesh Gateway: http://localhost:3000
- Quantum-Safe-Proxy: https://localhost:8443
- Backend Service: http://localhost:6000

## 配置

### PasskeyMesh Gateway

PasskeyMesh Gateway 的配置通過環境變量設置：

- `RUST_LOG`：日誌級別
- `QUANTUM_SAFE_PROXY_URL`：Quantum-Safe-Proxy 的 URL

### Quantum-Safe-Proxy

Quantum-Safe-Proxy 的配置通過命令行參數和 `config.json` 文件設置。

## 故障排除

如果遇到問題，請檢查各個服務的日誌：

```bash
docker-compose logs passkeymesh-gateway
docker-compose logs quantum-safe-proxy
docker-compose logs backend
```
