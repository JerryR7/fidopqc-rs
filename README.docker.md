# FIDO2 & PQC mTLS Demo Environment (Docker Compose)

[English](README.docker.md) | [繁體中文](README.docker.zh-TW.md)

This Docker Compose setup provides a complete demo environment to showcase the integration of FIDO2 passwordless authentication and post-quantum cryptography (PQC) mTLS connections. It demonstrates how legacy backend services can accept PQC TLS connections via a Quantum-Safe-Proxy.

## Architecture Overview

```
+-------------------+      +---------------------+      +-------------------+
|                   |      |                     |      |                   |
|  PasskeyMesh      | PQC  |  Quantum-Safe-      | TLS  |  Backend          |
|  Gateway          +----->+  Proxy              +----->+  Service          |
|  (FIDO2 + PQC)    | mTLS |  (OpenSSL 3.5)      |      |  (JWT Auth)       |
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

**Components:**

1. **PasskeyMesh Gateway**: Rust app handling WebAuthn authentication and PQC mTLS connections.
2. **Quantum-Safe-Proxy**: Proxy using OpenSSL 3.5, translating PQC TLS to standard TLS.
3. **Backend Service**: Simulated backend with JWT authentication.

## Quick Start

### 1. Prepare Certificates

```bash
# Start the Quantum-Safe-Proxy container
docker compose up -d quantum-safe-proxy

# Run the certificate generation script
docker exec -it fidopqc-rs-quantum-safe-proxy-1 /app/scripts/generate_certs.sh
```

### 2. Start All Services

```bash
# Build and start all services
docker compose up -d

# View logs
docker compose logs -f
```

### 3. Access the Demo

- Visit http://localhost:3001 for WebAuthn registration and login.
- Visit http://localhost:3001/api/auth/verify to view PQC TLS handshake info.

## Service Details

### PasskeyMesh Gateway (Rust App)

- **Port**: 3001
- **Features**: WebAuthn authentication, JWT generation, PQC mTLS connection
- **Config**: Via environment variables in Docker Compose

### Quantum-Safe-Proxy

- **Port**: 8443 (internal only)
- **Features**: Translates PQC TLS to standard TLS
- **Config**: Via `config.json`

### Backend Service

- **Port**: 6000 (internal only)
- **Features**: Handles API requests and JWT verification
- **Config**: Via OpenResty config

## Demo Highlights

- **PQC Integration**: Showcases how legacy services can accept PQC TLS via proxy.
- **End-to-End Authentication**: Full flow from WebAuthn registration/login to JWT verification.
- **PQC TLS Handshake Info**: Displays detailed PQC TLS connection info.

## Environment Variables

Key environment variables in Docker Compose:

| Variable                | Description                        | Default                                      |
|-------------------------|------------------------------------|----------------------------------------------|
| `JWT_SECRET`            | JWT signing key                    | `your-jwt-secret-key-for-production`         |
| `QUANTUM_SAFE_PROXY_URL`| Quantum-Safe-Proxy URL             | `https://quantum-safe-proxy:8443`            |
| `CLIENT_CERT_PATH`      | Client certificate path            | `/app/certs/hybrid-client/client.crt`        |
| `CLIENT_KEY_PATH`       | Client private key path            | `/app/certs/hybrid-client/client_pkcs8.key`  |
| `CA_CERT_PATH`          | CA certificate path                | `/app/certs/hybrid-ca/ca.crt`                |

## Troubleshooting

```bash
# View logs for all services
docker compose logs -f

# View logs for a specific service
docker compose logs -f passkeymesh-gateway
docker compose logs -f quantum-safe-proxy
docker compose logs -f backend-service
```

## Notes

- This is a demo environment; do not use in production.
- Certificates are self-signed and for demo purposes only.
- Use strong random JWT secrets in production.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
