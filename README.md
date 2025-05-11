# fidopqc-rs

[English](README.md) | [繁體中文](README.zh-TW.md)

A Rust-based service that integrates FIDO2 (WebAuthn) passwordless authentication with Post-Quantum Cryptography (PQC) mTLS connections. It provides a secure way to verify user identities and communicate with backend services over quantum-safe TLS.

## Project Overview

**fidopqc-rs** is a lightweight, high-performance Rust application focused on integrating two cutting-edge security technologies:

1. **FIDO2/WebAuthn Passwordless Authentication**: Authenticate users with biometrics (e.g., fingerprint) or security keys, eliminating password-related risks.
2. **Post-Quantum Cryptography (PQC) mTLS**: Secure communications using cryptographic algorithms resistant to quantum attacks.

This project demonstrates how to implement these advanced security technologies in modern web applications and provides a scalable foundation for integration with various backend systems.

## System Architecture

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

## Key Features

- **WebAuthn Passwordless Login**: Full implementation of WebAuthn registration and authentication flows.
- **JWT Token Generation & Verification**: Issue JWT tokens after successful authentication for subsequent API authorization.
- **Post-Quantum mTLS**: Uses OpenSSL 3.5 to establish PQC mTLS connections, protecting communications from quantum attacks.
- **TLS Handshake Details**: Displays detailed PQC TLS handshake information, including algorithms and cipher suites.
- **Unified API Endpoints**: Simple API endpoints for user authentication and backend service access.

## Technology Highlights

- **Rust Language**: Ensures memory and thread safety via Rust's ownership and type system.
- **Axum Framework**: High-performance async web framework built on Tokio.
- **OpenSSL 3.5**: Leverages the latest OpenSSL with native PQC algorithm support.
- **X25519MLKEM768**: Hybrid key exchange combining classical and post-quantum cryptography.
- **ML-DSA-87**: Post-quantum digital signature algorithm for hybrid certificates.
- **WebAuthn-rs**: Rust implementation of WebAuthn, supporting all major browsers and platforms.
- **JWT Authentication**: Secure user session management with JSON Web Tokens.

## Prerequisites

- Rust toolchain (>= 1.86.0)
- OpenSSL 3.5 (with PQC support)
- WebAuthn-compatible browser (Chrome / Firefox / Safari)

## Installation & Usage

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/fidopqc-rs.git
cd fidopqc-rs
```

### 2. Install Dependencies

```bash
# On Ubuntu/Debian
sudo apt-get install pkg-config libssl-dev

# On macOS
brew install openssl@3.5
```

### 3. Generate PQC Certificates

```bash
chmod +x scripts/generate_certs.sh
./scripts/generate_certs.sh
```

### 4. Set Environment Variables

Create a `.env` file or export variables:

```bash
# Required
JWT_SECRET=your-secure-jwt-secret
PORT=3001

# Optional
RUST_LOG=info,tower_http=debug,passkeymesh_gateway=trace
```

### 5. Build and Run

```bash
cargo build
cargo run
```

The service will be available at http://localhost:3001.

## Usage Guide

### WebAuthn Registration

1. **Send Registration Request**:

```bash
curl -X POST http://localhost:3001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}'
```

2. **Receive Registration Challenge**:

The service returns a JSON response with a registration challenge:

```json
{
  "status": "success",
  "challenge": "base64_encoded_challenge_data",
  "message": "Please complete registration in browser"
}
```

3. **Complete Registration**:

Visit http://localhost:3001 in your browser and complete registration using biometrics or a security key.

### WebAuthn Login

1. **Send Login Request**:

```bash
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}'
```

2. **Receive Login Challenge**:

```json
{
  "status": "success",
  "challenge": "base64_encoded_challenge_data",
  "message": "Please complete authentication in browser"
}
```

3. **Complete Login**:

Authenticate in the browser using your registered credential.

4. **Receive JWT Token**:

```json
{
  "status": "success",
  "token": "your.jwt.token",
  "message": "Authentication successful"
}
```

### Access API with JWT

Use the JWT token to access protected API endpoints:

```bash
curl http://localhost:3001/api/auth/verify \
  -H "Authorization: Bearer your.jwt.token"
```

Sample response:

```json
{
  "result": "{\"status\":\"success\",\"message\":\"Backend API is working!\",\"authenticated\":true,\"user_info\":\"testuser (1234-5678-9012)\"}",
  "proxy_status": "200 OK",
  "authenticated": true,
  "user_info": "\"testuser (1234-5678-9012)\"",
  "tls_info": "TLS Connection: Successful\nProtocol: TLSv1.3\nCipher: TLS_AES_256_GCM_SHA384\nKey Exchange: X25519MLKEM768 (Hybrid)\nPost-Quantum Cryptography: Enabled\nCert: certs/hybrid-client/client.crt\nCA: certs/hybrid-ca/ca.crt\nOpenSSL: OpenSSL 3.5.0 (PQC)"
}
```

## Project Structure

```
fidopqc-rs/
├── Cargo.toml                # Rust project config
├── Cargo.lock                # Dependency lock file
├── src/                      # Source code
│   ├── main.rs               # Entry point
│   ├── webauthn.rs           # WebAuthn logic
│   ├── call_proxy.rs         # PQC mTLS logic
│   ├── jwt.rs                # JWT logic
│   └── error.rs              # Error handling
├── scripts/                  # Scripts
│   ├── generate_certs.sh     # PQC cert generation
│   └── clean_certs.sh        # Cert cleanup
├── certs/                    # Certificates (generated)
│   ├── hybrid-ca/            # CA certs
│   ├── hybrid-server/        # Server certs
│   └── hybrid-client/        # Client certs
├── index.html                # Demo frontend
├── .env                      # Env config
└── .env.example              # Env example
```

## Module Overview

### main.rs

- Sets up Axum routes and middleware
- Configures CORS and logging
- Initializes WebAuthn instance
- Creates PQC mTLS client
- Starts HTTP server

### webauthn.rs

- Handles WebAuthn registration and login
- Manages user credentials
- Issues JWT tokens

### call_proxy.rs

- Establishes PQC mTLS connections using OpenSSL 3.5
- Retrieves TLS handshake info
- Sends HTTP requests to backend
- Parses responses

### jwt.rs

- Generates and verifies JWT tokens
- Extracts user info from JWT

### error.rs

- Defines error types and conversions
- Provides user-friendly error messages

## PQC mTLS Implementation

fidopqc-rs uses OpenSSL 3.5 for PQC mTLS connections:

### Hybrid Key Exchange

Uses **X25519MLKEM768** for hybrid key exchange:
- **X25519**: Classical elliptic curve cryptography
- **MLKEM768**: Post-quantum algorithm

This hybrid approach ensures security even if one algorithm is compromised.

### PQC Certificates

Uses **ML-DSA-87** for hybrid certificates:
- **CA Certificate**: Signs server and client certs
- **Server Certificate**: For server authentication
- **Client Certificate**: For client authentication

### TLS 1.3

Leverages TLS 1.3 for:
- Faster handshakes
- Improved security
- Fewer round-trips
- Better privacy

## Environment Variables

| Variable                | Description                  | Default                                  | Required? |
|-------------------------|------------------------------|------------------------------------------|-----------|
| `JWT_SECRET`            | JWT signing key              | None                                     | Yes       |
| `JWT_ISSUER`            | JWT issuer                   | `passkeymesh-gateway`                    | No        |
| `JWT_AUDIENCE`          | JWT audience                 | `backend-service`                        | No        |
| `PORT`                  | Server port                  | `3001`                                   | No        |
| `ENVIRONMENT`           | Environment                  | `development`                            | No        |
| `RUST_LOG`              | Log level                    | `info`                                   | No        |
| `CLIENT_CERT_PATH`      | Client cert path             | `certs/hybrid-client/client.crt`         | No        |
| `CLIENT_KEY_PATH`       | Client key path              | `certs/hybrid-client/client_pkcs8.key`   | No        |
| `CA_CERT_PATH`          | CA cert path                 | `certs/hybrid-ca/ca.crt`                 | No        |
| `OPENSSL_PATH`          | OpenSSL 3.5 path             | Auto-detect                              | No        |
| `QUANTUM_SAFE_PROXY_URL`| Quantum-safe proxy URL       | `https://localhost:8443`                 | No        |

## Security Best Practices

- Use strong, random JWT secrets and store them securely.
- Regularly update certificates and use secure key lengths.
- Use a database for production data storage (not in-memory).
- Avoid logging sensitive data (e.g., JWTs, passwords).
- Do not expose detailed error messages to clients.
- Stay updated with PQC standards and algorithms.

## Integration & Extension

**fidopqc-rs** is designed for extensibility and integration:

### Direct PQC Backend

If your backend supports PQC TLS:

```
fidopqc-rs <-- PQC mTLS --> PQC-enabled Backend
```

### Via Proxy

If your backend does not support PQC TLS:

```
fidopqc-rs <-- PQC mTLS --> Quantum-Safe-Proxy <-- TLS --> Legacy Backend
```

### Hybrid Deployment

Support both PQC and classical TLS for smooth migration:

```
fidopqc-rs <-- PQC mTLS --> PQC-enabled Services
fidopqc-rs <-- TLS --> Legacy Services
```

## Contributing

Contributions are welcome! Please:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to your branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Author

- **Jerry** - [GitHub](https://github.com/JerryR7)
- **Email**: vp780412@gmail.com

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.
