use std::{env, io::Write, process::{Command, Stdio}};
use serde_json::Value;

use crate::error::{AppError, AppResult};

/// TLS 配置結構體，包含 OpenSSL 路徑和證書路徑
pub struct TlsConfig {
    pub openssl: String,
    pub cert: String,
    pub key: String,
    pub ca: String,
}

impl TlsConfig {
    /// 創建新的 TLS 配置，從環境變量或默認值獲取路徑
    pub fn new() -> Self {
        Self {
            openssl: env::var("OPENSSL_PATH").unwrap_or_else(|_| {
                for path in [
                    "/usr/local/Cellar/openssl@3.5/3.5.0/bin/openssl",
                    "/usr/local/opt/openssl@3.5/bin/openssl",
                    "/opt/openssl35/bin/openssl",
                    "openssl35",
                    "openssl"
                ] {
                    if Command::new(path).arg("version").output().is_ok() {
                        return path.to_string();
                    }
                }
                "openssl".to_string()
            }),
            cert: env::var("CLIENT_CERT_PATH").unwrap_or_else(|_| "certs/hybrid-client/client.crt".to_string()),
            key: env::var("CLIENT_KEY_PATH").unwrap_or_else(|_| "certs/hybrid-client/client_pkcs8.key".to_string()),
            ca: env::var("CA_CERT_PATH").unwrap_or_else(|_| "certs/hybrid-ca/ca.crt".to_string()),
        }
    }

    /// 執行 OpenSSL 命令
    pub fn run(&self, host: &str, port: u16, args: &[&str], stdin: Option<&[u8]>) -> AppResult<std::process::Output> {
        let mut cmd = Command::new(&self.openssl);
        cmd.arg("s_client")
           .arg("-connect").arg(format!("{}:{}", host, port))
           .arg("-cert").arg(&self.cert)
           .arg("-key").arg(&self.key)
           .arg("-CAfile").arg(&self.ca)
           .arg("-tls1_3")
           .arg("-groups").arg("X25519MLKEM768");

        for arg in args {
            cmd.arg(arg);
        }

        if let Some(data) = stdin {
            let mut child = cmd.stdin(Stdio::piped())
                              .stdout(Stdio::piped())
                              .stderr(Stdio::piped())
                              .spawn()
                              .map_err(|e| AppError::Internal(format!("OpenSSL spawn error: {}", e)))?;

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(data)
                    .map_err(|e| AppError::Internal(format!("OpenSSL stdin error: {}", e)))?;
            }

            child.wait_with_output()
                .map_err(|e| AppError::Internal(format!("OpenSSL error: {}", e)))
        } else {
            cmd.output()
                .map_err(|e| AppError::Internal(format!("OpenSSL error: {}", e)))
        }
    }

    /// 獲取 OpenSSL 版本
    pub fn version(&self) -> String {
        Command::new(&self.openssl)
            .arg("version")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }

    // 這些方法已不再需要，因為字段現在是公開的
}

/// 獲取 TLS 連接信息
pub fn get_tls_info(host: &str, port: u16) -> AppResult<Value> {
    let config = TlsConfig::new();

    // 使用 -brief 參數獲取簡潔的 TLS 信息
    let output = config.run(host, port, &["-brief"], None)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // 合併 stdout 和 stderr，以便同時檢查兩者中的 TLS 信息
    let tls_output = format!("{}\n{}", stdout, stderr);

    // 連接狀態
    let connection_status = if output.status.success() {
        "Successful".to_string()
    } else {
        format!("Error: {}", stderr)
    };

    // 通用的提取函數，支持多種模式匹配
    let extract_value = |patterns: &[&str], default: &str| -> String {
        for pattern in patterns {
            for line in tls_output.lines() {
                if line.contains(pattern) {
                    if let Some(pos) = line.find(':') {
                        let value = line[pos+1..].trim().to_string();
                        if !value.is_empty() {
                            return value;
                        }
                    }
                }
            }
        }
        default.to_string()
    };

    // 提取 TLS 協議版本
    let protocol = extract_value(
        &["Protocol version:", "Protocol:"],
        "Unknown"
    );

    // 提取密碼套件信息
    let mut cipher = extract_value(
        &["Ciphersuite:", "Cipher is", "Cipher:"],
        "Unknown"
    );

    // 清理 cipher 值，只保留密碼套件名稱
    if !cipher.is_empty() && cipher != "Unknown" && cipher.contains("TLS_") {
        if let Some(pos) = cipher.find("TLS_") {
            cipher = cipher[pos..].trim().to_string();
        }
    }

    // 提取密鑰交換信息
    let key_exchange = extract_value(
        &["Negotiated TLS1.3 group:", "Server Temp Key:"],
        "Unknown"
    );

    // 提取簽名類型信息
    let signature_type = extract_value(
        &["Signature type:"],
        "Unknown"
    );

    // 只輸出簡短的摘要信息
    tracing::debug!("TLS Connection: Protocol={}, Cipher={}, KeyExchange={}, SignatureType={}",
                   protocol, cipher, key_exchange, signature_type);

    // 創建 JSON 格式的 TLS 信息
    let tls_info = serde_json::json!({
        "connection": connection_status,
        "protocol": protocol,
        "cipher": cipher,
        "key_exchange": key_exchange,
        "signature_type": signature_type,
        "pqc_enabled": true,
        "certificates": {
            "client": config.cert,
            "ca": config.ca
        },
        "openssl_version": config.version()
    });

    Ok(tls_info)
}
