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

    // 使用 -ciphersuites 參數獲取更多信息
    let output = config.run(host, port, &["-brief"], None)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // 合併 stdout 和 stderr，以便同時檢查兩者中的 TLS 信息
    let combined_output = format!("{}\n{}", stdout, stderr);
    let tls_output = &combined_output;

    // 提取 TLS 信息
    let extract = |pattern: &str, default: &str| -> String {
        // 首先嘗試精確匹配
        let result = tls_output.lines()
            .find(|line| line.contains(pattern))
            .map(|line| {
                // 提取冒號後面的值並去除前後空格
                if let Some(pos) = line.find(':') {
                    line[pos+1..].trim().to_string()
                } else {
                    line.trim().to_string()
                }
            });

        // 如果精確匹配失敗，嘗試更寬鬆的匹配（忽略多餘的空格）
        if result.is_none() {
            let pattern_base = pattern.trim().split_whitespace().next().unwrap_or("");
            tls_output.lines()
                .find(|line| line.contains(pattern_base) && line.contains(":"))
                .map_or_else(|| default.to_string(), |line| {
                    if let Some(pos) = line.find(':') {
                        line[pos+1..].trim().to_string()
                    } else {
                        line.trim().to_string()
                    }
                })
        } else {
            result.unwrap_or_else(|| default.to_string())
        }
    };

    // 連接狀態
    let connection_status = if output.status.success() {
        "Successful".to_string()
    } else {
        format!("Error: {}", stderr)
    };

    // 提取協議、密碼套件和密鑰交換信息
    let mut protocol = extract("Protocol version:", "");
    if protocol.is_empty() {
        // 嘗試從其他行中提取
        for line in tls_output.lines() {
            if line.contains("Protocol version:") {
                if let Some(pos) = line.find("Protocol version:") {
                    protocol = line[pos + "Protocol version:".len()..].trim().to_string();
                    break;
                }
            } else if line.contains("Protocol:") {
                if let Some(pos) = line.find("Protocol:") {
                    protocol = line[pos + "Protocol:".len()..].trim().to_string();
                    break;
                }
            } else if line.contains("New,") && line.contains("Protocol") {
                if let Some(pos) = line.find("New,") {
                    let parts: Vec<&str> = line[pos..].split(',').collect();
                    if parts.len() > 1 {
                        protocol = parts[1].trim().to_string();
                        break;
                    }
                }
            }
        }

        // 如果仍然為空，顯示 Unknown
        if protocol.is_empty() {
            protocol = "Unknown".to_string();
        }
    }

    // 嘗試多種方式提取密碼套件信息
    let mut cipher = extract("Ciphersuite:", "");
    if cipher.is_empty() {
        // 嘗試從 New 行中提取
        for line in tls_output.lines() {
            if line.contains("Ciphersuite:") {
                if let Some(pos) = line.find("Ciphersuite:") {
                    cipher = line[pos + "Ciphersuite:".len()..].trim().to_string();
                    break;
                }
            } else if line.contains("New") && line.contains("Cipher") && line.contains("is") {
                if let Some(pos) = line.rfind("is") {
                    cipher = line[pos+2..].trim().to_string();
                    break;
                }
            } else if line.contains("Cipher:") {
                if let Some(pos) = line.find("Cipher:") {
                    cipher = line[pos + "Cipher:".len()..].trim().to_string();
                    break;
                }
            }
        }

        // 如果仍然為空，顯示 Unknown
        if cipher.is_empty() {
            cipher = "Unknown".to_string();
        }
    }

    // 清理 cipher 值，只保留密碼套件名稱
    // 例如，從 "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" 中提取 "TLS_AES_256_GCM_SHA384"
    if !cipher.is_empty() && cipher != "Unknown" {
        if cipher.contains("TLS_") {
            if let Some(pos) = cipher.find("TLS_") {
                cipher = cipher[pos..].trim().to_string();
            }
        }
    }

    // 嘗試多種方式提取密鑰交換信息
    let mut key_exchange = extract("Negotiated TLS1.3 group:", "");
    if key_exchange.is_empty() {
        // 嘗試從其他行中提取
        for line in tls_output.lines() {
            if line.contains("Negotiated TLS1.3 group:") {
                if let Some(pos) = line.find("Negotiated TLS1.3 group:") {
                    key_exchange = line[pos + "Negotiated TLS1.3 group:".len()..].trim().to_string();
                    break;
                }
            } else if line.contains("Server Temp Key:") {
                if let Some(pos) = line.find("Server Temp Key:") {
                    key_exchange = line[pos + "Server Temp Key:".len()..].trim().to_string();
                    break;
                }
            }
        }

        // 如果仍然為空，顯示 Unknown
        if key_exchange.is_empty() {
            key_exchange = "Unknown".to_string();
        }
    }

    // 提取簽名類型信息
    let mut signature_type = extract("Signature type:", "Unknown");
    if signature_type.is_empty() {
        // 嘗試從其他行中提取
        for line in tls_output.lines() {
            if line.contains("Signature type:") {
                if let Some(pos) = line.find("Signature type:") {
                    signature_type = line[pos + "Signature type:".len()..].trim().to_string();
                    break;
                }
            }
        }

        // 如果仍然為空，顯示 Unknown
        if signature_type.is_empty() {
            signature_type = "Unknown".to_string();
        }
    }

    // 只輸出簡短的摘要信息，而不是完整的 OpenSSL 輸出
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
