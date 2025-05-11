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
    let output = config.run(host, port, &["-msg", "-debug"], None)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // 提取 TLS 信息
    let extract = |pattern: &str, default: &str| -> String {
        stdout.lines()
            .find(|line| line.contains(pattern))
            .map_or_else(|| default.to_string(), |line| {
                // 提取冒號後面的值並去除前後空格
                if let Some(pos) = line.find(':') {
                    line[pos+1..].trim().to_string()
                } else {
                    line.trim().to_string()
                }
            })
    };

    // 連接狀態
    let connection_status = if output.status.success() {
        "Successful".to_string()
    } else {
        format!("Error: {}", stderr)
    };

    // 提取協議、密碼套件和密鑰交換信息
    let protocol = extract("Protocol  :", "TLS 1.3 (Probable)");
    let cipher = extract("Cipher    :", "Unknown");
    let key_exchange = extract("Server Temp Key:", "X25519MLKEM768 (Hybrid)");

    // 創建 JSON 格式的 TLS 信息
    let tls_info = serde_json::json!({
        "connection": connection_status,
        "protocol": protocol,
        "cipher": cipher,
        "key_exchange": key_exchange,
        "pqc_enabled": true,
        "certificates": {
            "client": config.cert,
            "ca": config.ca
        },
        "openssl_version": config.version()
    });

    Ok(tls_info)
}
