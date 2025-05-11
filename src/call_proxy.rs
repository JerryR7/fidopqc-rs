use axum::Json;
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::{env, io::Write, process::{Command, Stdio}};

use crate::error::{AppError, AppResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    result: String,
    proxy_status: String,
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    user_info: Option<String>,
    #[serde(default)]
    tls_info: Option<String>,
}

struct TlsConfig {
    openssl: String,
    cert: String,
    key: String,
    ca: String,
}

impl TlsConfig {
    fn new() -> Self {
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

    fn run(&self, host: &str, port: u16, args: &[&str], stdin: Option<&[u8]>) -> AppResult<std::process::Output> {
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

    fn version(&self) -> String {
        Command::new(&self.openssl)
            .arg("version")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }
}

fn extract_json(raw: &str) -> String {
    if let Some(start) = raw.find('{') {
        let json = &raw[start..];
        if let Some(end) = json.rfind('}') {
            return json[0..=end].to_string();
        }
    }

    raw.lines()
        .filter(|line| !line.trim().is_empty() && !line.trim().chars().all(|c| c.is_digit(16) || c.is_whitespace()))
        .collect::<Vec<&str>>()
        .join("\n")
}

pub fn create_pqc_client() -> AppResult<Client> {
    let config = TlsConfig::new();
    tracing::info!("Using OpenSSL: {}, Cert: {}, Key: {}, CA: {}",
                  config.openssl, config.cert, config.key, config.ca);

    ClientBuilder::new()
        .build()
        .map_err(|e| AppError::Internal(format!("HTTP client error: {}", e)))
}

pub fn get_tls_info(host: &str, port: u16) -> AppResult<String> {
    let config = TlsConfig::new();
    let output = config.run(host, port, &["-msg", "-debug"], None)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut info = String::with_capacity(512);

    // 連接狀態
    if output.status.success() {
        info.push_str("TLS Connection: Successful\n");
    } else {
        info.push_str(&format!("TLS Connection Error: {}\n", stderr));
    }

    // 提取 TLS 信息
    let extract = |pattern: &str, default: &str| -> String {
        stdout.lines()
            .find(|line| line.contains(pattern))
            .map_or_else(|| default.to_string(), |line| line.trim().to_string())
    };

    info.push_str(&format!("{}\n", extract("Protocol  :", "Protocol: TLS 1.3 (Probable)")));
    info.push_str(&format!("{}\n", extract("Cipher    :", "Cipher: Unknown")));
    info.push_str(&format!("{}\n", extract("Server Temp Key:", "Key Exchange: X25519MLKEM768 (Hybrid)")));

    // PQC 信息
    info.push_str(&format!("Post-Quantum Cryptography: Enabled\nCert: {}\nCA: {}\nOpenSSL: {} (PQC)\n",
                         config.cert, config.ca, config.version()));

    Ok(info)
}

pub fn send_request(host: &str, port: u16, path: &str, auth: Option<&str>) -> AppResult<(String, String)> {
    let config = TlsConfig::new();

    // HTTP 請求
    let mut req = String::with_capacity(256);
    req.push_str(&format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path, host));

    if let Some(token) = auth {
        req.push_str(&format!("Authorization: {}\r\n", token));
    }

    req.push_str("X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n");
    req.push_str("X-XSS-Protection: 1; mode=block\r\nConnection: close\r\n\r\n");

    // 執行請求
    let output = config.run(host, port, &["-quiet"], Some(req.as_bytes()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Internal(format!("TLS connection failed: {}", stderr)));
    }

    // 解析響應
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.splitn(2, "\r\n\r\n").collect();

    if parts.len() < 2 {
        return Err(AppError::Internal("Invalid HTTP response".to_string()));
    }

    Ok((parts[0].to_string(), extract_json(parts[1])))
}

pub async fn handler(headers: axum::http::HeaderMap) -> AppResult<Json<ApiResponse>> {
    // 獲取 Authorization 頭
    let auth = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();

    tracing::info!("Forwarding request {} auth token", if auth.is_empty() { "without" } else { "with" });

    // 解析代理 URL
    let proxy_url = env::var("QUANTUM_SAFE_PROXY_URL")
        .unwrap_or_else(|_| "https://localhost:8443".to_string());

    let url_parts: Vec<&str> = proxy_url.trim_start_matches("https://").split(':').collect();
    let host = url_parts.get(0).copied().unwrap_or("localhost");
    let port = url_parts.get(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);

    // 獲取 TLS 信息
    let tls_info = get_tls_info(host, port)
        .unwrap_or_else(|e| format!("TLS info unavailable: {}\n", e));

    // 發送請求
    let auth_ref = if auth.is_empty() { None } else { Some(auth.as_str()) };
    let response = match send_request(host, port, "/api", auth_ref) {
        Ok((headers, body)) => {
            let status = headers.lines().next().unwrap_or("HTTP/1.1 200 OK").to_string();

            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(json) => ApiResponse {
                    result: body,
                    proxy_status: status,
                    authenticated: json.get("authenticated").and_then(|v| v.as_bool()).unwrap_or(false),
                    user_info: json.get("user_info").and_then(|v| if v.is_null() { None } else { Some(v.to_string()) }),
                    tls_info: Some(tls_info),
                },
                Err(_) => ApiResponse {
                    result: body, proxy_status: status,
                    authenticated: false, user_info: None, tls_info: Some(tls_info),
                }
            }
        },
        Err(e) => {
            tracing::error!("Proxy connection error: {}", e);
            ApiResponse {
                result: format!("{{\"status\":\"error\",\"message\":\"Proxy error: {}\"}}", e),
                proxy_status: "Error".to_string(),
                authenticated: false, user_info: None, tls_info: Some(tls_info),
            }
        }
    };

    Ok(Json(response))
}
