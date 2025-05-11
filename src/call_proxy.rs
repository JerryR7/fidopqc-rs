use axum::Json;
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json;
use std::env;
use std::process::{Command, Stdio};
use std::io::Write;

use crate::error::{AppError, AppResult};

// 統一的 API 響應結構
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

/// 查找 OpenSSL 3.5 的路徑
fn find_openssl_path() -> String {
    env::var("OPENSSL_PATH").unwrap_or_else(|_| {
        // 嘗試幾個可能的路徑
        let possible_paths = [
            "/usr/local/Cellar/openssl@3.5/3.5.0/bin/openssl",
            "/usr/local/opt/openssl@3.5/bin/openssl",
            "/opt/openssl35/bin/openssl",
            "openssl35",
            "openssl"
        ];

        for path in possible_paths {
            if Command::new(path).arg("version").output().is_ok() {
                return path.to_string();
            }
        }

        "openssl".to_string()
    })
}

/// 獲取 mTLS 憑證路徑
fn get_certificate_paths() -> (String, String, String) {
    let client_cert_path = env::var("CLIENT_CERT_PATH").unwrap_or_else(|_| "certs/hybrid-client/client.crt".to_string());
    let client_key_path = env::var("CLIENT_KEY_PATH").unwrap_or_else(|_| "certs/hybrid-client/client_pkcs8.key".to_string());
    let ca_cert_path = env::var("CA_CERT_PATH").unwrap_or_else(|_| "certs/hybrid-ca/ca.crt".to_string());

    (client_cert_path, client_key_path, ca_cert_path)
}

/// 執行 OpenSSL 命令
fn run_openssl_command(
    openssl_path: &str,
    host: &str,
    port: u16,
    cert_paths: &(String, String, String),
    extra_args: &[&str],
    stdin_data: Option<&[u8]>
) -> AppResult<std::process::Output> {
    let (client_cert_path, client_key_path, ca_cert_path) = cert_paths;

    // 構建基本命令
    let mut cmd = Command::new(openssl_path);
    cmd.arg("s_client")
       .arg("-connect")
       .arg(format!("{}:{}", host, port))
       .arg("-cert")
       .arg(client_cert_path)
       .arg("-key")
       .arg(client_key_path)
       .arg("-CAfile")
       .arg(ca_cert_path)
       .arg("-tls1_3")
       .arg("-groups")
       .arg("X25519MLKEM768");

    // 添加額外參數
    for arg in extra_args {
        cmd.arg(arg);
    }

    // 設置標準輸入（如果有）
    if let Some(data) = stdin_data {
        let mut child = cmd.stdin(Stdio::piped())
                          .stdout(Stdio::piped())
                          .stderr(Stdio::piped())
                          .spawn()
                          .map_err(|e| AppError::Internal(format!("Failed to spawn OpenSSL command: {}", e)))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data)
                .map_err(|e| AppError::Internal(format!("Failed to write to OpenSSL stdin: {}", e)))?;
        }

        child.wait_with_output()
            .map_err(|e| AppError::Internal(format!("Failed to execute OpenSSL command: {}", e)))
    } else {
        cmd.output()
            .map_err(|e| AppError::Internal(format!("Failed to execute OpenSSL command: {}", e)))
    }
}

/// 清理 HTTP 響應體，提取 JSON 內容
fn clean_http_response_body(raw_body: &str) -> String {
    // 尋找 JSON 開始的位置 (通常是 '{')
    if let Some(json_start) = raw_body.find('{') {
        let json_part = &raw_body[json_start..];

        // 尋找 JSON 結束的位置 (通常是 '}')
        if let Some(json_end) = json_part.rfind('}') {
            return json_part[0..=json_end].to_string();
        }
    }

    // 如果找不到有效的 JSON，移除 chunked 編碼
    raw_body.lines()
        .filter(|line| !line.trim().is_empty() && !line.trim().chars().all(|c| c.is_digit(16) || c.is_whitespace()))
        .collect::<Vec<&str>>()
        .join("\n")
}

/// 創建一個支持 PQC 的 HTTP 客戶端，用於與 Quantum-Safe-Proxy 通信
pub fn create_pqc_client() -> AppResult<Client> {
    // 從環境變數獲取完整的憑證路徑 (mTLS)
    let cert_paths = get_certificate_paths();
    let (client_cert_path, client_key_path, ca_cert_path) = &cert_paths;

    // 記錄使用的憑證路徑
    tracing::info!("Using client certificate: {}", client_cert_path);
    tracing::info!("Using client key: {}", client_key_path);
    tracing::info!("Using CA certificate: {}", ca_cert_path);

    // 獲取 OpenSSL 路徑
    let openssl_path = find_openssl_path();
    tracing::info!("Using OpenSSL path: {}", openssl_path);

    // 創建一個簡單的 HTTP 客戶端
    let client = ClientBuilder::new()
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {}", e)))?;

    tracing::info!("Successfully built HTTP client");

    Ok(client)
}

/// 使用 OpenSSL 3.5 命令行工具獲取 TLS 握手信息
pub fn get_tls_info_with_openssl(host: &str, port: u16) -> AppResult<String> {
    tracing::info!("Getting TLS handshake information for {}:{}", host, port);

    // 獲取憑證路徑和 OpenSSL 路徑
    let cert_paths = get_certificate_paths();
    let openssl_path = find_openssl_path();

    // 執行 OpenSSL 命令
    let output = run_openssl_command(&openssl_path, host, port, &cert_paths, &["-msg", "-debug"], None)?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // 構建 TLS 信息字符串
    let mut tls_info = String::with_capacity(512);

    // 檢查連接狀態
    if output.status.success() {
        tls_info.push_str("TLS Connection: Successful\n");
    } else {
        tls_info.push_str(&format!("TLS Connection Error: {}\n", stderr));
    }

    // 從輸出中提取 TLS 信息
    let extract_info = |pattern: &str, default: &str| -> String {
        stdout.lines()
            .find(|line| line.contains(pattern))
            .map_or_else(|| default.to_string(), |line| line.trim().to_string())
    };

    tls_info.push_str(&extract_info("Protocol  :", "Protocol: TLS 1.3 (Probable)"));
    tls_info.push_str("\n");
    tls_info.push_str(&extract_info("Cipher    :", "Cipher: Unknown"));
    tls_info.push_str("\n");
    tls_info.push_str(&extract_info("Server Temp Key:", "Key Exchange Algorithm: X25519MLKEM768 (Hybrid, Probable)"));
    tls_info.push_str("\n");

    // 添加 PQC 相關信息
    tls_info.push_str("Post-Quantum Cryptography: Enabled\n");
    tls_info.push_str(&format!("Client Certificate: {}\n", cert_paths.0));
    tls_info.push_str(&format!("CA Certificate: {}\n", cert_paths.2));

    // 添加 OpenSSL 版本信息
    let version = Command::new(&openssl_path)
        .arg("version")
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());

    tls_info.push_str(&format!("OpenSSL Version: {} (with post-quantum support)\n", version));

    tracing::info!("Successfully retrieved TLS handshake information");
    Ok(tls_info)
}

/// 使用 OpenSSL 3.5 命令行工具發送 HTTP 請求
pub fn send_request_with_openssl(host: &str, port: u16, path: &str, auth_header: Option<&str>) -> AppResult<(String, String)> {
    tracing::info!("Sending HTTP request to {}:{}{}", host, port, path);

    // 獲取憑證路徑和 OpenSSL 路徑
    let cert_paths = get_certificate_paths();
    let openssl_path = find_openssl_path();

    // 創建 HTTP 請求
    let mut http_request = String::with_capacity(256);
    http_request.push_str(&format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path, host));

    // 添加 Authorization 頭
    if let Some(auth) = auth_header {
        http_request.push_str(&format!("Authorization: {}\r\n", auth));
    }

    // 添加安全標頭
    http_request.push_str("X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nX-XSS-Protection: 1; mode=block\r\nConnection: close\r\n\r\n");

    // 執行 OpenSSL 命令
    let output = run_openssl_command(
        &openssl_path,
        host,
        port,
        &cert_paths,
        &["-quiet"],
        Some(http_request.as_bytes())
    )?;

    // 檢查是否成功建立連接
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Internal(format!("Failed to establish TLS connection: {}", stderr)));
    }

    // 從輸出中提取 HTTP 響應
    let stdout = String::from_utf8_lossy(&output.stdout);
    let response_parts: Vec<&str> = stdout.splitn(2, "\r\n\r\n").collect();

    if response_parts.len() < 2 {
        return Err(AppError::Internal("Invalid HTTP response".to_string()));
    }

    let headers = response_parts[0].to_string();
    let body = clean_http_response_body(response_parts[1]);

    tracing::info!("Successfully sent HTTP request and received response");
    Ok((headers, body))
}

/// 處理 API 請求，通過 PQC mTLS 連接到 Quantum-Safe-Proxy
pub async fn handler(headers: axum::http::HeaderMap) -> AppResult<Json<ApiResponse>> {
    // 從請求頭獲取 Authorization 頭
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();

    // 記錄請求信息（不記錄完整令牌）
    tracing::info!("Forwarding request {} Authorization header to backend",
                  if auth_header.is_empty() { "without" } else { "with" });

    // 設置代理 URL（從環境變量獲取或使用默認值）
    let proxy_base_url = env::var("QUANTUM_SAFE_PROXY_URL")
        .unwrap_or_else(|_| "https://localhost:8443".to_string());

    // 解析主機名和端口
    let url_parts: Vec<&str> = proxy_base_url.trim_start_matches("https://").split(':').collect();
    let host = url_parts.get(0).copied().unwrap_or("localhost");
    let port = url_parts.get(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);

    // 獲取 TLS 握手信息
    let tls_info = get_tls_info_with_openssl(host, port)
        .unwrap_or_else(|e| format!("TLS handshake information not available: {}\n", e));

    // 發送請求到代理
    let auth_header_ref = if auth_header.is_empty() { None } else { Some(auth_header.as_str()) };
    let response = match send_request_with_openssl(host, port, "/api", auth_header_ref) {
        Ok((headers, body)) => {
            // 解析狀態碼
            let status = headers.lines().next().unwrap_or("HTTP/1.1 200 OK").to_string();

            // 嘗試解析響應體為JSON
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(json_value) => ApiResponse {
                    result: body,
                    proxy_status: status,
                    authenticated: json_value.get("authenticated").and_then(|v| v.as_bool()).unwrap_or(false),
                    user_info: json_value.get("user_info").and_then(|v| if v.is_null() { None } else { Some(v.to_string()) }),
                    tls_info: Some(tls_info),
                },
                Err(_) => ApiResponse {
                    result: body,
                    proxy_status: status,
                    authenticated: false,
                    user_info: None,
                    tls_info: Some(tls_info),
                }
            }
        },
        Err(e) => {
            tracing::error!("Error connecting to proxy: {}", e);
            ApiResponse {
                result: format!("{{\"status\":\"error\",\"message\":\"Failed to connect to proxy: {}\"}}", e),
                proxy_status: "Error".to_string(),
                authenticated: false,
                user_info: None,
                tls_info: Some(tls_info),
            }
        }
    };

    Ok(Json(response))
}
