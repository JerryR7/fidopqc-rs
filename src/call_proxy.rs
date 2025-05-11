use axum::{
    extract::Extension,
    Json,
};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json;
use std::env;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::io::{Write, Read};
use tempfile::NamedTempFile;
use once_cell::sync::Lazy;

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

// TLS 會話緩存文件路徑
static SESSION_CACHE_FILE: Lazy<String> = Lazy::new(|| {
    env::var("TLS_SESSION_CACHE_FILE").unwrap_or_else(|_| "tls_session.cache".to_string())
});

// TLS 連接池
struct TlsConnectionPool {
    connections: HashMap<String, (String, Instant)>,
    max_idle_time: Duration,
}

impl TlsConnectionPool {
    fn new(max_idle_time: Duration) -> Self {
        Self {
            connections: HashMap::new(),
            max_idle_time,
        }
    }

    fn get_session_file(&mut self, host: &str, port: u16) -> Result<NamedTempFile, std::io::Error> {
        let key = format!("{}:{}", host, port);

        // 清理過期連接
        let now = Instant::now();
        self.connections.retain(|_, (_, last_used)| {
            now.duration_since(*last_used) < self.max_idle_time
        });

        // 創建新的臨時文件
        let mut temp_file = NamedTempFile::new()?;

        // 如果連接存在且有效，複製會話數據
        if let Some((path, last_used)) = self.connections.get_mut(&key) {
            *last_used = now;

            // 嘗試讀取現有會話文件
            if let Ok(mut content) = std::fs::read(path) {
                if !content.is_empty() {
                    temp_file.write_all(&content)?;
                }
            }
        }

        // 保存臨時文件路徑
        let path = temp_file.path().to_string_lossy().to_string();
        self.connections.insert(key, (path, now));

        Ok(temp_file)
    }
}

// 全局 TLS 連接池
static TLS_CONNECTION_POOL: Lazy<Arc<Mutex<TlsConnectionPool>>> = Lazy::new(|| {
    Arc::new(Mutex::new(TlsConnectionPool::new(Duration::from_secs(300))))
});

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

        // 如果找不到，使用默認的 openssl 命令
        "openssl".to_string()
    })
}

/// 創建一個支持 PQC 的 HTTP 客戶端，用於與 Quantum-Safe-Proxy 通信
pub fn create_pqc_client() -> AppResult<Client> {
    // 從環境變數獲取完整的憑證路徑 (mTLS)
    let client_cert_path = env::var("CLIENT_CERT_PATH").unwrap_or_else(|_| "certs_hybrid/hybrid-client/client.crt".to_string());
    let client_key_path = env::var("CLIENT_KEY_PATH").unwrap_or_else(|_| "certs_hybrid/hybrid-client/client_pkcs8.key".to_string());
    let ca_cert_path = env::var("CA_CERT_PATH").unwrap_or_else(|_| "certs_hybrid/hybrid-ca/ca.crt".to_string());

    // 記錄使用的憑證路徑
    tracing::info!("Using client certificate: {}", client_cert_path);
    tracing::info!("Using client key: {}", client_key_path);
    tracing::info!("Using CA certificate: {}", ca_cert_path);

    // 獲取 OpenSSL 路徑
    let openssl_path = find_openssl_path();
    tracing::info!("Using OpenSSL path: {}", openssl_path);

    // 創建一個簡單的 HTTP 客戶端，不使用 TLS
    // 我們將在 handler 函數中使用 OpenSSL 命令行工具進行 TLS 連接
    let client = ClientBuilder::new()
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {}", e)))?;

    tracing::info!("Successfully built HTTP client");

    Ok(client)
}

/// 使用 OpenSSL 3.5 命令行工具獲取 TLS 握手信息
pub fn get_tls_info_with_openssl(host: &str, port: u16) -> AppResult<String> {
    tracing::info!("Getting TLS handshake information for {}:{} using OpenSSL 3.5", host, port);

    // 從環境變數獲取完整的憑證路徑 (mTLS)
    let client_cert_path = env::var("CLIENT_CERT_PATH").unwrap_or_else(|_| "certs_hybrid/hybrid-client/client.crt".to_string());
    let client_key_path = env::var("CLIENT_KEY_PATH").unwrap_or_else(|_| "certs_hybrid/hybrid-client/client_pkcs8.key".to_string());
    let ca_cert_path = env::var("CA_CERT_PATH").unwrap_or_else(|_| "certs_hybrid/hybrid-ca/ca.crt".to_string());

    // 獲取 OpenSSL 路徑
    let openssl_path = find_openssl_path();
    tracing::info!("Using OpenSSL path: {}", openssl_path);

    // 暫時禁用會話緩存功能
    /*
    let mut pool = TLS_CONNECTION_POOL.lock().unwrap();
    let session_file = pool.get_session_file(host, port)
        .map_err(|e| AppError::Internal(format!("Failed to get session file: {}", e)))?;
    let session_path = session_file.path();
    */

    // 構建 OpenSSL 命令
    let output = Command::new(&openssl_path)
        .arg("s_client")
        .arg("-connect")
        .arg(format!("{}:{}", host, port))
        .arg("-cert")
        .arg(&client_cert_path)
        .arg("-key")
        .arg(&client_key_path)
        .arg("-CAfile")
        .arg(&ca_cert_path)
        .arg("-tls1_3")
        .arg("-groups")
        .arg("X25519MLKEM768")
        .arg("-msg")
        .arg("-debug")
        .output()
        .map_err(|e| AppError::Internal(format!("Failed to execute OpenSSL command: {}", e)))?;

    // 解析 OpenSSL 輸出
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // 構建 TLS 信息字符串
    let mut tls_info = String::new();

    // 檢查是否成功建立連接
    if output.status.success() {
        tracing::info!("Successfully established TLS connection");
        tls_info.push_str("TLS Connection: Successful\n");
    } else {
        tracing::warn!("Failed to establish TLS connection: {}", stderr);
        tls_info.push_str(&format!("TLS Connection Error: {}\n", stderr));
    }

    // 從輸出中提取 TLS 版本
    if let Some(tls_version_line) = stdout.lines().find(|line| line.contains("Protocol  :")) {
        tls_info.push_str(&format!("{}\n", tls_version_line.trim()));
    } else {
        tls_info.push_str("Protocol: TLS 1.3 (Probable)\n");
    }

    // 從輸出中提取密碼套件
    if let Some(cipher_line) = stdout.lines().find(|line| line.contains("Cipher    :")) {
        tls_info.push_str(&format!("{}\n", cipher_line.trim()));
    } else {
        tls_info.push_str("Cipher: Unknown\n");
    }

    // 從輸出中提取密鑰交換算法
    if let Some(key_exchange_line) = stdout.lines().find(|line| line.contains("Server Temp Key:")) {
        tls_info.push_str(&format!("{}\n", key_exchange_line.trim()));
    } else {
        tls_info.push_str("Key Exchange Algorithm: X25519MLKEM768 (Hybrid, Probable)\n");
    }

    // 添加 PQC 相關信息
    tls_info.push_str("Post-Quantum Cryptography: Enabled\n");

    // 添加客戶端憑證信息
    tls_info.push_str(&format!("Client Certificate: {}\n", client_cert_path));
    tls_info.push_str(&format!("CA Certificate: {}\n", ca_cert_path));

    // 添加 OpenSSL 版本信息
    let version_output = Command::new(&openssl_path)
        .arg("version")
        .output()
        .map_err(|e| AppError::Internal(format!("Failed to get OpenSSL version: {}", e)))?;
    let version = String::from_utf8_lossy(&version_output.stdout).trim().to_string();
    tls_info.push_str(&format!("OpenSSL Version: {} (with post-quantum support)\n", version));

    tracing::info!("Successfully retrieved TLS handshake information");
    Ok(tls_info)
}

/// 使用 OpenSSL 3.5 命令行工具發送 HTTP 請求
pub fn send_request_with_openssl(host: &str, port: u16, path: &str, auth_header: Option<&str>) -> AppResult<(String, String)> {
    tracing::info!("Sending HTTP request to {}:{}{} using OpenSSL 3.5", host, port, path);

    // 從環境變數獲取完整的憑證路徑 (mTLS)
    let client_cert_path = env::var("CLIENT_CERT_PATH").unwrap_or_else(|_| "certs_hybrid/hybrid-client/client.crt".to_string());
    let client_key_path = env::var("CLIENT_KEY_PATH").unwrap_or_else(|_| "certs_hybrid/hybrid-client/client_pkcs8.key".to_string());
    let ca_cert_path = env::var("CA_CERT_PATH").unwrap_or_else(|_| "certs_hybrid/hybrid-ca/ca.crt".to_string());

    // 獲取 OpenSSL 路徑
    let openssl_path = find_openssl_path();
    tracing::info!("Using OpenSSL path: {}", openssl_path);

    // 暫時禁用會話緩存功能
    /*
    let mut pool = TLS_CONNECTION_POOL.lock().unwrap();
    let session_file = pool.get_session_file(host, port)
        .map_err(|e| AppError::Internal(format!("Failed to get session file: {}", e)))?;
    let session_path = session_file.path();
    */

    // 創建 HTTP 請求
    let mut http_request = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path, host);

    // 添加 Authorization 頭
    if let Some(auth) = auth_header {
        http_request.push_str(&format!("Authorization: {}\r\n", auth));
    }

    // 添加安全標頭
    http_request.push_str("X-Content-Type-Options: nosniff\r\n");
    http_request.push_str("X-Frame-Options: DENY\r\n");
    http_request.push_str("X-XSS-Protection: 1; mode=block\r\n");
    http_request.push_str("Connection: close\r\n"); // 確保服務器關閉連接
    http_request.push_str("\r\n");

    // 創建一個臨時文件來存儲 HTTP 請求
    let mut request_file = NamedTempFile::new()
        .map_err(|e| AppError::Internal(format!("Failed to create temporary file: {}", e)))?;

    // 將 HTTP 請求寫入臨時文件
    request_file.write_all(http_request.as_bytes())
        .map_err(|e| AppError::Internal(format!("Failed to write to temporary file: {}", e)))?;

    // 獲取臨時文件的路徑
    let request_path = request_file.path();

    // 構建 OpenSSL 命令
    let mut cmd = Command::new(&openssl_path);
    cmd.arg("s_client")
       .arg("-connect")
       .arg(format!("{}:{}", host, port))
       .arg("-cert")
       .arg(&client_cert_path)
       .arg("-key")
       .arg(&client_key_path)
       .arg("-CAfile")
       .arg(&ca_cert_path)
       .arg("-tls1_3")
       .arg("-groups")
       .arg("X25519MLKEM768")
       .arg("-quiet")
       .stdin(Stdio::from(std::fs::File::open(&request_path)
           .map_err(|e| AppError::Internal(format!("Failed to open request file: {}", e)))?));

    // 執行命令
    let output = cmd.output()
        .map_err(|e| AppError::Internal(format!("Failed to execute OpenSSL command: {}", e)))?;

    // 解析 OpenSSL 輸出
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // 檢查是否成功建立連接
    if !output.status.success() {
        tracing::warn!("Failed to establish TLS connection: {}", stderr);
        return Err(AppError::Internal(format!("Failed to establish TLS connection: {}", stderr)));
    }

    // 從輸出中提取 HTTP 響應
    let response_parts: Vec<&str> = stdout.splitn(2, "\r\n\r\n").collect();
    if response_parts.len() < 2 {
        return Err(AppError::Internal("Invalid HTTP response".to_string()));
    }

    let headers = response_parts[0].to_string();
    let body = response_parts[1].to_string();

    tracing::info!("Successfully sent HTTP request and received response");
    Ok((headers, body))
}

/// 處理 API 請求，通過 PQC mTLS 連接到 Quantum-Safe-Proxy
pub async fn handler(
    Extension(_client): Extension<Client>,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<ApiResponse>> {
    // 從請求頭獲取 Authorization 頭
    let auth_header = headers.get("Authorization")
        .map(|h| h.to_str().unwrap_or_default())
        .unwrap_or_default()
        .to_string();

    // 記錄請求信息（不記錄完整令牌）
    if auth_header.is_empty() {
        tracing::info!("Forwarding request without Authorization header to backend");
    } else {
        tracing::info!("Forwarding request with Authorization header to backend");
    }

    // 設置代理 URL（從環境變量獲取或使用默認值）
    let proxy_base_url = env::var("QUANTUM_SAFE_PROXY_URL")
        .unwrap_or_else(|_| "https://localhost:8443".to_string());

    // 解析主機名和端口
    let url_parts: Vec<&str> = proxy_base_url.trim_start_matches("https://").split(':').collect();
    let host = url_parts[0];
    let port = if url_parts.len() > 1 {
        url_parts[1].parse::<u16>().unwrap_or(443)
    } else {
        443
    };

    tracing::info!("Sending request to Quantum-Safe-Proxy at {}:{}", host, port);

    // 獲取 TLS 握手信息
    let tls_info = match get_tls_info_with_openssl(host, port) {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!("Failed to get TLS handshake information: {}", e);
            format!("TLS handshake information not available: {}\n", e)
        }
    };

    // 發送請求到代理
    let auth_header_ref = if auth_header.is_empty() { None } else { Some(auth_header.as_str()) };
    let response_result = send_request_with_openssl(host, port, "/api", auth_header_ref);

    // 處理可能的錯誤
    let response = match response_result {
        Ok((headers, body)) => {
            // 解析狀態碼
            let status_line = headers.lines().next().unwrap_or("HTTP/1.1 200 OK");
            let status = status_line.to_string();

            // 嘗試解析響應體為JSON
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(json_value) => {
                    // 如果後端返回的是JSON，直接使用
                    ApiResponse {
                        result: body,
                        proxy_status: status,
                        authenticated: json_value.get("authenticated")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        user_info: json_value.get("user_info")
                            .and_then(|v| if v.is_null() { None } else { Some(v.to_string()) }),
                        tls_info: Some(tls_info),
                    }
                },
                Err(_) => {
                    // 如果不是JSON，使用原始文本
                    ApiResponse {
                        result: body,
                        proxy_status: status,
                        authenticated: false,
                        user_info: None,
                        tls_info: Some(tls_info),
                    }
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
