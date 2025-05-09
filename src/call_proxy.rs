use axum::{
    extract::Extension,
    Json,
    http::HeaderMap,
};
use reqwest::{Client, ClientBuilder, Identity};
use serde::{Deserialize, Serialize};
use serde_json;
use std::env;
use std::path::Path;
use crate::error::{AppError, AppResult};

#[derive(Debug, Deserialize)]
pub struct DemoQuery {
    // 移除 token 字段，不再從 URL 參數獲取 JWT
}

#[derive(Debug, Deserialize)]
pub struct ProxyRequest {
    // 移除 token 字段，不再從請求體獲取 JWT
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DemoResponse {
    result: String,
    proxy_status: String,
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    user_info: Option<String>,
}

/// 創建一個支持 PQC 的 HTTP 客戶端，用於與 Quantum-Safe-Proxy 通信
pub fn create_pqc_client() -> AppResult<Client> {
    // 獲取證書路徑，優先使用環境變量，否則使用默認路徑
    let certs_dir = env::var("CERTS_DIR").unwrap_or_else(|_| "certs".to_string());

    // 客戶端證書和私鑰路徑（使用混合證書）
    let hybrid_dir = Path::new(&certs_dir).join("hybrid").join("ml-dsa-87");
    let client_cert_path = hybrid_dir.join("client_hybrid.crt");
    let client_key_path = hybrid_dir.join("client_rsa.key");

    // 如果混合證書不存在，則使用傳統證書
    let (cert_path, key_path) = if client_cert_path.exists() && client_key_path.exists() {
        tracing::info!("Using PQC hybrid client certificate");
        (client_cert_path, client_key_path)
    } else {
        tracing::info!("PQC hybrid client certificate not found, using traditional certificate");
        (Path::new(&certs_dir).join("client.pqc.crt"), Path::new(&certs_dir).join("client.pqc.key"))
    };

    // CA 證書路徑 - 使用服務器 CA 鏈來驗證服務器證書
    let ca_path = Path::new(&certs_dir).join("server-ca-chain.pem");

    // 讀取客戶端證書
    let cert_data = std::fs::read(&cert_path)
        .map_err(|e| AppError::Internal(format!("Failed to read client certificate: {}", e)))?;

    // 讀取客戶端私鑰
    let key_data = std::fs::read(&key_path)
        .map_err(|e| AppError::Internal(format!("Failed to read client key: {}", e)))?;

    // 讀取 CA 證書（目前未使用，但保留以備將來使用）
    let _ca_data = std::fs::read(&ca_path)
        .map_err(|e| AppError::Internal(format!("Failed to open CA certificate: {}", e)))?;

    // 創建 HTTPS 客戶端
    let client = ClientBuilder::new()
        .use_native_tls() // 使用 native-tls 而不是 rustls
        .danger_accept_invalid_certs(true) // 接受無效證書（僅用於開發環境）
        .identity(Identity::from_pkcs8_pem(&cert_data, &key_data)
            .map_err(|e| AppError::Internal(format!("Failed to load client identity: {}", e)))?)
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {}", e)))?;

    Ok(client)
}



/// 處理演示請求，通過 PQC mTLS 連接到 Quantum-Safe-Proxy
pub async fn handler(
    Extension(client): Extension<Client>,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<DemoResponse>> {
    // 從請求頭獲取 Authorization 頭
    let auth_header = headers.get("Authorization")
        .map(|h| h.to_str().unwrap_or(""))
        .unwrap_or("")
        .to_string();

    // 記錄請求信息（不記錄完整令牌）
    if auth_header.is_empty() {
        tracing::info!("Forwarding request without Authorization header to backend");
    } else {
        tracing::info!("Forwarding request with Authorization header to backend");
    }

    // 設置代理 URL（從環境變量獲取或使用默認值）
    let proxy_url = env::var("QUANTUM_SAFE_PROXY_URL")
        .unwrap_or_else(|_| "https://localhost:8443".to_string());
    let proxy_url = format!("{}/api", proxy_url);

    tracing::info!("Sending request to Quantum-Safe-Proxy at {}", proxy_url);

    // 發送請求到代理，透明傳遞 Authorization 頭
    let mut request_builder = client.get(&proxy_url);

    // 只有當 Authorization 頭存在時才添加
    if !auth_header.is_empty() {
        request_builder = request_builder.header("Authorization", auth_header);
    }

    let response_result = request_builder.send().await;

    // 處理可能的錯誤
    let response = match response_result {
        Ok(response) => {
            // 獲取響應狀態
            let status = response.status();

            // 獲取響應體
            let body_text = response.text().await?;

            // 嘗試解析響應體為JSON
            match serde_json::from_str::<serde_json::Value>(&body_text) {
                Ok(json_value) => {
                    // 如果後端返回的是JSON，直接使用
                    DemoResponse {
                        result: body_text,
                        proxy_status: format!("{}", status),
                        authenticated: json_value.get("authenticated")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        user_info: json_value.get("user_info")
                            .and_then(|v| if v.is_null() { None } else { Some(v.to_string()) }),
                    }
                },
                Err(_) => {
                    // 如果不是JSON，使用原始文本
                    DemoResponse {
                        result: body_text,
                        proxy_status: format!("{}", status),
                        authenticated: false,
                        user_info: None,
                    }
                }
            }
        },
        Err(e) => {
            tracing::error!("Error connecting to proxy: {}", e);
            DemoResponse {
                result: format!("{{\"status\":\"error\",\"message\":\"Failed to connect to proxy: {}\"}}", e),
                proxy_status: "Error".to_string(),
                authenticated: false,
                user_info: None,
            }
        }
    };

    Ok(Json(response))
}
