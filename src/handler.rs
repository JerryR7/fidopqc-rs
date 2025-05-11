use std::env;
use axum::Json;
use serde_json::Value;

use crate::error::AppResult;
use crate::tls::get_tls_info;
use crate::http_client::send_request;
use crate::api_response::{ApiResponse, ApiResponseBuilder, is_authenticated, ensure_auth_consistency, determine_response_status};

/// 處理 API 請求
pub async fn handle_request(headers: axum::http::HeaderMap) -> AppResult<Json<ApiResponse>> {
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
        .unwrap_or_else(|e| serde_json::json!({
            "error": format!("TLS info unavailable: {}", e)
        }));

    // 發送請求
    let auth_ref = if auth.is_empty() { None } else { Some(auth.as_str()) };
    let response = match send_request(host, port, "/api", auth_ref) {
        Ok(http_response) => {
            // 解析 JSON 響應
            match serde_json::from_str::<Value>(&http_response.body) {
                Ok(backend_json) => {
                    // 檢查認證狀態
                    let auth_status = is_authenticated(&auth);
                    
                    // 確保後端響應中的認證狀態與請求的認證狀態一致
                    let modified_backend_json = ensure_auth_consistency(&backend_json, auth_status);
                    
                    // 確定響應狀態
                    let response_status = determine_response_status(&backend_json, http_response.status.code);
                    
                    // 構建 API 響應
                    ApiResponseBuilder::new()
                        .status(response_status)
                        .backend_response(modified_backend_json)
                        .proxy_info(http_response.status.to_json())
                        .tls_info(tls_info)
                        .build()
                },
                Err(_) => {
                    // 如果無法解析為 JSON，則創建一個包含原始響應的 JSON 對象
                    let fallback_json = serde_json::json!({
                        "raw_response": http_response.body,
                        "parse_error": "Could not parse response as JSON"
                    });
                    
                    // 構建 API 響應
                    ApiResponseBuilder::new()
                        .status(if http_response.status.is_error() { "error" } else { "warning" })
                        .backend_response(fallback_json)
                        .proxy_info(http_response.status.to_json())
                        .tls_info(tls_info)
                        .build()
                }
            }
        },
        Err(e) => {
            tracing::error!("Proxy connection error: {}", e);
            
            // 構建錯誤響應
            ApiResponseBuilder::new()
                .status("error")
                .backend_response(serde_json::json!({
                    "message": format!("Proxy error: {}", e)
                }))
                .proxy_info(serde_json::json!({
                    "status_line": "Error",
                    "error": e.to_string()
                }))
                .tls_info(tls_info)
                .build()
        }
    };

    Ok(Json(response))
}
