use std::env;
use axum::Json;
use serde_json::Value;

use crate::error::AppResult;
use crate::tls::get_tls_info;
use crate::http_client::send_request;
use crate::api_response::{ApiResponse, ApiResponseBuilder, is_authenticated, ensure_auth_consistency, determine_response_status};

// Handle API request
pub async fn handle_request(headers: axum::http::HeaderMap) -> AppResult<Json<ApiResponse>> {
    // Get authorization header
    let auth = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();

    tracing::info!("Forwarding request with {} auth token", if auth.is_empty() { "no" } else { "a" });

    // Parse proxy URL
    let proxy_url = env::var("QUANTUM_SAFE_PROXY_URL")
        .unwrap_or_else(|_| "https://localhost:8443".to_string());

    let url_parts: Vec<&str> = proxy_url.trim_start_matches("https://").split(':').collect();
    let host = url_parts.get(0).copied().unwrap_or("localhost");
    let port = url_parts.get(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);

    // Get TLS info
    let tls_info = get_tls_info(host, port)
        .unwrap_or_else(|e| serde_json::json!({"error": format!("TLS info unavailable: {}", e)}));

    // Send request
    let auth_ref = if auth.is_empty() { None } else { Some(auth.as_str()) };
    let response = match send_request(host, port, "/api", auth_ref) {
        Ok(http_response) => {
            // Parse JSON response
            match serde_json::from_str::<Value>(&http_response.body) {
                Ok(backend_json) => {
                    // Check authentication status and ensure consistency
                    let auth_status = is_authenticated(&auth);
                    let modified_json = ensure_auth_consistency(&backend_json, auth_status);
                    let status = determine_response_status(&backend_json, http_response.status.code);

                    // Build API response
                    ApiResponseBuilder::new()
                        .status(status)
                        .backend_response(modified_json)
                        .proxy_info(http_response.status.to_json())
                        .tls_info(tls_info)
                        .build()
                },
                Err(_) => {
                    // Cannot parse as JSON, create JSON object with raw response
                    ApiResponseBuilder::new()
                        .status(if http_response.status.is_error() { "error" } else { "warning" })
                        .backend_response(serde_json::json!({
                            "raw_response": http_response.body,
                            "parse_error": "Failed to parse response as JSON"
                        }))
                        .proxy_info(http_response.status.to_json())
                        .tls_info(tls_info)
                        .build()
                }
            }
        },
        Err(e) => {
            tracing::error!("Proxy connection error: {}", e);

            // Build error response
            ApiResponseBuilder::new()
                .status("error")
                .backend_response(serde_json::json!({"message": format!("Proxy error: {}", e)}))
                .proxy_info(serde_json::json!({"status_line": "Error", "error": e.to_string()}))
                .tls_info(tls_info)
                .build()
        }
    };

    Ok(Json(response))
}
