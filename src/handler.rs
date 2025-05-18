use std::env;
use axum::{Json, extract::Path};
use serde_json::Value;

use crate::error::AppResult;
use crate::tls::get_tls_info;
use crate::http_client::send_request;
use crate::api_response::{ApiResponse, ApiResponseBuilder, is_authenticated, ensure_auth_consistency, determine_response_status};

// Service type enum
#[derive(Debug, Clone, Copy)]
pub enum ServiceType {
    Log,
    User,
    Payment,
}

impl ServiceType {
    // Get service name
    pub fn name(&self) -> &'static str {
        match self {
            ServiceType::Log => "log-service",
            ServiceType::User => "user-service",
            ServiceType::Payment => "payment-service",
        }
    }

    // Get environment variable name for service URL
    pub fn env_var(&self) -> &'static str {
        match self {
            ServiceType::Log => "QUANTUM_SAFE_PROXY_URL",
            ServiceType::User => "USER_SERVICE_URL",
            ServiceType::Payment => "PAYMENT_SERVICE_URL",
        }
    }

    // Get default URL for service
    pub fn default_url(&self) -> &'static str {
        match self {
            ServiceType::Log => "https://quantum-safe-proxy:8443",
            ServiceType::User => "https://user-quantum-safe-proxy:8443",
            ServiceType::Payment => "https://payment-quantum-safe-proxy:8443",
        }
    }

    // Get JWT audience for service
    pub fn audience(&self) -> &'static str {
        match self {
            ServiceType::Log => "backend-service",
            ServiceType::User => "user-service",
            ServiceType::Payment => "payment-service",
        }
    }
}

// Handle API request to default service (log service)
pub async fn handle_request(headers: axum::http::HeaderMap) -> AppResult<Json<ApiResponse>> {
    handle_service_request(ServiceType::Log, headers).await
}

// Handle API request to user service
pub async fn handle_user_request(headers: axum::http::HeaderMap) -> AppResult<Json<ApiResponse>> {
    handle_service_request(ServiceType::User, headers).await
}

// Handle API request to payment service
pub async fn handle_payment_request(headers: axum::http::HeaderMap) -> AppResult<Json<ApiResponse>> {
    handle_service_request(ServiceType::Payment, headers).await
}

// Handle API request to specific service by path parameter
pub async fn handle_service_by_path(
    Path(service_name): Path<String>,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<ApiResponse>> {
    let service_type = match service_name.as_str() {
        "logs" | "log" => ServiceType::Log,
        "users" | "user" => ServiceType::User,
        "payments" | "payment" => ServiceType::Payment,
        _ => ServiceType::Log, // Default to log service
    };

    handle_service_request(service_type, headers).await
}

// Common handler for all service requests
async fn handle_service_request(
    service_type: ServiceType,
    headers: axum::http::HeaderMap,
) -> AppResult<Json<ApiResponse>> {
    // Get authorization header
    let auth = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();

    tracing::info!("Forwarding request to {} with {} auth token",
                  service_type.name(),
                  if auth.is_empty() { "no" } else { "a" });

    // Parse proxy URL
    let proxy_url = env::var(service_type.env_var())
        .unwrap_or_else(|_| service_type.default_url().to_string());

    let url_parts: Vec<&str> = proxy_url.trim_start_matches("https://").split(':').collect();
    let host = url_parts.get(0).copied().unwrap_or("localhost");
    let port = url_parts.get(1).and_then(|p| p.parse::<u16>().ok()).unwrap_or(443);

    // Get TLS info
    let tls_info = get_tls_info(host, port)
        .unwrap_or_else(|e| serde_json::json!({
            "error": format!("TLS info unavailable: {}", e),
            "service": service_type.name()
        }));

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
                            "parse_error": "Failed to parse response as JSON",
                            "service": service_type.name()
                        }))
                        .proxy_info(http_response.status.to_json())
                        .tls_info(tls_info)
                        .build()
                }
            }
        },
        Err(e) => {
            tracing::error!("Proxy connection error for {}: {}", service_type.name(), e);

            // Build error response
            ApiResponseBuilder::new()
                .status("error")
                .backend_response(serde_json::json!({
                    "message": format!("Proxy error: {}", e),
                    "service": service_type.name()
                }))
                .proxy_info(serde_json::json!({
                    "status_line": "Error",
                    "error": e.to_string(),
                    "service": service_type.name()
                }))
                .tls_info(tls_info)
                .build()
        }
    };

    Ok(Json(response))
}
