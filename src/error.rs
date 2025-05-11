use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::prelude::WebauthnError),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("TLS configuration error: {0}")]
    #[allow(dead_code)]
    TlsConfig(String),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("PEM error: {0}")]
    #[allow(dead_code)]
    Pem(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, error_code) = match self {
            AppError::Authentication(msg) => (
                StatusCode::UNAUTHORIZED,
                msg,
                "AUTH_ERROR"
            ),
            AppError::WebAuthn(e) => {
                tracing::error!("WebAuthn error: {}", e);
                (
                    StatusCode::BAD_REQUEST,
                    e.to_string(),
                    "WEBAUTHN_ERROR"
                )
            },
            AppError::Jwt(e) => {
                tracing::error!("JWT error: {}", e);
                (
                    StatusCode::UNAUTHORIZED,
                    e.to_string(),
                    "JWT_ERROR"
                )
            },
            AppError::TlsConfig(e) => {
                tracing::error!("TLS configuration error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "TLS_CONFIG_ERROR"
                )
            },
            AppError::HttpClient(e) => {
                tracing::error!("HTTP client error: {}", e);
                (
                    StatusCode::BAD_GATEWAY,
                    "Failed to communicate with backend service".to_string(),
                    "HTTP_CLIENT_ERROR"
                )
            },
            AppError::Internal(e) => {
                tracing::error!("Internal server error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                    "INTERNAL_ERROR"
                )
            },
            AppError::Pem(e) => {
                tracing::error!("PEM error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Certificate error".to_string(),
                    "PEM_ERROR"
                )
            },
        };

        // Add security headers
        let mut response = Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .header("X-Content-Type-Options", "nosniff")
            .header("X-Frame-Options", "DENY")
            .header("X-XSS-Protection", "1; mode=block");

        // If in production environment, add HSTS header
        if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
            response = response.header(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains"
            );
        }

        // Build error response body
        let body = Json(json!({
            "status": "error",
            "code": error_code,
            "message": error_message,
            "timestamp": chrono::Utc::now().to_rfc3339()
        }));

        // Build final response
        match response.body(body.into_response().into_body()) {
            Ok(resp) => resp,
            Err(_) => {
                // If response building fails, return a simple error response
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "status": "error",
                        "code": "RESPONSE_BUILD_ERROR",
                        "message": "Failed to build error response"
                    }))
                ).into_response()
            }
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
