use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Authentication error: {0}")] Authentication(String),
    #[error("WebAuthn error: {0}")] WebAuthn(#[from] webauthn_rs::prelude::WebauthnError),
    #[error("JWT error: {0}")] Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("HTTP client error: {0}")] HttpClient(#[from] reqwest::Error),
    #[error("Internal server error: {0}")] Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Determine status code and error message based on error type
        let (status, error_message, error_code) = match self {
            AppError::Authentication(msg) => {
                (StatusCode::UNAUTHORIZED, msg, "AUTH_ERROR")
            },
            AppError::WebAuthn(e) => {
                tracing::error!("WebAuthn error: {}", e);
                (StatusCode::BAD_REQUEST, e.to_string(), "WEBAUTHN_ERROR")
            },
            AppError::Jwt(e) => {
                tracing::error!("JWT error: {}", e);
                (StatusCode::UNAUTHORIZED, e.to_string(), "JWT_ERROR")
            },
            AppError::HttpClient(e) => {
                tracing::error!("HTTP client error: {}", e);
                (StatusCode::BAD_GATEWAY, "Unable to communicate with backend service".to_string(), "HTTP_CLIENT_ERROR")
            },
            AppError::Internal(e) => {
                tracing::error!("Internal server error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string(), "INTERNAL_ERROR")
            },
        };

        // Build response
        let headers = [
            ("Content-Type", "application/json"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("X-XSS-Protection", "1; mode=block"),
        ];

        let mut builder = Response::builder().status(status);
        for (key, value) in headers {
            builder = builder.header(key, value);
        }

        // Add HSTS header in production
        if std::env::var("ENVIRONMENT").unwrap_or_default() == "production" {
            builder = builder.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }

        // Build error response body
        let body = Json(json!({
            "status": "error",
            "code": error_code,
            "message": error_message,
            "timestamp": chrono::Utc::now().to_rfc3339()
        }));

        // Build final response
        builder.body(body.into_response().into_body())
            .unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                    "status": "error",
                    "code": "RESPONSE_BUILD_ERROR",
                    "message": "Failed to build error response"
                }))).into_response()
            })
    }
}

pub type AppResult<T> = Result<T, AppError>;
