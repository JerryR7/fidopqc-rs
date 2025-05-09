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
        let (status, error_message) = match self {
            AppError::Authentication(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::WebAuthn(e) => (StatusCode::BAD_REQUEST, e.to_string()),
            AppError::Jwt(e) => (StatusCode::UNAUTHORIZED, e.to_string()),
            AppError::TlsConfig(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            AppError::HttpClient(e) => (StatusCode::BAD_GATEWAY, e.to_string()),
            AppError::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
            AppError::Pem(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
        };

        let body = Json(json!({
            "error": error_message
        }));

        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
