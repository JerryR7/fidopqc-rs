use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use crate::error::{AppError, AppResult};

// 從環境變量獲取 JWT 密鑰
static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    std::env::var("JWT_SECRET")
        .expect("Missing JWT_SECRET environment variable. Please set it before starting the application.")
});

// 從環境變量獲取發行者和受眾
static JWT_ISSUER: Lazy<String> = Lazy::new(|| {
    std::env::var("JWT_ISSUER").unwrap_or_else(|_| "passkeymesh-gateway".to_string())
});

static JWT_AUDIENCE: Lazy<String> = Lazy::new(|| {
    std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "backend-service".to_string())
});

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // 用戶 ID
    pub name: String,     // 用戶名稱
    pub exp: usize,       // 過期時間
    pub iat: usize,       // 簽發時間
    pub iss: String,      // 發行者
    pub aud: String,      // 受眾
}

/// 為用戶簽發 JWT 令牌
pub fn issue_jwt(user_id: &str, username: &str) -> AppResult<String> {
    let now = Utc::now();
    let expires_at = now + Duration::hours(24);

    let claims = Claims {
        sub: user_id.to_string(),
        name: username.to_string(),
        exp: expires_at.timestamp() as usize,
        iat: now.timestamp() as usize,
        iss: JWT_ISSUER.to_string(),
        aud: JWT_AUDIENCE.to_string(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    ).map_err(|e| AppError::Jwt(e))?;

    Ok(token)
}


