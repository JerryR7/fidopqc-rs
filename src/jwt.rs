use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use crate::error::AppResult;

// 在實際應用中，這個密鑰應該從環境變量或安全存儲中獲取
static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| "your-jwt-secret-key-for-development-only".to_string())
});

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // 用戶 ID
    pub name: String,     // 用戶名稱
    pub exp: usize,       // 過期時間
    pub iat: usize,       // 簽發時間
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
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )?;

    Ok(token)
}


