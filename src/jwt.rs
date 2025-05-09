use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, EncodingKey, DecodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use crate::error::{AppError, AppResult};

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

/// 驗證 JWT 令牌
///
/// 返回一個元組 (Claims, bool)，其中第二個元素表示是否為真實用戶（非演示用戶）
pub fn verify_jwt(token: &str) -> AppResult<(Claims, bool)> {
    // 如果是演示令牌，則返回一個默認的聲明，並標記為非真實用戶
    if token == "demo-token" {
        let now = Utc::now();
        let expires_at = now + Duration::hours(1);

        return Ok((Claims {
            sub: "guest".to_string(),
            name: "Guest".to_string(),
            exp: expires_at.timestamp() as usize,
            iat: now.timestamp() as usize,
        }, false));
    }

    // 驗證 JWT 令牌
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::default(),
    ).map_err(|e| AppError::Authentication(format!("Invalid token: {}", e)))?;

    Ok((token_data.claims, true))
}
