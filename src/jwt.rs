use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use crate::error::{AppError, AppResult};

// JWT environment variables
static JWT_SECRET: Lazy<String> = Lazy::new(|| {
    std::env::var("JWT_SECRET").expect("Missing JWT_SECRET environment variable")
});

static JWT_ISSUER: Lazy<String> = Lazy::new(|| {
    std::env::var("JWT_ISSUER").unwrap_or_else(|_| "passkeymesh-gateway".to_string())
});

// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // User ID
    pub name: String, // Username
    pub exp: usize,   // Expiration time
    pub iat: usize,   // Issued at
    pub iss: String,  // Issuer
    pub aud: Vec<String>,  // Multiple Audiences
}

// Issue JWT token for user
pub fn issue_jwt(user_id: &str, username: &str) -> AppResult<String> {
    let now = Utc::now();

    // Define multiple audiences for the JWT
    let audiences = vec![
        "backend-service".to_string(),
        "user-service".to_string(),
        "payment-service".to_string(),
    ];

    encode(
        &Header::default(),
        &Claims {
            sub: user_id.to_string(),
            name: username.to_string(),
            exp: (now + Duration::hours(24)).timestamp() as usize,
            iat: now.timestamp() as usize,
            iss: JWT_ISSUER.to_string(),
            aud: audiences,
        },
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    ).map_err(AppError::Jwt)
}
