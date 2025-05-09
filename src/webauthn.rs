use axum::{
    routing::post,
    Router,
    Json,
    Extension,
};

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::{Arc, Mutex}};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::{
    error::{AppError, AppResult},
    jwt,
};

// 用戶存儲
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub credentials: Vec<Passkey>,
}

type UserStore = Arc<Mutex<HashMap<String, User>>>;
// 使用字符串 ID 來存儲註冊和認證狀態
type RegistrationStateStore = Arc<Mutex<HashMap<String, PasskeyRegistration>>>;
type AuthenticationStateStore = Arc<Mutex<HashMap<String, PasskeyAuthentication>>>;

// 創建一個簡單的內存用戶存儲
fn create_user_store() -> UserStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// 創建一個簡單的內存註冊狀態存儲
fn create_registration_state_store() -> RegistrationStateStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// 創建一個簡單的內存認證狀態存儲
fn create_authentication_state_store() -> AuthenticationStateStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// 註冊請求
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
}

// 註冊響應
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub public_key: serde_json::Value,
    pub user_id: String,
}

// 完成註冊請求
#[derive(Debug, Deserialize)]
pub struct FinishRegisterRequest {
    pub username: String,
    pub credential: RegisterPublicKeyCredential,
}

// 登錄請求
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
}

// 登錄響應
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub public_key: serde_json::Value,
}

// 完成登錄請求
#[derive(Debug, Deserialize)]
pub struct FinishLoginRequest {
    pub username: String,
    pub credential: PublicKeyCredential,
}

// 完成登錄響應
#[derive(Debug, Serialize)]
pub struct FinishLoginResponse {
    pub token: String,
}

// 創建 WebAuthn 路由
pub fn routes(webauthn: Arc<Webauthn>) -> Router {
    let user_store = create_user_store();
    let registration_state_store = create_registration_state_store();
    let authentication_state_store = create_authentication_state_store();

    Router::new()
        .route("/register", post(start_register))
        .route("/verify-register", post(finish_register))
        .route("/login", post(start_login))
        .route("/verify-login", post(finish_login))
        .layer(Extension(user_store))
        .layer(Extension(registration_state_store))
        .layer(Extension(authentication_state_store))
        .layer(Extension(webauthn))
}

// 開始註冊處理函數
async fn start_register(
    Extension(webauthn): Extension<Arc<Webauthn>>,
    Extension(user_store): Extension<UserStore>,
    Extension(registration_state_store): Extension<RegistrationStateStore>,
    Json(req): Json<RegisterRequest>,
) -> AppResult<Json<RegisterResponse>> {
    let username = req.username.trim();
    if username.is_empty() {
        return Err(AppError::Authentication("Username cannot be empty".to_string()));
    }

    let user_id = Uuid::new_v4().to_string();

    // 存儲用戶
    let mut store = user_store.lock().unwrap();
    store.insert(
        user_id.clone(),
        User {
            id: user_id.clone(),
            name: username.to_string(),
            credentials: Vec::new(),
        },
    );

    // 創建註冊挑戰
    let user_unique_id = Uuid::new_v4();
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(
            user_unique_id,
            &username,
            &username,
            None,
        )
        .map_err(AppError::WebAuthn)?;

    // 存儲註冊狀態
    let mut reg_store = registration_state_store.lock().unwrap();
    reg_store.insert(user_id.clone(), reg_state);

    // 打印註冊挑戰的結構
    let ccr_json = serde_json::to_value(&ccr).unwrap();
    tracing::info!("Registration challenge: {}", serde_json::to_string_pretty(&ccr_json).unwrap());

    Ok(Json(RegisterResponse {
        public_key: ccr_json,
        user_id,
    }))
}

// 完成註冊處理函數
async fn finish_register(
    Extension(webauthn): Extension<Arc<Webauthn>>,
    Extension(user_store): Extension<UserStore>,
    Extension(registration_state_store): Extension<RegistrationStateStore>,
    Json(req): Json<FinishRegisterRequest>,
) -> AppResult<Json<serde_json::Value>> {
    let username = req.username.trim();
    if username.is_empty() {
        return Err(AppError::Authentication("Username cannot be empty".to_string()));
    }

    // 查找用戶
    let mut store = user_store.lock().unwrap();
    let user = store
        .values_mut()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    // 獲取註冊狀態
    let mut reg_store = registration_state_store.lock().unwrap();
    let reg_state = reg_store
        .remove(&user.id)
        .ok_or_else(|| AppError::Authentication("Registration session expired".to_string()))?;

    // 驗證註冊
    let credential = webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(AppError::WebAuthn)?;

    // 更新用戶憑證
    user.credentials.push(credential);

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Registration successful"
    })))
}

// 開始登錄處理函數
async fn start_login(
    Extension(webauthn): Extension<Arc<Webauthn>>,
    Extension(user_store): Extension<UserStore>,
    Extension(authentication_state_store): Extension<AuthenticationStateStore>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    let username = req.username.trim();
    if username.is_empty() {
        return Err(AppError::Authentication("Username cannot be empty".to_string()));
    }

    // 查找用戶
    let store = user_store.lock().unwrap();
    let user = store
        .values()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    if user.credentials.is_empty() {
        return Err(AppError::Authentication("No credentials found for user".to_string()));
    }

    // 創建認證挑戰
    let (auth_challenge, auth_state) = webauthn
        .start_passkey_authentication(&user.credentials)
        .map_err(AppError::WebAuthn)?;

    // 打印認證挑戰的結構
    let auth_challenge_json = serde_json::to_value(&auth_challenge).unwrap();
    tracing::info!("Authentication challenge: {}", serde_json::to_string_pretty(&auth_challenge_json).unwrap());

    // 存儲認證狀態
    let mut auth_store = authentication_state_store.lock().unwrap();
    auth_store.insert(user.id.clone(), auth_state);

    Ok(Json(LoginResponse {
        public_key: auth_challenge_json,
    }))
}

// 完成登錄處理函數
async fn finish_login(
    Extension(webauthn): Extension<Arc<Webauthn>>,
    Extension(user_store): Extension<UserStore>,
    Extension(authentication_state_store): Extension<AuthenticationStateStore>,
    Json(req): Json<FinishLoginRequest>,
) -> AppResult<Json<FinishLoginResponse>> {
    let username = req.username.trim();
    if username.is_empty() {
        return Err(AppError::Authentication("Username cannot be empty".to_string()));
    }

    // 查找用戶
    let mut store = user_store.lock().unwrap();
    let user = store
        .values_mut()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    // 獲取認證狀態
    let mut auth_store = authentication_state_store.lock().unwrap();
    let auth_state = auth_store
        .remove(&user.id)
        .ok_or_else(|| AppError::Authentication("Authentication session expired".to_string()))?;

    // 驗證登錄
    webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(AppError::WebAuthn)?;

    // 更新憑證計數器
    // 在實際應用中，我們應該更新憑證計數器
    // 但由於 AuthenticationResult 的 cred_id 是私有的，我們無法直接訪問
    // 這裡我們簡化為直接生成 JWT 令牌
    let token = jwt::issue_jwt(&user.id, &user.name)?;

    Ok(Json(FinishLoginResponse { token }))
}
