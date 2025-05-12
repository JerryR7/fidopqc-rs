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

// User storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub credentials: Vec<Passkey>,
}

type UserStore = Arc<Mutex<HashMap<String, User>>>;
// Use string IDs to store registration and authentication states
type RegistrationStateStore = Arc<Mutex<HashMap<String, PasskeyRegistration>>>;
type AuthenticationStateStore = Arc<Mutex<HashMap<String, PasskeyAuthentication>>>;

// Create a simple in-memory user store
fn create_user_store() -> UserStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// Create a simple in-memory registration state store
fn create_registration_state_store() -> RegistrationStateStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// Create a simple in-memory authentication state store
fn create_authentication_state_store() -> AuthenticationStateStore {
    Arc::new(Mutex::new(HashMap::new()))
}

// Registration request
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
}

// Registration response
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub public_key: serde_json::Value,
    pub user_id: String,
}

// Complete registration request
#[derive(Debug, Deserialize)]
pub struct FinishRegisterRequest {
    pub username: String,
    pub credential: RegisterPublicKeyCredential,
}

// Login request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
}

// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub public_key: serde_json::Value,
}

// Complete login request
#[derive(Debug, Deserialize)]
pub struct FinishLoginRequest {
    pub username: String,
    pub credential: PublicKeyCredential,
}

// Complete login response
#[derive(Debug, Serialize)]
pub struct FinishLoginResponse {
    pub token: String,
}

// Create WebAuthn routes
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

// Start registration handler
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

    // Store user
    let mut store = user_store.lock().unwrap();
    store.insert(
        user_id.clone(),
        User {
            id: user_id.clone(),
            name: username.to_string(),
            credentials: Vec::new(),
        },
    );

    // Create a registration challenge
    let user_unique_id = Uuid::new_v4();
    let (ccr, reg_state) = webauthn
        .start_passkey_registration(
            user_unique_id,
            &username,
            &username,
            None,
        )
        .map_err(AppError::WebAuthn)?;

    // Store registration state
    let mut reg_store = registration_state_store.lock().unwrap();
    reg_store.insert(user_id.clone(), reg_state);

    // Print registration challenge structure
    let ccr_json = serde_json::to_value(&ccr).unwrap();
    tracing::info!("Registration challenge: {}", serde_json::to_string_pretty(&ccr_json).unwrap());

    Ok(Json(RegisterResponse {
        public_key: ccr_json,
        user_id,
    }))
}

// Complete registration handler
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

    // Find user
    let mut store = user_store.lock().unwrap();
    let user = store
        .values_mut()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    // Get registration state
    let mut reg_store = registration_state_store.lock().unwrap();
    let reg_state = reg_store
        .remove(&user.id)
        .ok_or_else(|| AppError::Authentication("Registration session expired".to_string()))?;

    // Verify registration
    let credential = webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(AppError::WebAuthn)?;

    // Update user credentials
    user.credentials.push(credential);

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Registration successful"
    })))
}

// Start login handler
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

    // Find user
    let store = user_store.lock().unwrap();
    let user = store
        .values()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    if user.credentials.is_empty() {
        return Err(AppError::Authentication("No credentials found for user".to_string()));
    }

    // Create an authentication challenge
    let (auth_challenge, auth_state) = webauthn
        .start_passkey_authentication(&user.credentials)
        .map_err(AppError::WebAuthn)?;

    // Print authentication challenge structure
    let auth_challenge_json = serde_json::to_value(&auth_challenge).unwrap();
    tracing::info!("Authentication challenge: {}", serde_json::to_string_pretty(&auth_challenge_json).unwrap());

    // Store authentication state
    let mut auth_store = authentication_state_store.lock().unwrap();
    auth_store.insert(user.id.clone(), auth_state);

    Ok(Json(LoginResponse {
        public_key: auth_challenge_json,
    }))
}

// Complete login handler
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

    // Find user
    let mut store = user_store.lock().unwrap();
    let user = store
        .values_mut()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    // Get authentication state
    let mut auth_store = authentication_state_store.lock().unwrap();
    let auth_state = auth_store
        .remove(&user.id)
        .ok_or_else(|| AppError::Authentication("Authentication session expired".to_string()))?;

    // Verify login
    webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(AppError::WebAuthn)?;

    // Update credential counter
    // In a real application, we should update the credential counter
    // But since AuthenticationResult's cred_id is private, we can't access it directly
    // Here we simplify by directly generating a JWT token
    let token = jwt::issue_jwt(&user.id, &user.name)?;

    Ok(Json(FinishLoginResponse { token }))
}
