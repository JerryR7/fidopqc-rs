use axum::{routing::post, Router, Json, Extension};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::{Arc, Mutex}};
use uuid::Uuid;
use webauthn_rs::prelude::*;
use crate::{error::{AppError, AppResult}, jwt};

// Data models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub credentials: Vec<Passkey>,
}

#[derive(Debug, Deserialize)] pub struct RegisterRequest { pub username: String }
#[derive(Debug, Serialize)] pub struct RegisterResponse { pub public_key: serde_json::Value, pub user_id: String }
#[derive(Debug, Deserialize)] pub struct FinishRegisterRequest { pub username: String, pub credential: RegisterPublicKeyCredential }
#[derive(Debug, Deserialize)] pub struct LoginRequest { pub username: String }
#[derive(Debug, Serialize)] pub struct LoginResponse { pub public_key: serde_json::Value }
#[derive(Debug, Deserialize)] pub struct FinishLoginRequest { pub username: String, pub credential: PublicKeyCredential }
#[derive(Debug, Serialize)] pub struct FinishLoginResponse { pub token: String }

// Storage types
type UserStore = Arc<Mutex<HashMap<String, User>>>;
type RegistrationStateStore = Arc<Mutex<HashMap<String, PasskeyRegistration>>>;
type AuthenticationStateStore = Arc<Mutex<HashMap<String, PasskeyAuthentication>>>;

// Utility functions
fn lock_err<T, E>(result: Result<T, E>) -> AppResult<T> {
    result.map_err(|_| AppError::Internal("Lock failed".to_string()))
}

fn validate_and_find_user<'a>(store: &'a mut HashMap<String, User>, username: &str) -> AppResult<&'a mut User> {
    let username = username.trim();
    if username.is_empty() { return Err(AppError::Authentication("Username cannot be empty".to_string())); }

    store.values_mut()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))
}

// Route setup
pub fn routes(webauthn: Arc<Webauthn>) -> Router {
    let user_store: UserStore = Arc::new(Mutex::new(HashMap::new()));
    let registration_state_store: RegistrationStateStore = Arc::new(Mutex::new(HashMap::new()));
    let authentication_state_store: AuthenticationStateStore = Arc::new(Mutex::new(HashMap::new()));

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

// Start registration
async fn start_register(
    Extension(webauthn): Extension<Arc<Webauthn>>,
    Extension(user_store): Extension<UserStore>,
    Extension(registration_state_store): Extension<RegistrationStateStore>,
    Json(req): Json<RegisterRequest>,
) -> AppResult<Json<RegisterResponse>> {
    let username = req.username.trim();
    if username.is_empty() { return Err(AppError::Authentication("Username cannot be empty".to_string())); }

    // Check if username already exists and create new user
    let mut store = lock_err(user_store.lock())?;
    if store.values().any(|u| u.name == username) {
        return Err(AppError::Authentication("Username already exists".to_string()));
    }

    // Create user and registration challenge
    let uuid = Uuid::new_v4();
    let user_id = uuid.to_string();

    store.insert(user_id.clone(), User {
        id: user_id.clone(),
        name: username.to_string(),
        credentials: Vec::new(),
    });

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(uuid, username, username, None)
        .map_err(AppError::WebAuthn)?;

    // Store registration state
    lock_err(registration_state_store.lock())?.insert(user_id.clone(), reg_state);

    // Convert challenge to JSON
    let ccr_json = serde_json::to_value(&ccr)
        .map_err(|_| AppError::Internal("Serialization failed".to_string()))?;

    if let Ok(pretty) = serde_json::to_string_pretty(&ccr_json) {
        tracing::info!("Registration challenge: {}", pretty);
    }

    Ok(Json(RegisterResponse { public_key: ccr_json, user_id }))
}

// Finish registration
async fn finish_register(
    Extension(webauthn): Extension<Arc<Webauthn>>,
    Extension(user_store): Extension<UserStore>,
    Extension(registration_state_store): Extension<RegistrationStateStore>,
    Json(req): Json<FinishRegisterRequest>,
) -> AppResult<Json<serde_json::Value>> {
    // Find user
    let mut store = lock_err(user_store.lock())?;
    let user = validate_and_find_user(&mut store, &req.username)?;

    // Get registration state and verify
    let reg_state = lock_err(registration_state_store.lock())?
        .remove(&user.id)
        .ok_or_else(|| AppError::Authentication("Registration session expired".to_string()))?;

    // Verify registration and update user credentials
    let credential = webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(AppError::WebAuthn)?;

    user.credentials.push(credential);

    Ok(Json(serde_json::json!({"status": "success", "message": "Registration successful"})))
}

// Start login
async fn start_login(
    Extension(webauthn): Extension<Arc<Webauthn>>,
    Extension(user_store): Extension<UserStore>,
    Extension(authentication_state_store): Extension<AuthenticationStateStore>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    // Find user
    let store = lock_err(user_store.lock())?;
    let username = req.username.trim();
    if username.is_empty() { return Err(AppError::Authentication("Username cannot be empty".to_string())); }

    let user = store.values()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    // Check if user has credentials
    if user.credentials.is_empty() {
        return Err(AppError::Authentication("User has no registered credentials".to_string()));
    }

    // Create authentication challenge
    let (auth_challenge, auth_state) = webauthn
        .start_passkey_authentication(&user.credentials)
        .map_err(AppError::WebAuthn)?;

    // Store authentication state
    lock_err(authentication_state_store.lock())?.insert(user.id.clone(), auth_state);

    // Convert challenge to JSON
    let auth_challenge_json = serde_json::to_value(&auth_challenge)
        .map_err(|_| AppError::Internal("Serialization failed".to_string()))?;

    if let Ok(pretty) = serde_json::to_string_pretty(&auth_challenge_json) {
        tracing::info!("Authentication challenge: {}", pretty);
    }

    Ok(Json(LoginResponse { public_key: auth_challenge_json }))
}

// Finish login
async fn finish_login(
    Extension(webauthn): Extension<Arc<Webauthn>>,
    Extension(user_store): Extension<UserStore>,
    Extension(authentication_state_store): Extension<AuthenticationStateStore>,
    Json(req): Json<FinishLoginRequest>,
) -> AppResult<Json<FinishLoginResponse>> {
    // Find user
    let mut store = lock_err(user_store.lock())?;
    let user = validate_and_find_user(&mut store, &req.username)?;

    // Get authentication state
    let auth_state = lock_err(authentication_state_store.lock())?
        .remove(&user.id)
        .ok_or_else(|| AppError::Authentication("Authentication session expired".to_string()))?;

    // Verify login
    let auth_result = webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(AppError::WebAuthn)?;

    // Verify user handle
    if let Some(user_handle) = &req.credential.response.user_handle {
        let expected_uuid = Uuid::parse_str(&user.id)
            .map_err(|_| AppError::Internal("UUID parse failed".to_string()))?;

        let credential_user_handle = Uuid::from_slice(user_handle)
            .map_err(|_| AppError::Authentication("Invalid credential user handle".to_string()))?;

        if credential_user_handle != expected_uuid {
            return Err(AppError::Authentication("User handle does not match".to_string()));
        }
    }

    // Update credential counter
    if let Some(credential) = user.credentials.iter_mut().find(|c| c.cred_id() == auth_result.cred_id()) {
        credential.update_credential(&auth_result);
    }

    // Issue JWT token
    let token = jwt::issue_jwt(&user.id, &user.name)?;

    Ok(Json(FinishLoginResponse { token }))
}