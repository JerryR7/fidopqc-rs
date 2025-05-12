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
    /// User ID as UUID string - this is also used as the WebAuthn user handle
    /// This ID must be stable and unique for each user to ensure proper credential binding
    pub id: String,

    /// Username for display purposes
    pub name: String,

    /// List of registered passkeys (credentials) for this user
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

    // Check if username already exists
    let mut store = user_store.lock().map_err(|e| AppError::Internal(format!("Failed to lock user store: {}", e)))?;
    if store.values().any(|u| u.name == username) {
        return Err(AppError::Authentication("Username already exists".to_string()));
    }

    // Generate a stable user ID that will be used as the user handle
    let user_id = Uuid::new_v4().to_string();
    let user_unique_id = Uuid::parse_str(&user_id).map_err(|e| AppError::Internal(format!("Failed to parse UUID: {}", e)))?;

    // Create a new user with empty credentials
    let user = User {
        id: user_id.clone(),
        name: username.to_string(),
        credentials: Vec::new(),
    };

    // Store user
    store.insert(user_id.clone(), user.clone());

    // Create a registration challenge
    // Use the same UUID for user_id and user_handle to ensure proper binding
    // For new users, there are no credentials to exclude
    let exclude_credentials = None;

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(
            user_unique_id,
            &username,
            &username,
            exclude_credentials,
        )
        .map_err(AppError::WebAuthn)?;

    // Store registration state
    let mut reg_store = registration_state_store.lock()
        .map_err(|e| AppError::Internal(format!("Failed to lock registration state store: {}", e)))?;
    reg_store.insert(user_id.clone(), reg_state);

    // Print registration challenge structure
    let ccr_json = serde_json::to_value(&ccr)
        .map_err(|e| AppError::Internal(format!("Failed to serialize challenge: {}", e)))?;

    if let Ok(pretty) = serde_json::to_string_pretty(&ccr_json) {
        tracing::info!("Registration challenge: {}", pretty);
    }

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
    let mut store = user_store.lock()
        .map_err(|e| AppError::Internal(format!("Failed to lock user store: {}", e)))?;

    let user = store
        .values_mut()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    // Get registration state
    let mut reg_store = registration_state_store.lock()
        .map_err(|e| AppError::Internal(format!("Failed to lock registration state store: {}", e)))?;

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
    let store = user_store.lock()
        .map_err(|e| AppError::Internal(format!("Failed to lock user store: {}", e)))?;

    let user = store
        .values()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    if user.credentials.is_empty() {
        return Err(AppError::Authentication("No credentials found for user".to_string()));
    }

    // Create an authentication challenge with allowCredentials list
    let (auth_challenge, auth_state) = webauthn
        .start_passkey_authentication(&user.credentials)
        .map_err(AppError::WebAuthn)?;

    // Print authentication challenge structure
    let auth_challenge_json = serde_json::to_value(&auth_challenge)
        .map_err(|e| AppError::Internal(format!("Failed to serialize challenge: {}", e)))?;

    if let Ok(pretty) = serde_json::to_string_pretty(&auth_challenge_json) {
        tracing::info!("Authentication challenge: {}", pretty);
    }

    // Store authentication state
    let mut auth_store = authentication_state_store.lock()
        .map_err(|e| AppError::Internal(format!("Failed to lock authentication state store: {}", e)))?;

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
    let mut store = user_store.lock()
        .map_err(|e| AppError::Internal(format!("Failed to lock user store: {}", e)))?;

    let user = store
        .values_mut()
        .find(|u| u.name == username)
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

    // Get authentication state
    let mut auth_store = authentication_state_store.lock()
        .map_err(|e| AppError::Internal(format!("Failed to lock authentication state store: {}", e)))?;

    let auth_state = auth_store
        .remove(&user.id)
        .ok_or_else(|| AppError::Authentication("Authentication session expired".to_string()))?;

    // Verify login and get authentication result
    let auth_result = webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(AppError::WebAuthn)?;

    // Verify that the user handle in the credential matches the user's ID
    verify_user_handle(&req.credential, &user.id)?;

    // Update credential counter to prevent replay attacks
    let cred_id = auth_result.cred_id();
    if let Some(credential) = user.credentials.iter_mut().find(|c| c.cred_id() == cred_id) {
        // Update the credential with the authentication result
        credential.update_credential(&auth_result);
        tracing::info!("Updated counter for credential {:?}", cred_id);
    } else {
        tracing::error!("Could not find credential with ID {:?} to update counter", cred_id);
    }

    // Generate JWT token
    let token = jwt::issue_jwt(&user.id, &user.name)?;

    Ok(Json(FinishLoginResponse { token }))
}

/// Verify that the user handle in the credential matches the expected user ID
/// This is a critical security check to prevent credential substitution attacks
fn verify_user_handle(credential: &PublicKeyCredential, expected_user_id: &str) -> AppResult<()> {
    if let Some(user_handle) = &credential.response.user_handle {
        let expected_uuid = Uuid::parse_str(expected_user_id)
            .map_err(|e| AppError::Internal(format!("Failed to parse user ID as UUID: {}", e)))?;

        let credential_user_handle = Uuid::from_slice(user_handle)
            .map_err(|e| AppError::Authentication(format!("Invalid user handle in credential: {}", e)))?;

        if credential_user_handle != expected_uuid {
            return Err(AppError::Authentication(
                "User handle mismatch - possible credential substitution attack".to_string()
            ));
        }

        Ok(())
    } else {
        // According to WebAuthn spec, user_handle should be present in cross-origin authentication
        tracing::warn!("No user handle in authentication response - this may be a security risk");
        Ok(())
    }
}