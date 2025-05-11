use serde::{Deserialize, Serialize};
use serde_json::Value;

/// API response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    pub status: String,
    pub backend_response: Value,
    pub proxy_info: Value,
    pub tls_info: Value,
}

/// API response builder
pub struct ApiResponseBuilder {
    status: String,
    backend_response: Value,
    proxy_info: Value,
    tls_info: Value,
}

impl ApiResponseBuilder {
    /// Create new API response builder
    pub fn new() -> Self {
        Self {
            status: "success".to_string(),
            backend_response: Value::Null,
            proxy_info: Value::Null,
            tls_info: Value::Null,
        }
    }

    /// Set status
    pub fn status(mut self, status: impl Into<String>) -> Self {
        self.status = status.into();
        self
    }

    /// Set backend response
    pub fn backend_response(mut self, response: Value) -> Self {
        self.backend_response = response;
        self
    }

    /// Set proxy information
    pub fn proxy_info(mut self, info: Value) -> Self {
        self.proxy_info = info;
        self
    }

    /// Set TLS information
    pub fn tls_info(mut self, info: Value) -> Self {
        self.tls_info = info;
        self
    }

    /// Build API response
    pub fn build(self) -> ApiResponse {
        ApiResponse {
            status: self.status,
            backend_response: self.backend_response,
            proxy_info: self.proxy_info,
            tls_info: self.tls_info,
        }
    }
}

impl Default for ApiResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if request is authenticated
pub fn is_authenticated(auth: &str) -> bool {
    !auth.is_empty() && auth.starts_with("Bearer ")
}

/// Ensure authentication status in backend response is consistent with request authentication status
pub fn ensure_auth_consistency(backend_json: &Value, is_auth: bool) -> Value {
    let mut modified = backend_json.clone();

    if let Some(obj) = modified.as_object_mut() {
        // Set authentication status in backend response based on request authentication status
        obj.insert("authenticated".to_string(), Value::Bool(is_auth));

        // If request is not authenticated, set user_info to null
        if !is_auth {
            obj.insert("user_info".to_string(), Value::Null);
        }
    }

    modified
}

/// Determine response status based on backend response and HTTP status
pub fn determine_response_status(backend_json: &Value, status_code: u16) -> String {
    if backend_json.get("status").and_then(|v| v.as_str()) == Some("error") {
        "error".to_string()
    } else if status_code >= 400 {
        "error".to_string()
    } else {
        "success".to_string()
    }
}

/// Create error response
#[allow(dead_code)]
pub fn create_error_response(message: &str) -> ApiResponse {
    ApiResponseBuilder::new()
        .status("error")
        .backend_response(serde_json::json!({
            "status": "error",
            "message": message
        }))
        .proxy_info(serde_json::json!({
            "status_line": "Error",
            "error": message
        }))
        .tls_info(serde_json::json!({
            "error": "TLS info unavailable"
        }))
        .build()
}
