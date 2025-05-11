use serde::{Deserialize, Serialize};
use serde_json::Value;

/// API 響應結構體
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse {
    pub status: String,
    pub backend_response: Value,
    pub proxy_info: Value,
    pub tls_info: Value,
}

/// API 響應構建器
pub struct ApiResponseBuilder {
    status: String,
    backend_response: Value,
    proxy_info: Value,
    tls_info: Value,
}

impl ApiResponseBuilder {
    /// 創建新的 API 響應構建器
    pub fn new() -> Self {
        Self {
            status: "success".to_string(),
            backend_response: Value::Null,
            proxy_info: Value::Null,
            tls_info: Value::Null,
        }
    }

    /// 設置狀態
    pub fn status(mut self, status: impl Into<String>) -> Self {
        self.status = status.into();
        self
    }

    /// 設置後端響應
    pub fn backend_response(mut self, response: Value) -> Self {
        self.backend_response = response;
        self
    }

    /// 設置代理信息
    pub fn proxy_info(mut self, info: Value) -> Self {
        self.proxy_info = info;
        self
    }

    /// 設置 TLS 信息
    pub fn tls_info(mut self, info: Value) -> Self {
        self.tls_info = info;
        self
    }

    /// 構建 API 響應
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

/// 檢查請求是否已認證
pub fn is_authenticated(auth: &str) -> bool {
    !auth.is_empty() && auth.starts_with("Bearer ")
}

/// 確保後端響應中的認證狀態與請求的認證狀態一致
pub fn ensure_auth_consistency(backend_json: &Value, is_auth: bool) -> Value {
    let mut modified = backend_json.clone();

    if let Some(obj) = modified.as_object_mut() {
        // 根據請求的認證狀態設置後端響應中的認證狀態
        obj.insert("authenticated".to_string(), Value::Bool(is_auth));

        // 如果請求未認證，將 user_info 設置為 null
        if !is_auth {
            obj.insert("user_info".to_string(), Value::Null);
        }
    }

    modified
}

/// 根據後端響應和 HTTP 狀態確定響應狀態
pub fn determine_response_status(backend_json: &Value, status_code: u16) -> String {
    if backend_json.get("status").and_then(|v| v.as_str()) == Some("error") {
        "error".to_string()
    } else if status_code >= 400 {
        "error".to_string()
    } else {
        "success".to_string()
    }
}

/// 創建錯誤響應
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
