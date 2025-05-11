use reqwest::Client;
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::tls::TlsConfig;

/// HTTP status structure
#[derive(Debug, Clone)]
pub struct HttpStatus {
    pub code: u16,
    pub line: String,
}

impl HttpStatus {
    /// Parse HTTP status from status line
    pub fn from_status_line(status_line: &str) -> Self {
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        let code = if parts.len() >= 2 {
            parts[1].parse::<u16>().unwrap_or(200)
        } else {
            200
        };

        Self {
            code,
            line: status_line.to_string()
        }
    }

    /// Check if status code is successful (2xx)
    #[allow(dead_code)]
    pub fn is_success(&self) -> bool {
        self.code >= 200 && self.code < 300
    }

    /// Check if status code is error (4xx, 5xx)
    pub fn is_error(&self) -> bool {
        self.code >= 400
    }

    /// Convert to JSON object
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "status_line": self.line,
            "status_code": self.code
        })
    }
}

/// HTTP response structure
#[derive(Debug)]
pub struct HttpResponse {
    pub status: HttpStatus,
    pub body: String,
}

/// Create PQC TLS client
pub fn create_pqc_client() -> AppResult<Client> {
    let config = TlsConfig::new();
    tracing::info!("Using OpenSSL: {}, Cert: {}, Key: {}, CA: {}",
                  config.openssl, config.cert, config.key, config.ca);

    reqwest::ClientBuilder::new()
        .build()
        .map_err(|e| AppError::Internal(format!("HTTP client error: {}", e)))
}

/// Extract JSON from HTTP response
pub fn extract_json(raw: &str) -> String {
    if let Some(start) = raw.find('{') {
        let json = &raw[start..];
        if let Some(end) = json.rfind('}') {
            return json[0..=end].to_string();
        }
    }

    raw.lines()
        .filter(|line| !line.trim().is_empty() && !line.trim().chars().all(|c| c.is_digit(16) || c.is_whitespace()))
        .collect::<Vec<&str>>()
        .join("\n")
}

/// Send HTTP request and get response
pub fn send_request(host: &str, port: u16, path: &str, auth: Option<&str>) -> AppResult<HttpResponse> {
    let config = TlsConfig::new();

    // HTTP request
    let mut req = String::with_capacity(256);
    req.push_str(&format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path, host));

    if let Some(token) = auth {
        req.push_str(&format!("Authorization: {}\r\n", token));
    }

    req.push_str("X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\n");
    req.push_str("X-XSS-Protection: 1; mode=block\r\nConnection: close\r\n\r\n");

    // Execute request
    let output = config.run(host, port, &["-quiet"], Some(req.as_bytes()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::Internal(format!("TLS connection failed: {}", stderr)));
    }

    // Parse response
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.splitn(2, "\r\n\r\n").collect();

    if parts.len() < 2 {
        return Err(AppError::Internal("Invalid HTTP response".to_string()));
    }

    let status_line = parts[0].lines().next().unwrap_or("HTTP/1.1 200 OK").to_string();
    let status = HttpStatus::from_status_line(&status_line);
    let body = extract_json(parts[1]);

    Ok(HttpResponse { status, body })
}
