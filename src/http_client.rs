use reqwest::Client;
use serde_json::Value;
use crate::error::{AppError, AppResult};
use crate::tls::TlsConfig;

// HTTP status structure
#[derive(Debug, Clone)]
pub struct HttpStatus {
    pub code: u16,
    pub line: String,
}

impl HttpStatus {
    // Parse HTTP status from status line
    pub fn from_status_line(status_line: &str) -> Self {
        let code = status_line.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(200);

        Self { code, line: status_line.to_string() }
    }

    // Check if status code is error (4xx, 5xx)
    pub fn is_error(&self) -> bool { self.code >= 400 }

    // Convert to JSON object
    pub fn to_json(&self) -> Value {
        serde_json::json!({ "status_line": self.line, "status_code": self.code })
    }
}

// HTTP response structure
#[derive(Debug)]
pub struct HttpResponse {
    pub status: HttpStatus,
    pub body: String,
}

// Create PQC TLS client
pub fn create_pqc_client() -> AppResult<Client> {
    let config = TlsConfig::new();
    tracing::info!("Using OpenSSL: {}, cert: {}, key: {}, CA: {}",
                  config.openssl, config.cert, config.key, config.ca);

    reqwest::ClientBuilder::new()
        .build()
        .map_err(|e| AppError::Internal(format!("HTTP client error: {}", e)))
}

// Extract JSON from HTTP response
pub fn extract_json(raw: &str) -> String {
    // Try to find JSON object
    if let (Some(start), Some(end)) = (raw.find('{'), raw.rfind('}')) {
        if start < end {
            return raw[start..=end].to_string();
        }
    }

    // If no JSON object found, filter and return non-empty lines
    raw.lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.chars().all(|c| c.is_digit(16) || c.is_whitespace())
        })
        .collect::<Vec<&str>>()
        .join("\n")
}

// Send HTTP request and get response
pub fn send_request(host: &str, port: u16, path: &str, auth: Option<&str>) -> AppResult<HttpResponse> {
    // Build HTTP request
    let mut req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path, host);

    if let Some(token) = auth {
        req.push_str(&format!("Authorization: {}\r\n", token));
    }

    req.push_str(concat!(
        "X-Content-Type-Options: nosniff\r\n",
        "X-Frame-Options: DENY\r\n",
        "X-XSS-Protection: 1; mode=block\r\n",
        "Connection: close\r\n\r\n"
    ));

    // Execute request
    let output = TlsConfig::new().run(host, port, &["-quiet"], Some(req.as_bytes()))?;

    if !output.status.success() {
        return Err(AppError::Internal(format!(
            "TLS connection failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Parse response
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.splitn(2, "\r\n\r\n").collect();

    if parts.len() < 2 {
        return Err(AppError::Internal("Invalid HTTP response".to_string()));
    }

    let status_line = parts[0].lines().next().unwrap_or("HTTP/1.1 200 OK").to_string();

    Ok(HttpResponse {
        status: HttpStatus::from_status_line(&status_line),
        body: extract_json(parts[1])
    })
}
