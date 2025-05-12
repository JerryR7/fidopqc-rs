use std::{env, io::Write, process::{Command, Stdio}};
use serde_json::Value;
use crate::error::{AppError, AppResult};

// TLS configuration structure
pub struct TlsConfig {
    pub openssl: String,
    pub cert: String,
    pub key: String,
    pub ca: String,
}

impl TlsConfig {
    // Create a new TLS configuration
    pub fn new() -> Self {
        Self {
            openssl: env::var("OPENSSL_PATH").unwrap_or_else(|_| {
                for path in [
                    "/usr/local/Cellar/openssl@3.5/3.5.0/bin/openssl",
                    "/usr/local/opt/openssl@3.5/bin/openssl",
                    "/opt/openssl35/bin/openssl",
                    "openssl35",
                    "openssl"
                ] {
                    if Command::new(path).arg("version").output().is_ok() {
                        return path.to_string();
                    }
                }
                "openssl".to_string()
            }),
            cert: env::var("CLIENT_CERT_PATH").unwrap_or_else(|_| "certs/hybrid-client/client.crt".to_string()),
            key: env::var("CLIENT_KEY_PATH").unwrap_or_else(|_| "certs/hybrid-client/client_pkcs8.key".to_string()),
            ca: env::var("CA_CERT_PATH").unwrap_or_else(|_| "certs/hybrid-ca/ca.crt".to_string()),
        }
    }

    // Execute OpenSSL command
    pub fn run(&self, host: &str, port: u16, args: &[&str], stdin: Option<&[u8]>) -> AppResult<std::process::Output> {
        let mut cmd = Command::new(&self.openssl);
        cmd.arg("s_client")
           .args(["-connect", &format!("{}:{}", host, port)])
           .args(["-cert", &self.cert])
           .args(["-key", &self.key])
           .args(["-CAfile", &self.ca])
           .args(["-tls1_3", "-groups", "X25519MLKEM768"])
           .args(args);

        match stdin {
            Some(data) => {
                let mut child = cmd.stdin(Stdio::piped())
                                  .stdout(Stdio::piped())
                                  .stderr(Stdio::piped())
                                  .spawn()
                                  .map_err(|e| AppError::Internal(format!("OpenSSL startup error: {}", e)))?;

                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(data)
                        .map_err(|e| AppError::Internal(format!("OpenSSL input error: {}", e)))?;
                }

                child.wait_with_output()
                    .map_err(|e| AppError::Internal(format!("OpenSSL error: {}", e)))
            },
            None => cmd.output()
                     .map_err(|e| AppError::Internal(format!("OpenSSL error: {}", e)))
        }
    }

    // Get OpenSSL version
    pub fn version(&self) -> String {
        Command::new(&self.openssl)
            .arg("version")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

// Get TLS connection information
pub fn get_tls_info(host: &str, port: u16) -> AppResult<Value> {
    let config = TlsConfig::new();
    let output = config.run(host, port, &["-brief"], None)?;

    // Combine standard output and error output
    let tls_output = format!("{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Connection status
    let connection_status = if output.status.success() {
        "success".to_string()
    } else {
        format!("error: {}", String::from_utf8_lossy(&output.stderr))
    };

    // General function to extract values
    let extract_value = |patterns: &[&str]| -> String {
        for pattern in patterns {
            for line in tls_output.lines() {
                if line.contains(pattern) {
                    if let Some(pos) = line.find(':') {
                        let value = line[pos+1..].trim();
                        if !value.is_empty() {
                            return value.to_string();
                        }
                    }
                }
            }
        }
        "unknown".to_string()
    };

    // Extract TLS protocol version
    let protocol = extract_value(&["Protocol version:", "Protocol:"]);

    // Extract cipher suite information
    let mut cipher = extract_value(&["Ciphersuite:", "Cipher is", "Cipher:"]);

    // Clean up cipher suite value
    if cipher != "unknown" && cipher.contains("TLS_") {
        if let Some(pos) = cipher.find("TLS_") {
            cipher = cipher[pos..].trim().to_string();
        }
    }

    // Extract key exchange information
    let key_exchange = extract_value(&["Negotiated TLS1.3 group:", "Server Temp Key:"]);

    // Extract signature type information
    let signature_type = extract_value(&["Signature type:"]);

    // Create JSON-formatted TLS information
    Ok(serde_json::json!({
        "connection": connection_status,
        "protocol": protocol,
        "cipher": cipher,
        "key_exchange": key_exchange,
        "signature_type": signature_type,
        "pqc_enabled": true,
        "certificates": {
            "client": config.cert,
            "ca": config.ca
        },
        "openssl_version": config.version()
    }))
}
