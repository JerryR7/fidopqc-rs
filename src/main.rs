mod webauthn;
mod error;
mod jwt;
mod tls;
mod http_client;
mod api_response;
mod handler;

use axum::{routing::get, Router, Extension, response::Html, http::StatusCode};
use std::{sync::Arc, net::SocketAddr};
use tokio::fs;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use webauthn_rs::prelude::*;
use url::Url;
use dotenv::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables and initialize logging
    dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting PasskeyMesh Gateway...");

    // Configure WebAuthn
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>().unwrap_or(3001);

    let webauthn = Arc::new(
        WebauthnBuilder::new("localhost", &Url::parse(&format!("http://localhost:{}", port)).unwrap())
            .expect("Invalid configuration")
            .rp_name("PasskeyMesh Gateway")
            .build()
            .expect("Invalid configuration")
    );

    // Initialize PQC mTLS HTTP client
    let _ = http_client::create_pqc_client()?;

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin([format!("http://localhost:{}", port).parse().unwrap()])
        .allow_methods(vec![
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(vec![
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
        .allow_credentials(true);

    // Create routes
    let app = Router::new()
        .route("/", get(serve_index))
        .nest("/auth", webauthn::routes(Arc::clone(&webauthn)))
        .route("/api/auth/verify", get(handler::handle_request).post(handler::handle_request))
        .layer(Extension(Arc::clone(&webauthn)))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Server listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

// Serve index.html page
async fn serve_index() -> Result<Html<String>, (StatusCode, String)> {
    match fs::read_to_string("index.html").await {
        Ok(content) => Ok(Html(content)),
        Err(err) => {
            tracing::error!("Failed to read index.html: {}", err);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read index.html: {}", err)))
        }
    }
}
