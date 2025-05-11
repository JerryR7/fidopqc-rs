mod webauthn;
mod error;
mod jwt;
mod tls;
mod http_client;
mod api_response;
mod handler;

use axum::{
    routing::get,
    Router,
    Extension,
    response::Html,
    http::StatusCode,
};
use std::{sync::Arc, path::PathBuf, net::SocketAddr};
use tokio::fs;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use webauthn_rs::prelude::*;
use url::Url;
use dotenv::dotenv;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file
    dotenv().ok();

    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting PasskeyMesh Gateway...");

    // Configure WebAuthn
    let rp_id = "localhost";
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string()).parse::<u16>().unwrap_or(3001);
    let rp_origin = Url::parse(&format!("http://localhost:{}", port)).unwrap();

    let builder = WebauthnBuilder::new(rp_id, &rp_origin)
        .expect("Invalid configuration")
        .rp_name("PasskeyMesh Gateway");

    let webauthn = Arc::new(builder.build().expect("Invalid configuration"));

    // Create PQC mTLS HTTP client (only for initialization and logging)
    let _ = http_client::create_pqc_client()?;

    // Configure CORS - more secure configuration
    let cors = CorsLayer::new()
        .allow_origin([format!("http://localhost:{}", port).parse().unwrap()])  // Only allow specific origins
        .allow_methods(vec![
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])  // Only allow specific methods
        .allow_headers(vec![
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])  // Only allow specific headers
        .allow_credentials(true);  // Allow credentials

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
    let index_path = PathBuf::from("index.html");

    match fs::read_to_string(index_path).await {
        Ok(content) => Ok(Html(content)),
        Err(err) => {
            tracing::error!("Failed to read index.html: {}", err);
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read index.html: {}", err)))
        }
    }
}
