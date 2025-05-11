mod webauthn;
mod call_proxy;
mod error;
mod jwt;

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
    // 加載 .env 文件
    dotenv().ok();

    // 初始化日誌
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting PasskeyMesh Gateway...");

    // 配置 WebAuthn
    let rp_id = "localhost";
    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string()).parse::<u16>().unwrap_or(3001);
    let rp_origin = Url::parse(&format!("http://localhost:{}", port)).unwrap();

    let builder = WebauthnBuilder::new(rp_id, &rp_origin)
        .expect("Invalid configuration")
        .rp_name("PasskeyMesh Gateway");

    let webauthn = Arc::new(builder.build().expect("Invalid configuration"));

    // 創建 PQC mTLS HTTP 客戶端
    let http_client = call_proxy::create_pqc_client()?;

    // 配置 CORS - 更安全的配置
    let cors = CorsLayer::new()
        .allow_origin([format!("http://localhost:{}", port).parse().unwrap()])  // 只允許特定來源
        .allow_methods(vec![
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])  // 只允許特定方法
        .allow_headers(vec![
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])  // 只允許特定標頭
        .allow_credentials(true);  // 允許憑證

    // 創建路由
    let app = Router::new()
        .route("/", get(serve_index))
        .nest("/auth", webauthn::routes(Arc::clone(&webauthn)))
        .route("/api/auth/verify", get(call_proxy::handler).post(call_proxy::handler))
        .layer(Extension(http_client))
        .layer(Extension(Arc::clone(&webauthn)))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    // 啟動服務器
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Server listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

// 提供 index.html 頁面
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
