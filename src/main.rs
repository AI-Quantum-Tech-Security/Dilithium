use std::sync::Arc;
use tokio::net::TcpListener;
use std::env;

mod api;

#[tokio::main]
async fn main() {
    let app_keys = Arc::new(api::crypto_keys::AppCryptoKeys::new()
        .expect("Failed to generate keys"));

    let app = api::routes(app_keys);

    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    println!("Listening on http://{}", addr);

    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}