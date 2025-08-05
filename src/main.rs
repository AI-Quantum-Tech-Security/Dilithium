use axum::Router;
use std::env;
use std::sync::Arc;
use tokio::net::TcpListener;
use aws_sdk_kms::Client as KmsClient;
use aws_config::load_from_env;

mod api;
mod auth;
mod signer;

#[tokio::main]
async fn main() {
    let config = load_from_env().await;
    let kms_client = KmsClient::new(&config);

    // In a real app, you would load the key ID from a config file or env var
    // and retrieve the public key from the KMS.
    let dilithium_key = signer::create_dilithium_key_in_kms(&kms_client, "dilithium-signing-key").await
        .expect("Failed to create or retrieve KMS key");

    let app_state = api::AppState {
        kms_client: Arc::new(kms_client),
        dilithium_key,
    };

    let app = api::routes(app_state);

    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    println!("Listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}