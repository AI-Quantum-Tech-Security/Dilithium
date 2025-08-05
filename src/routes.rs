use axum::{routing::post, Router};
use crate::api::{sign_handler, verify_handler};
use crate::auth::InternalAuth;

pub fn protected_routes() -> Router {
    Router::new()
        .route("/sign", post(sign_handler))
        .layer(axum::middleware::from_fn(auth_middleware))
        .route("/verify", post(verify_handler))
}

async fn auth_middleware<B>(
    InternalAuth(req): InternalAuth,
    next: axum::middleware::Next<B>,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    Ok(next.run(req).await)
}