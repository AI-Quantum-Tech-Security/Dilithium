// src/routes.rs
use axum::{routing::post, Router};
use crate::handlers::{sign_handler, verify_handler};
use crate::auth::InternalAuth;

pub fn protected_routes() -> Router {
    Router::new()
        .route("/sign", post(sign_handler))
        .route("/verify", post(verify_handler))
        .layer(axum::middleware::from_fn(auth_middleware))
}

async fn auth_middleware<B>(
    req: axum::http::Request<B>,
    next: axum::middleware::Next<B>,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    InternalAuth::from_request_parts(&mut req.into_parts().0, &()).await?;
    Ok(next.run(req).await)
}
