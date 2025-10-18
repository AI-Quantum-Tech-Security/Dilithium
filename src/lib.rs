pub mod api {
    pub mod crypto_keys;
    pub mod auth;
    pub mod error;
    pub mod routes;
}

pub use api::{crypto_keys, auth, error};