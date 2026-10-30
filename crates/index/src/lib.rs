//! Authenticated retained high-water state; no ambient trust or deployment authority.
pub mod client;
pub mod crypto;
pub mod model;
pub mod provider;
pub mod transition;

pub type Result<T, E = String> = std::result::Result<T, E>;
