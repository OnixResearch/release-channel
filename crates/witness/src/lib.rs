//! Explicit-policy Sigsum witnesses for arbitrary metadata hashes.
//! Local state is a rollback fence only while its storage and verifier remain trusted.
//! It does not provide independence from a local administrator or global trust roots.
mod bounded;
pub mod provider;
pub mod sigsum;
pub mod state;
pub mod types;
