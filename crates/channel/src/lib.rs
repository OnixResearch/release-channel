#![forbid(unsafe_code)]
//! Governed distribution decisions over explicit authority and observation inputs.
//! No trust discovery, build/readiness truth, TUF compatibility, or deployment grant.
pub mod authentication;
pub mod consumer;
pub mod model;
pub mod planner;
pub mod publication;
pub mod reconciliation;
mod signature;
pub mod supersession;
pub mod wire;
pub mod witness;
