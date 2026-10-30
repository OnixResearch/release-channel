//! Existing OCI registry and static HTTPS metadata transports, not a new registry.
//! All network authority, roots, credentials, limits and control-plane CAS are ports.
pub mod governance;
pub mod http;
pub mod pilot;
pub mod store;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Policy,
    Request,
    Transport,
    Uncertain,
    Status(u16),
    Incomplete,
    Digest,
    Protocol,
}

pub fn digest(bytes: &[u8]) -> [u8; 32] {
    channel::model::hash(bytes)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    <sha2::Sha256 as sha2::Digest>::digest(bytes).into()
}

pub fn hex(id: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in id {
        result.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        result.push(char::from(ALPHABET[usize::from(byte & 15)]));
    }
    result
}
