pub type Id = [u8; 32];
pub const MAX_MIRRORS: usize = 16;
pub const MAX_DELEGATIONS: usize = 32;
pub const MAX_SIGNATURES: usize = 64;
pub const METADATA_DOMAIN: &[u8] = b"release-channel.metadata.v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Identity,
    Policy,
    Expired,
    Freeze,
    Readiness,
    Revocation,
    Delegation,
    Authentication,
    Rotation,
    Rollback,
    MixMatch,
    Mirror,
    Witness,
    Conflict,
    MissingState,
    Storage,
    Transport,
    Uncertain,
    Encoding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub channel: Id,
    pub generation: u64,
    pub metadata: Id,
    pub trust: Id,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub channel: Id,
    pub generation: u64,
    pub release: Id,
    pub readiness: Id,
    pub evidence: Id,
    pub policy: Id,
    pub delegation: Id,
    pub revocation: Id,
    pub trust: Id,
    pub mirrors: Vec<Id>,
    pub prior: Option<State>,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Metadata {
    /// Versioned fixed-width framing; mirror order is canonical and significant.
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        if self.mirrors.is_empty() || self.mirrors.len() > MAX_MIRRORS {
            return Err(Error::Bounds);
        }
        let mut out = Vec::with_capacity(512 + self.mirrors.len() * 32);
        out.extend_from_slice(METADATA_DOMAIN);
        for id in [
            self.channel,
            self.release,
            self.readiness,
            self.evidence,
            self.policy,
            self.delegation,
            self.revocation,
            self.trust,
        ] {
            out.extend_from_slice(&id);
        }
        for number in [self.generation, self.issued_at, self.expires_at] {
            out.extend_from_slice(&number.to_le_bytes());
        }
        out.extend_from_slice(&(self.mirrors.len() as u64).to_le_bytes());
        for mirror in &self.mirrors {
            out.extend_from_slice(mirror);
        }
        match self.prior {
            None => out.push(0),
            Some(prior) => {
                out.push(1);
                out.extend_from_slice(&prior.channel);
                out.extend_from_slice(&prior.generation.to_le_bytes());
                out.extend_from_slice(&prior.metadata);
                out.extend_from_slice(&prior.trust);
            }
        }
        Ok(out)
    }

    /// Bounded exact inverse of the signed transport framing; rejects trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        crate::wire::metadata(bytes)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub identity: Id,
    pub channel: Id,
    pub trust: Id,
    pub not_before: u64,
    pub expires_at: u64,
    pub first_generation: u64,
    pub last_generation: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub channel: Id,
    pub trust: Id,
    pub authentication: artifact_auth_core::AuthenticationPolicy,
    pub delegations: Vec<Delegation>,
    pub mirrors: Vec<Id>,
    pub witness: Id,
    pub max_metadata_age: u64,
    pub max_readiness_age: u64,
    pub max_revocation_age: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFacts {
    pub release: Id,
    pub readiness: Id,
    pub evidence: Id,
    pub readiness_issued: u64,
    pub readiness_expires: u64,
    pub readiness_passed: bool,
    pub revocation: Id,
    pub revocation_issued: u64,
    pub revocation_expires: u64,
}

pub fn nonzero(id: &Id) -> bool {
    *id != [0; 32]
}
pub fn hash(bytes: &[u8]) -> Id {
    *blake3::hash(bytes).as_bytes()
}
pub fn hex(id: &Id) -> String {
    blake3::Hash::from_bytes(*id).to_hex().to_string()
}
