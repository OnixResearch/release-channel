pub const MAX_FRAME: usize = 65_536;
pub const MAX_NAMESPACES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    pub channel: String,
    pub platform: String,
    pub track: String,
}

impl Namespace {
    pub fn validate(&self) -> crate::Result<()> {
        for part in [&self.channel, &self.platform, &self.track] {
            if part.is_empty()
                || part.len() > 128
                || !part
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-./:".contains(&c))
            {
                return Err("invalid exact namespace".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub generation: u64,
    pub digest: [u8; 32],
    pub predecessor: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PendingStatus {
    Reserved,
    Orphan,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub reservation: [u8; 32],
    pub claim: Claim,
    pub status: PendingStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub revision: u64,
    pub highest: Option<Claim>,
    pub committed: Option<Claim>,
    pub pending: Option<Pending>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Operation {
    Enroll {
        writer: [u8; 32],
    },
    Query,
    Reserve {
        expected_revision: u64,
        claim: Claim,
    },
    Commit {
        expected_revision: u64,
        reservation: [u8; 32],
        expected_predecessor: Option<[u8; 32]>,
    },
    Orphan {
        expected_revision: u64,
        reservation: [u8; 32],
    },
    ResolveOrphan {
        expected_revision: u64,
        reservation: [u8; 32],
    },
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub namespace: Namespace,
    pub challenge: [u8; 32],
    pub operation: Operation,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest {
    pub request: Request,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub namespace: Namespace,
    pub challenge: [u8; 32],
    /// Digest of the exact successfully applied request, including operation and challenge.
    pub request_digest: [u8; 32],
    pub snapshot: Snapshot,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReply {
    pub reply: Reply,
    pub signature: Vec<u8>,
}

impl Snapshot {
    pub fn validate(&self) -> crate::Result<()> {
        if self.revision == 0
            || self
                .highest
                .as_ref()
                .is_some_and(|claim| claim.generation == 0)
            || self
                .committed
                .as_ref()
                .is_some_and(|claim| claim.generation == 0)
        {
            return Err("invalid durable revision/generation".into());
        }
        if let Some(pending) = &self.pending {
            if self.highest.as_ref() != Some(&pending.claim)
                || pending.claim.predecessor != self.committed.as_ref().map(|claim| claim.digest)
                || self
                    .committed
                    .as_ref()
                    .is_some_and(|claim| pending.claim.generation <= claim.generation)
            {
                return Err("invalid durable pending/high-water relation".into());
            }
        } else if self.highest != self.committed {
            let highest = self.highest.as_ref().ok_or("missing durable high-water")?;
            if highest.predecessor != self.committed.as_ref().map(|claim| claim.digest)
                || self
                    .committed
                    .as_ref()
                    .is_some_and(|claim| highest.generation <= claim.generation)
            {
                return Err("invalid resolved high-water gap".into());
            }
        }
        Ok(())
    }
}
