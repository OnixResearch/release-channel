#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Statement {
    pub metadata_hash: [u8; 32],
    pub signer: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Checkpoint {
    pub log: String,
    pub size: u64,
    pub root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Evidence {
    pub statement: Statement,
    pub proof: String,
    pub checkpoint: Checkpoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid(String),
    Quorum(String),
    Unavailable(String),
    /// Submission or durable publication may have happened; never infer absence.
    Uncertain(String),
    Fork {
        previous: Checkpoint,
        observed: Checkpoint,
    },
    Rollback {
        previous: u64,
        observed: u64,
    },
    Durability(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
