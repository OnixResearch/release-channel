use release_channel_witness::{provider, state, types};
use std::{collections, path};

#[derive(Clone)]
struct Fake {
    evidence: collections::BTreeMap<String, types::Evidence>,
    next: String,
    failure: Option<types::Error>,
}

impl provider::Provider for Fake {
    fn append(&mut self, statement: &types::Statement) -> Result<types::Evidence, types::Error> {
        let next = self.next.clone();
        self.verify(statement, &next)
    }

    fn verify(
        &mut self,
        statement: &types::Statement,
        proof: &str,
    ) -> Result<types::Evidence, types::Error> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let evidence = self
            .evidence
            .get(proof)
            .ok_or_else(|| types::Error::Invalid("unknown proof".into()))?;
        if evidence.statement != *statement {
            return Err(types::Error::Invalid("signed metadata mismatch".into()));
        }
        Ok(evidence.clone())
    }

    fn consistency(
        &mut self,
        previous: &types::Checkpoint,
        observed: &types::Checkpoint,
    ) -> Result<(), types::Error> {
        if previous.root == "baseline" && observed.root == "unproven" {
            return Err(types::Error::Unavailable(
                "consistency path unavailable".into(),
            ));
        }
        Ok(())
    }
}

fn evidence(size: u64, root: &str) -> types::Evidence {
    types::Evidence {
        statement: types::Statement {
            metadata_hash: [size as u8; 32],
            signer: "signer".into(),
        },
        proof: root.into(),
        checkpoint: types::Checkpoint {
            log: "log".into(),
            size,
            root: root.into(),
        },
    }
}

fn fake(next: &types::Evidence) -> Fake {
    let baseline = evidence(10, "baseline");
    Fake {
        evidence: [
            (baseline.proof.clone(), baseline),
            (next.proof.clone(), next.clone()),
        ]
        .into(),
        next: next.proof.clone(),
        failure: None,
    }
}

fn enrolled(path: path::PathBuf, next: &types::Evidence) -> state::Monotonic<Fake> {
    state::Monotonic::enroll(fake(next), path, &evidence(10, "baseline"))
        .expect("explicit enrollment")
}

#[test]
fn advance_is_durable_and_reverified_on_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checkpoint");
    let next = evidence(12, "advanced");
    let mut witness = enrolled(path.clone(), &next);
    let observed = witness.append(&next.statement).unwrap();
    assert_eq!(observed, next);
    drop(witness);
    let reopened = state::Monotonic::open(fake(&next), path).unwrap();
    assert_eq!(reopened.checkpoint(), Some(&next.checkpoint));
}

#[test]
fn missing_state_and_reenrollment_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checkpoint");
    let next = evidence(11, "advanced");
    assert!(matches!(
        state::Monotonic::open(fake(&next), path.clone()),
        Err(types::Error::Invalid(_))
    ));
    drop(enrolled(path.clone(), &next));
    assert!(matches!(
        state::Monotonic::enroll(fake(&next), path, &evidence(10, "baseline")),
        Err(types::Error::Durability(_))
    ));
}

#[test]
fn signed_same_size_conflict_is_a_fork_and_preserves_history() {
    let directory = tempfile::tempdir().unwrap();
    let next = evidence(10, "conflict");
    let mut witness = enrolled(directory.path().join("checkpoint"), &next);
    assert!(matches!(
        witness.append(&next.statement),
        Err(types::Error::Fork { .. })
    ));
    assert_eq!(
        witness.checkpoint(),
        Some(&evidence(10, "baseline").checkpoint)
    );
}

#[test]
fn rollback_cannot_replace_larger_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let next = evidence(9, "old");
    let mut witness = enrolled(directory.path().join("checkpoint"), &next);
    assert!(matches!(
        witness.append(&next.statement),
        Err(types::Error::Rollback {
            previous: 10,
            observed: 9
        })
    ));
}

#[test]
fn inclusion_without_consistency_does_not_advance() {
    let directory = tempfile::tempdir().unwrap();
    let next = evidence(11, "unproven");
    let mut witness = enrolled(directory.path().join("checkpoint"), &next);
    assert!(matches!(
        witness.append(&next.statement),
        Err(types::Error::Unavailable(_))
    ));
    assert_eq!(
        witness.checkpoint(),
        Some(&evidence(10, "baseline").checkpoint)
    );
}

#[test]
fn changed_metadata_cannot_reuse_proof() {
    let directory = tempfile::tempdir().unwrap();
    let next = evidence(11, "advanced");
    let mut witness = enrolled(directory.path().join("checkpoint"), &next);
    let changed = types::Statement {
        metadata_hash: [99; 32],
        signer: next.statement.signer.clone(),
    };
    assert!(matches!(
        witness.verify(&changed, &next.proof),
        Err(types::Error::Invalid(_))
    ));
}

#[test]
fn absent_quorum_never_enrolls() {
    let directory = tempfile::tempdir().unwrap();
    let next = evidence(11, "advanced");
    let mut provider = fake(&next);
    provider.failure = Some(types::Error::Quorum("insufficient cosignatures".into()));
    assert!(matches!(
        state::Monotonic::enroll(provider, directory.path().join("checkpoint"), &next),
        Err(types::Error::Quorum(_))
    ));
    assert!(!directory.path().join("checkpoint").exists());
}
