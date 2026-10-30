use release_channel::authentication;
use release_channel::model;
use release_channel::planner;

pub struct Fixture {
    pub metadata: model::Metadata,
    pub policy: model::Policy,
    pub facts: model::ReleaseFacts,
    pub signatures: Vec<artifact_auth_core::SignatureEvidence>,
}

fn key(number: u8) -> artifact_auth_core::ArtifactRef {
    authentication::reference("ed25519-public-key.v1", [number; 32])
}

impl Fixture {
    pub fn new() -> Self {
        let trusted_keys = (1..=2)
            .map(|number| artifact_auth_core::TrustedKeyObservation {
                producer_id: "publisher".into(),
                key_id: format!("key-{number}"),
                key_identity: key(number),
                allowed_purposes: vec!["channel-publish".into()],
                generation: 1,
                currentness: artifact_auth_core::KeyCurrentness::Current,
                currentness_ref: authentication::reference(
                    "release-channel.revocation.v1",
                    [8; 32],
                ),
            })
            .collect();
        let policy = model::Policy {
            channel: [3; 32],
            trust: [4; 32],
            witness: [5; 32],
            mirrors: vec![[6; 32], [7; 32]],
            max_metadata_age: 100,
            max_readiness_age: 100,
            max_revocation_age: 100,
            authentication: artifact_auth_core::AuthenticationPolicy {
                schema: "artifact-auth.policy.v1".into(),
                profile_id: "release-channel.v1".into(),
                threshold: 2,
                trusted_keys,
            },
            delegations: vec![model::Delegation {
                identity: [9; 32],
                channel: [3; 32],
                trust: [4; 32],
                not_before: 1,
                expires_at: 200,
                first_generation: 1,
                last_generation: 10,
            }],
        };
        let metadata = model::Metadata {
            channel: [3; 32],
            trust: [4; 32],
            generation: 1,
            release: [10; 32],
            readiness: [11; 32],
            evidence: [12; 32],
            policy: authentication::policy_identity(&policy).unwrap(),
            delegation: [9; 32],
            revocation: [8; 32],
            mirrors: policy.mirrors.clone(),
            prior: None,
            issued_at: 10,
            expires_at: 90,
        };
        let facts = model::ReleaseFacts {
            release: metadata.release,
            readiness: metadata.readiness,
            evidence: metadata.evidence,
            readiness_issued: 10,
            readiness_expires: 90,
            readiness_passed: true,
            revocation: metadata.revocation,
            revocation_issued: 10,
            revocation_expires: 90,
        };
        let mut fixture = Self {
            metadata,
            policy,
            facts,
            signatures: vec![],
        };
        fixture.sign();
        fixture
    }

    pub fn sign(&mut self) {
        self.metadata.policy = authentication::policy_identity(&self.policy).unwrap();
        self.signatures = self
            .policy
            .authentication
            .trusted_keys
            .iter()
            .map(|key| artifact_auth_core::SignatureEvidence {
                statement: artifact_auth_core::ArtifactStatement {
                    schema: "artifact-auth.statement.v1".into(),
                    scope: authentication::scope(&self.metadata).unwrap(),
                    producer_id: key.producer_id.clone(),
                    key_id: key.key_id.clone(),
                    key_identity: key.key_identity.clone(),
                },
                generation: key.generation,
                cryptographic: artifact_auth_core::CryptographicObservation {
                    algorithm: "ed25519".into(),
                    key_identity: key.key_identity.clone(),
                    verified: true,
                    failure_code: None,
                },
            })
            .collect();
    }

    pub fn request(&self) -> planner::Request<'_> {
        planner::Request {
            metadata: &self.metadata,
            policy: &self.policy,
            facts: &self.facts,
            signatures: &self.signatures,
            expected: self.metadata.prior,
            rotation: None,
            supersession: None,
            now: 20,
        }
    }

    pub fn plan(&self) -> planner::Plan {
        planner::plan(&self.request()).unwrap()
    }
}
