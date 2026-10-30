use release_channel::authentication;
use release_channel::model;

pub fn signed(
    key: &model::Id,
    domain: &[u8],
    payload: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let payload = serde_json::to_vec(&payload)?;
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&payload);
    let key = ed25519_dalek::SigningKey::from_bytes(key);
    let signature = ed25519_dalek::Signer::sign(&key, &bytes)
        .to_bytes()
        .to_vec();
    Ok(serde_json::json!({"payload":payload,"signature":signature}))
}

pub fn payload(value: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::from_value(value["payload"].clone())?)
}

pub fn policy(
    seeds: &[model::Id; 2],
    revocation: model::Id,
    trust: model::Id,
    mirrors: Vec<model::Id>,
    now: u64,
) -> model::Policy {
    let trusted_keys = seeds
        .iter()
        .enumerate()
        .map(|(number, seed)| {
            let key = ed25519_dalek::SigningKey::from_bytes(seed);
            artifact_auth_core::TrustedKeyObservation {
                producer_id: "experimental-publisher".into(),
                key_id: format!("key-{number}"),
                key_identity: artifact_auth_ed25519::public_key_identity(
                    key.verifying_key().as_bytes(),
                ),
                allowed_purposes: vec!["channel-publish".into()],
                generation: 1,
                currentness: artifact_auth_core::KeyCurrentness::Current,
                currentness_ref: authentication::reference(
                    "release-channel.revocation.v1",
                    revocation,
                ),
            }
        })
        .collect();
    model::Policy {
        channel: [3; 32],
        trust,
        witness: [5; 32],
        mirrors,
        max_metadata_age: 3600,
        max_readiness_age: 3600,
        max_revocation_age: 3600,
        authentication: artifact_auth_core::AuthenticationPolicy {
            schema: "artifact-auth.policy.v1".into(),
            profile_id: "release-channel.v1".into(),
            threshold: 2,
            trusted_keys,
        },
        delegations: vec![model::Delegation {
            identity: [9; 32],
            channel: [3; 32],
            trust,
            not_before: now - 3600,
            expires_at: now + 3600,
            first_generation: 1,
            last_generation: 100,
        }],
    }
}

pub fn carriers(
    policy: &model::Policy,
    metadata: &model::Metadata,
    seeds: &[model::Id; 2],
) -> anyhow::Result<Vec<authentication::Carrier>> {
    seeds
        .iter()
        .zip(&policy.authentication.trusted_keys)
        .map(|(seed, trusted)| {
            let key = ed25519_dalek::SigningKey::from_bytes(seed);
            let statement = artifact_auth_core::ArtifactStatement {
                schema: artifact_auth_core::STATEMENT_SCHEMA_V1.into(),
                scope: authentication::scope(metadata)
                    .map_err(|_| anyhow::anyhow!("metadata scope"))?,
                producer_id: trusted.producer_id.clone(),
                key_id: trusted.key_id.clone(),
                key_identity: trusted.key_identity.clone(),
            };
            let bytes = artifact_auth_core::canonical_statement_bytes(&statement)
                .map_err(|_| anyhow::anyhow!("canonical statement"))?;
            Ok(authentication::Carrier {
                public_key: key.verifying_key().to_bytes(),
                signature: ed25519_dalek::Signer::sign(&key, &bytes).to_bytes(),
                generation: trusted.generation,
            })
        })
        .collect()
}
