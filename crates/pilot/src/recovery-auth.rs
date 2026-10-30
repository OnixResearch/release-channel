use crate::setup;
use release_channel::authentication;
use release_channel::model;

pub fn signatures(
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
                    .map_err(|e| anyhow::anyhow!("scope: {e:?}"))?,
                producer_id: trusted.producer_id.clone(),
                key_id: trusted.key_id.clone(),
                key_identity: trusted.key_identity.clone(),
            };
            let bytes = artifact_auth_core::canonical_statement_bytes(&statement)
                .map_err(|e| anyhow::anyhow!("statement: {e:?}"))?;
            Ok(authentication::Carrier {
                public_key: key.verifying_key().to_bytes(),
                signature: ed25519_dalek::Signer::sign(&key, &bytes).to_bytes(),
                generation: trusted.generation,
            })
        })
        .collect()
}

pub fn facts(
    request: &serde_json::Value,
    metadata: &model::Metadata,
) -> anyhow::Result<model::ReleaseFacts> {
    let decode = |name: &str| -> anyhow::Result<serde_json::Value> {
        let bytes: Vec<u8> = serde_json::from_value(request[name]["payload"].clone())?;
        Ok(serde_json::from_slice(&bytes)?)
    };
    let readiness = decode("readiness")?;
    let revocation = decode("revocation")?;
    Ok(model::ReleaseFacts {
        release: metadata.release,
        readiness: metadata.readiness,
        evidence: metadata.evidence,
        readiness_issued: serde_json::from_value(readiness["issued"].clone())?,
        readiness_expires: serde_json::from_value(readiness["expires"].clone())?,
        readiness_passed: serde_json::from_value(readiness["passed"].clone())?,
        revocation: metadata.revocation,
        revocation_issued: serde_json::from_value(revocation["issued"].clone())?,
        revocation_expires: serde_json::from_value(revocation["expires"].clone())?,
    })
}

pub fn pin(secrets: &setup::Secrets) -> model::Id {
    ed25519_dalek::SigningKey::from_bytes(&secrets.server)
        .verifying_key()
        .to_bytes()
}
