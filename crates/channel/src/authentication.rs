use crate::model;

pub fn policy_identity(policy: &model::Policy) -> Result<model::Id, model::Error> {
    if policy.delegations.len() > model::MAX_DELEGATIONS
        || policy.mirrors.len() > model::MAX_MIRRORS
        || policy.authentication.trusted_keys.len() > model::MAX_SIGNATURES
    {
        return Err(model::Error::Bounds);
    }
    let auth = artifact_auth_core::policy_identity(&policy.authentication)
        .map_err(|_| model::Error::Policy)?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(b"release-channel.policy.v1\0");
    bytes.extend_from_slice(auth.as_bytes());
    for id in [policy.channel, policy.trust, policy.witness] {
        if !model::nonzero(&id) {
            return Err(model::Error::Identity);
        }
        bytes.extend_from_slice(&id);
    }
    for age in [
        policy.max_metadata_age,
        policy.max_readiness_age,
        policy.max_revocation_age,
    ] {
        if age == 0 {
            return Err(model::Error::Policy);
        }
        bytes.extend_from_slice(&age.to_le_bytes());
    }
    bytes.extend_from_slice(&(policy.mirrors.len() as u64).to_le_bytes());
    for mirror in &policy.mirrors {
        bytes.extend_from_slice(mirror);
    }
    bytes.extend_from_slice(&(policy.delegations.len() as u64).to_le_bytes());
    for delegation in &policy.delegations {
        for id in [delegation.identity, delegation.channel, delegation.trust] {
            bytes.extend_from_slice(&id);
        }
        for number in [
            delegation.not_before,
            delegation.expires_at,
            delegation.first_generation,
            delegation.last_generation,
        ] {
            bytes.extend_from_slice(&number.to_le_bytes());
        }
    }
    Ok(model::hash(&bytes))
}

pub fn reference(profile: &str, identity: model::Id) -> artifact_auth_core::ArtifactRef {
    artifact_auth_core::ArtifactRef {
        profile: profile.into(),
        algorithm: "blake3".into(),
        digest_hex: model::hex(&identity),
    }
}

pub fn scope(
    metadata: &model::Metadata,
) -> Result<artifact_auth_core::AuthenticationScope, model::Error> {
    Ok(artifact_auth_core::AuthenticationScope {
        domain: "release-channel.v1".into(),
        purpose: "channel-publish".into(),
        profile_id: "release-channel.v1".into(),
        subject: reference(
            "release-channel.metadata.v1",
            model::hash(&metadata.bytes()?),
        ),
        parents: vec![reference(
            "release-channel.delegation.v1",
            metadata.delegation,
        )],
        verifier_context: reference("release-channel.policy.v1", metadata.policy),
    })
}

pub fn authenticate(
    policy: &model::Policy,
    metadata: &model::Metadata,
    evidence: &[artifact_auth_core::SignatureEvidence],
) -> Result<(), model::Error> {
    if evidence.len() > model::MAX_SIGNATURES {
        return Err(model::Error::Bounds);
    }
    if metadata.mirrors.is_empty() || metadata.mirrors.len() > model::MAX_MIRRORS {
        return Err(model::Error::Bounds);
    }
    policy_identity(policy)?;
    let revocation = reference("release-channel.revocation.v1", metadata.revocation);
    if policy
        .authentication
        .trusted_keys
        .iter()
        .any(|key| key.currentness_ref != revocation)
    {
        return Err(model::Error::Revocation);
    }
    let result = artifact_auth_core::evaluate_authentication(
        &policy.authentication,
        &scope(metadata)?,
        evidence,
    );
    if !result.passed {
        return Err(model::Error::Authentication);
    }
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Carrier {
    pub public_key: [u8; 32],
    #[serde(with = "crate::signature")]
    pub signature: [u8; 64],
    pub generation: u64,
}

/// External signature boundary: never trusts a caller's `verified` boolean.
pub fn verify(
    policy: &model::Policy,
    metadata: &model::Metadata,
    carriers: &[Carrier],
) -> Result<Vec<artifact_auth_core::SignatureEvidence>, model::Error> {
    if carriers.len() > model::MAX_SIGNATURES {
        return Err(model::Error::Bounds);
    }
    policy_identity(policy)?;
    let scope = scope(metadata)?;
    let mut evidence = Vec::with_capacity(carriers.len());
    for carrier in carriers {
        let identity = artifact_auth_ed25519::public_key_identity(&carrier.public_key);
        let key = policy
            .authentication
            .trusted_keys
            .iter()
            .find(|key| key.key_identity == identity)
            .ok_or(model::Error::Authentication)?;
        let statement = artifact_auth_core::ArtifactStatement {
            schema: artifact_auth_core::STATEMENT_SCHEMA_V1.into(),
            scope: scope.clone(),
            producer_id: key.producer_id.clone(),
            key_id: key.key_id.clone(),
            key_identity: identity,
        };
        let cryptographic = artifact_auth_ed25519::verify_statement(
            &statement,
            &carrier.public_key,
            &carrier.signature,
        );
        evidence.push(artifact_auth_core::SignatureEvidence {
            statement,
            generation: carrier.generation,
            cryptographic,
        });
    }
    authenticate(policy, metadata, &evidence)?;
    Ok(evidence)
}
