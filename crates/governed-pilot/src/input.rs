use release_channel::{authentication, model, planner};
use release_channel_transports::pilot;
use std::path;

#[derive(serde::Deserialize)]
pub struct Runtime {
    pub oci: pilot::Endpoint,
    pub mirror: pilot::Endpoint,
    pub witness_program: String,
    pub witness_policy: String,
    pub witness_secret: String,
    pub witness_signer: String,
}

#[derive(serde::Deserialize)]
pub struct Policy {
    pub target: model::Id,
    pub channel: model::Policy,
    pub artifact_key: model::Id,
}

#[derive(serde::Deserialize)]
struct Signed {
    payload: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct Request {
    target: model::Id,
    metadata: model::Metadata,
    signatures: Vec<authentication::Carrier>,
    readiness: Signed,
    revocation: Signed,
}

#[derive(serde::Deserialize)]
struct Readiness {
    target: model::Id,
    release: model::Id,
    evidence: model::Id,
    issued: u64,
    expires: u64,
    passed: bool,
}

#[derive(serde::Deserialize)]
struct Revocation {
    target: model::Id,
    issued: u64,
    expires: u64,
    revoked: Vec<model::Id>,
}

pub fn read<T: serde::de::DeserializeOwned>(path: &path::Path) -> anyhow::Result<T> {
    let name = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 operator path"))?;
    let bytes = pilot::read_bounded(name, 1_048_576).map_err(anyhow::Error::msg)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn verify<T: serde::de::DeserializeOwned>(
    signed: &Signed,
    domain: &[u8],
    key: &model::Id,
) -> anyhow::Result<T> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(key)?;
    let signature = ed25519_dalek::Signature::from_slice(&signed.signature)?;
    let mut bytes = Vec::with_capacity(domain.len() + signed.payload.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&signed.payload);
    key.verify_strict(&bytes, &signature)?;
    Ok(serde_json::from_slice(&signed.payload)?)
}

pub fn plan(root: &path::Path, now: u64) -> anyhow::Result<planner::Plan> {
    let policy: Policy = read(&root.join("policy.json"))?;
    let request: Request = read(&root.join("first.json"))?;
    let ready: Readiness = verify(
        &request.readiness,
        b"onixos.channel.readiness.v1\0",
        &policy.artifact_key,
    )?;
    let revoked: Revocation = verify(
        &request.revocation,
        b"onixos.channel.revocation.v1\0",
        &policy.artifact_key,
    )?;
    anyhow::ensure!(
        request.target == policy.target
            && ready.target == policy.target
            && revoked.target == policy.target,
        "signed target mismatch"
    );
    anyhow::ensure!(
        !revoked.revoked.contains(&request.metadata.release),
        "release revoked"
    );
    anyhow::ensure!(
        model::hash(&request.readiness.payload) == request.metadata.readiness
            && model::hash(&request.revocation.payload) == request.metadata.revocation,
        "signed artifact identity mismatch"
    );
    let facts = model::ReleaseFacts {
        release: ready.release,
        readiness: model::hash(&request.readiness.payload),
        evidence: ready.evidence,
        readiness_passed: ready.passed,
        readiness_issued: ready.issued,
        readiness_expires: ready.expires,
        revocation: model::hash(&request.revocation.payload),
        revocation_issued: revoked.issued,
        revocation_expires: revoked.expires,
    };
    let signatures =
        authentication::verify(&policy.channel, &request.metadata, &request.signatures)
            .map_err(|error| anyhow::anyhow!("channel authentication: {error:?}"))?;
    planner::plan(&planner::Request {
        metadata: &request.metadata,
        policy: &policy.channel,
        facts: &facts,
        signatures: &signatures,
        expected: request.metadata.prior,
        rotation: None,
        supersession: None,
        now,
    })
    .map_err(|error| anyhow::anyhow!("publication plan: {error:?}"))
}
