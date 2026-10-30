use crate::{cases, setup, signing};
use release_channel::model;

pub fn consumer_policy(
    root: &std::path::Path,
    config: &setup::Config,
    secrets: &setup::Secrets,
    policy: &model::Policy,
    previous: Option<&model::Policy>,
) -> serde_json::Value {
    serde_json::json!({"target":([42u8;32]),"channel":policy,"previous":previous,
        "artifact_key":ed25519_dalek::SigningKey::from_bytes(&secrets.artifact).verifying_key().to_bytes(),
        "namespace":setup::namespace(),"index_key":ed25519_dalek::SigningKey::from_bytes(&secrets.server).verifying_key().to_bytes(),
        "query_key":root.join("writer.json"),"index_program":config.index_program,
        "index_arguments":["serve",root.join("index-root"),root.join("index-config.json")],
        "oci":config.oci,"mirror":config.mirror,"witness_program":config.witness_program,
        "witness_policy":config.witness_policy,"witness_signer":config.witness_signer})
}

pub fn generate(
    root: &std::path::Path,
    config: &setup::Config,
    secrets: &setup::Secrets,
) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let revoked = signing::signed(
        &secrets.artifact,
        b"onixos.channel.revocation.v1\0",
        serde_json::json!({
        "target":([42u8;32]),"issued":now-1,"expires":now+3600,"revoked":[]}),
    )?;
    let revocation = model::hash(&signing::payload(&revoked)?);
    let mut mirrors: Vec<model::Id> = vec![
        serde_json::from_value(config.oci["identity"].clone())?,
        serde_json::from_value(config.mirror["identity"].clone())?,
    ];
    mirrors.sort_unstable();
    let old = signing::policy(&secrets.old, revocation, [4; 32], mirrors.clone(), now);
    let new = signing::policy(&secrets.new, revocation, [44; 32], mirrors, now);
    crate::save(
        &root.join("policy.json"),
        &consumer_policy(root, config, secrets, &old, None),
    )?;
    crate::save(
        &root.join("rotated-policy.json"),
        &consumer_policy(root, config, secrets, &new, Some(&old)),
    )?;
    let context = cases::Context {
        root,
        config,
        secrets,
        old,
        new,
        revoked,
        now,
    };
    let first = cases::request(&context, "first", None, 1)?;
    let second = cases::request(&context, "second", Some(first), 2)?;
    let rotated = cases::request(&context, "rotated", Some(second), 3)?;
    let control = cases::request(&context, "control", Some(rotated), 4)?;
    for phase in ["expired", "revoked", "split"] {
        cases::request(&context, phase, Some(control), 5)?;
    }
    Ok(())
}
