use crate::{fixtures, setup, signing};
use release_channel::{authentication, model, planner};

pub struct Context<'a> {
    pub root: &'a std::path::Path,
    pub config: &'a setup::Config,
    pub secrets: &'a setup::Secrets,
    pub old: model::Policy,
    pub new: model::Policy,
    pub revoked: serde_json::Value,
    pub now: u64,
}

fn artifacts(
    context: &Context<'_>,
    phase: &str,
    generation: u64,
) -> anyhow::Result<(serde_json::Value, serde_json::Value)> {
    let release = [10 + generation as u8; 32];
    let ready = signing::signed(
        &context.secrets.artifact,
        b"onixos.channel.readiness.v1\0",
        serde_json::json!({
        "target":([42u8;32]),"release":release,"evidence":([12u8;32]),"issued":context.now-1,"expires":context.now+3600,"passed":true}),
    )?;
    let revoked = if generation < 4 {
        context.revoked.clone()
    } else {
        let list = if phase == "revoked" {
            vec![release]
        } else {
            Vec::new()
        };
        signing::signed(
            &context.secrets.artifact,
            b"onixos.channel.revocation.v1\0",
            serde_json::json!({
            "target":([42u8;32]),"issued":context.now,"expires":context.now+3600,"revoked":list}),
        )?
    };
    Ok((ready, revoked))
}

fn metadata(
    context: &Context<'_>,
    phase: &str,
    prior: Option<model::State>,
    policy: &model::Policy,
    artifacts: &(serde_json::Value, serde_json::Value),
) -> anyhow::Result<model::Metadata> {
    let generation = prior.map_or(1, |state| state.generation + 1);
    Ok(model::Metadata {
        channel: policy.channel,
        generation,
        release: [10 + generation as u8; 32],
        readiness: model::hash(&signing::payload(&artifacts.0)?),
        evidence: [12; 32],
        policy: authentication::policy_identity(policy)
            .map_err(|_| anyhow::anyhow!("policy identity"))?,
        delegation: [9; 32],
        revocation: model::hash(&signing::payload(&artifacts.1)?),
        trust: policy.trust,
        mirrors: policy.mirrors.clone(),
        prior,
        issued_at: context.now - 120,
        expires_at: if phase == "expired" {
            context.now - 1
        } else {
            context.now + 3600
        },
    })
}

fn validate(
    context: &Context<'_>,
    phase: &str,
    policy: &model::Policy,
    metadata: &model::Metadata,
    signatures: &[authentication::Carrier],
) -> anyhow::Result<()> {
    let evidence = authentication::verify(policy, metadata, signatures)
        .map_err(|_| anyhow::anyhow!("fixture real signature verification"))?;
    let old_carriers = signing::carriers(&context.old, metadata, &context.secrets.old)?;
    let old = authentication::verify(&context.old, metadata, &old_carriers);
    let rotation = if phase == "rotated" {
        Some(planner::Rotation {
            previous_policy: &context.old,
            previous_signatures: old
                .as_ref()
                .map_err(|_| anyhow::anyhow!("old fixture signature"))?,
        })
    } else {
        None
    };
    let facts = model::ReleaseFacts {
        release: metadata.release,
        readiness: metadata.readiness,
        evidence: metadata.evidence,
        readiness_issued: context.now - 1,
        readiness_expires: context.now + 3600,
        readiness_passed: true,
        revocation: metadata.revocation,
        revocation_issued: if metadata.generation >= 4 {
            context.now
        } else {
            context.now - 1
        },
        revocation_expires: context.now + 3600,
    };
    let result = planner::plan(&planner::Request {
        metadata,
        policy,
        facts: &facts,
        signatures: &evidence,
        expected: metadata.prior,
        rotation,
        now: context.now,
        supersession: None,
    });
    if phase == "expired" {
        anyhow::ensure!(
            matches!(result, Err(model::Error::Freeze)),
            "expiry alone must block core plan"
        );
    } else {
        result.map_err(|_| anyhow::anyhow!("all non-list fixture channel checks must pass"))?;
    }
    Ok(())
}

pub fn request(
    context: &Context<'_>,
    phase: &str,
    prior: Option<model::State>,
    generation: u64,
) -> anyhow::Result<model::State> {
    let artifacts = artifacts(context, phase, generation)?;
    let mut policy = if generation >= 3 {
        context.new.clone()
    } else {
        context.old.clone()
    };
    let revocation = model::hash(&signing::payload(&artifacts.1)?);
    for key in &mut policy.authentication.trusted_keys {
        key.currentness_ref =
            authentication::reference("release-channel.revocation.v1", revocation);
    }
    let metadata = metadata(context, phase, prior, &policy, &artifacts)?;
    anyhow::ensure!(
        metadata.generation == generation,
        "exact fixture generation"
    );
    let seeds = if generation >= 3 {
        &context.secrets.new
    } else {
        &context.secrets.old
    };
    let signatures = signing::carriers(&policy, &metadata, seeds)?;
    validate(context, phase, &policy, &metadata, &signatures)?;
    let previous = if phase == "rotated" {
        signing::carriers(&context.old, &metadata, &context.secrets.old)?
    } else {
        Vec::new()
    };
    crate::save(
        &context.root.join(format!("{phase}.json")),
        &serde_json::json!({"target":([42u8;32]),
        "metadata":metadata,"signatures":signatures,"previous_signatures":previous,
        "readiness":artifacts.0,"revocation":artifacts.1,"proof":""}),
    )?;
    if generation >= 4 {
        crate::save(
            &context.root.join(format!("{phase}-policy.json")),
            &fixtures::consumer_policy(
                context.root,
                context.config,
                context.secrets,
                &policy,
                None,
            ),
        )?;
    }
    Ok(model::State {
        channel: metadata.channel,
        generation,
        metadata: model::hash(&metadata.bytes().map_err(|_| anyhow::anyhow!("encoding"))?),
        trust: metadata.trust,
    })
}
