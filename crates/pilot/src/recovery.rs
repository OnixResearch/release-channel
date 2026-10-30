use crate::publish;
use crate::recovery_auth;
use crate::recovery_transport;
use crate::setup;
use release_channel::authentication;
use release_channel::model;
use release_channel::planner;
use release_channel::supersession;
use release_channel_index::model as index;

fn snapshot(root: &std::path::Path) -> anyhow::Result<index::Snapshot> {
    Ok(recovery_transport::query(root)?.1.reply.snapshot)
}

fn lost_reserve(root: &std::path::Path) -> anyhow::Result<model::Metadata> {
    let value: serde_json::Value = crate::read(&root.join("first.json"))?;
    let metadata: model::Metadata = serde_json::from_value(value["metadata"].clone())?;
    let before = snapshot(root)?;
    anyhow::ensure!(
        before.highest.is_none(),
        "recovery requires freshly prepared dedicated root"
    );
    let claim = publish::claim(&metadata)?;
    recovery_transport::lose(
        root,
        index::Operation::Reserve {
            expected_revision: before.revision,
            claim: claim.clone(),
        },
    )?;
    let staged = snapshot(root)?;
    anyhow::ensure!(
        staged.revision == before.revision + 1
            && staged.pending.as_ref().is_some_and(|p| p.claim == claim),
        "reserve was not durable"
    );
    publish::current(root, &metadata)?;
    publish::run(root, "first")?;
    println!("recovery=lost-reserve; exact-reservation-finalized");
    Ok(metadata)
}

fn lost_commit(root: &std::path::Path) -> anyhow::Result<model::Metadata> {
    let value: serde_json::Value = crate::read(&root.join("second.json"))?;
    let metadata: model::Metadata = serde_json::from_value(value["metadata"].clone())?;
    let secrets: setup::Secrets = crate::read(&root.join("secrets.json"))?;
    let staged = setup::exchange(
        root,
        index::Operation::Reserve {
            expected_revision: snapshot(root)?.revision,
            claim: publish::claim(&metadata)?,
        },
        &secrets.writer,
    )?;
    recovery_transport::lose(
        root,
        index::Operation::Commit {
            expected_revision: staged.revision,
            reservation: staged
                .pending
                .ok_or_else(|| anyhow::anyhow!("reservation"))?
                .reservation,
            expected_predecessor: metadata.prior.map(|s| s.metadata),
        },
    )?;
    let committed = snapshot(root)?;
    release_channel_index::client::require_current(&committed, &publish::claim(&metadata)?)
        .map_err(anyhow::Error::msg)?;
    publish::current(root, &metadata)?;
    anyhow::ensure!(
        snapshot(root)? == committed,
        "commit replay mutated external history"
    );
    publish::run(root, "second")?;
    println!("recovery=lost-commit; exact-committed-claim-recognized");
    Ok(metadata)
}

fn resolve(root: &std::path::Path, metadata: &model::Metadata) -> anyhow::Result<u64> {
    let secrets: setup::Secrets = crate::read(&root.join("secrets.json"))?;
    let claim = publish::claim(metadata)?;
    let staged = setup::exchange(
        root,
        index::Operation::Reserve {
            expected_revision: snapshot(root)?.revision,
            claim: claim.clone(),
        },
        &secrets.writer,
    )?;
    let reservation = staged
        .pending
        .ok_or_else(|| anyhow::anyhow!("reservation"))?
        .reservation;
    let orphan = setup::exchange(
        root,
        index::Operation::Orphan {
            expected_revision: staged.revision,
            reservation,
        },
        &secrets.writer,
    )?;
    anyhow::ensure!(
        publish::current(root, metadata).is_err(),
        "orphan silently finalized"
    );
    let resolved = setup::exchange(
        root,
        index::Operation::ResolveOrphan {
            expected_revision: orphan.revision,
            reservation,
        },
        &secrets.writer,
    )?;
    anyhow::ensure!(
        resolved.pending.is_none()
            && resolved.highest == Some(claim)
            && resolved.committed == orphan.committed,
        "resolution lowered durable highwater"
    );
    Ok(resolved.revision)
}

fn supersede(root: &std::path::Path, prior: model::Metadata) -> anyhow::Result<()> {
    let secrets: setup::Secrets = crate::read(&root.join("secrets.json"))?;
    let policy_value: serde_json::Value = crate::read(&root.join("policy.json"))?;
    let policy: model::Policy = serde_json::from_value(policy_value["channel"].clone())?;
    let mut request: serde_json::Value = crate::read(&root.join("second.json"))?;
    let predecessor = model::State {
        channel: prior.channel,
        generation: prior.generation,
        metadata: publish::claim(&prior)?.digest,
        trust: prior.trust,
    };
    let mut metadata = prior;
    metadata.prior = Some(predecessor);
    metadata.generation = predecessor.generation + 1;
    let facts = recovery_auth::facts(&request, &metadata)?;
    let carriers = recovery_auth::signatures(&policy, &metadata, &secrets.old)?;
    let signatures = authentication::verify(&policy, &metadata, &carriers)
        .map_err(|e| anyhow::anyhow!("orphan signatures: {e:?}"))?;
    planner::plan(&planner::Request {
        metadata: &metadata,
        policy: &policy,
        facts: &facts,
        signatures: &signatures,
        expected: Some(predecessor),
        rotation: None,
        supersession: None,
        now: metadata.issued_at + 120,
    })
    .map_err(|e| anyhow::anyhow!("orphan must be genuinely plannable: {e:?}"))?;
    let revision = resolve(root, &metadata)?;
    let (query, reply) = recovery_transport::query(root)?;
    let pin = recovery_auth::pin(&secrets);
    let namespace = setup::namespace();
    let proof = supersession::Supersession::verify(
        &supersession::Context {
            pin: &pin,
            namespace: &namespace,
            minimum_revision: revision,
            predecessor,
        },
        &query,
        &reply,
    )
    .map_err(|e| anyhow::anyhow!("supersession proof: {e:?}"))?;
    finish(root, &mut request, &mut metadata, &policy, &proof)?;
    request["supersession"] = serde_json::json!({"request":query,"reply":reply});
    crate::save(&root.join("recovery.json"), &request)?;
    publish::run(root, "recovery")?;
    println!("recovery=orphan; strict-supersession-planned-and-published");
    Ok(())
}

fn finish(
    root: &std::path::Path,
    request: &mut serde_json::Value,
    metadata: &mut model::Metadata,
    policy: &model::Policy,
    proof: &supersession::Supersession,
) -> anyhow::Result<()> {
    let secrets: setup::Secrets = crate::read(&root.join("secrets.json"))?;
    let facts = recovery_auth::facts(request, metadata)?;
    // Equality with the abandoned highwater is never sufficient, even with a valid proof.
    let carriers = recovery_auth::signatures(policy, metadata, &secrets.old)?;
    let signatures = authentication::verify(policy, metadata, &carriers)
        .map_err(|e| anyhow::anyhow!("signature: {e:?}"))?;
    let denied = planner::plan(&planner::Request {
        metadata,
        policy,
        facts: &facts,
        signatures: &signatures,
        expected: metadata.prior,
        rotation: None,
        supersession: Some(proof),
        now: metadata.issued_at + 120,
    });
    anyhow::ensure!(
        matches!(denied, Err(model::Error::Rollback)),
        "non-strict supersession accepted"
    );
    metadata.generation = proof
        .highest()
        .generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("generation overflow"))?;
    let carriers = recovery_auth::signatures(policy, metadata, &secrets.old)?;
    let signatures = authentication::verify(policy, metadata, &carriers)
        .map_err(|e| anyhow::anyhow!("signature: {e:?}"))?;
    let mut plan_request = planner::Request {
        metadata,
        policy,
        facts: &facts,
        signatures: &signatures,
        expected: metadata.prior,
        rotation: None,
        supersession: None,
        now: metadata.issued_at + 120,
    };
    anyhow::ensure!(
        matches!(planner::plan(&plan_request), Err(model::Error::Rollback)),
        "plain planner allowed gap"
    );
    plan_request.supersession = Some(proof);
    planner::plan(&plan_request)
        .map_err(|e| anyhow::anyhow!("authenticated recovery planning: {e:?}"))?;
    request["metadata"] = serde_json::to_value(metadata)?;
    request["signatures"] = serde_json::to_value(carriers)?;
    Ok(())
}

pub fn run(root: &std::path::Path) -> anyhow::Result<()> {
    lost_reserve(root)?;
    let second = lost_commit(root)?;
    supersede(root, second)
}
