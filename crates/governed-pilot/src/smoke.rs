use crate::{control, input, witness};
use release_channel::{model, publication};
use release_channel_transports::{governance, pilot};
use std::{fs, path, time};

fn publisher(
    config: &input::Runtime,
    root: &path::Path,
) -> anyhow::Result<governance::GovernedPublisher> {
    Ok(governance::GovernedPublisher::new(
        model::hash(b"governed-pilot.publisher"),
        vec![
            Box::new(pilot::oci(&config.oci).map_err(anyhow::Error::msg)?),
            Box::new(pilot::mirror(&config.mirror, true).map_err(anyhow::Error::msg)?),
        ],
        Box::new(control::Control::open(root, true)?),
    ))
}

fn receiver(config: &input::Runtime, root: &path::Path) -> anyhow::Result<governance::Receiver> {
    Ok(governance::Receiver {
        id: model::hash(b"governed-pilot.independent-receiver"),
        stores: vec![
            Box::new(pilot::oci(&config.oci).map_err(anyhow::Error::msg)?),
            Box::new(pilot::mirror(&config.mirror, false).map_err(anyhow::Error::msg)?),
        ],
        control: Box::new(control::Control::open(root, false)?),
    })
}

pub fn run(fixtures: &path::Path, root: &path::Path) -> anyhow::Result<()> {
    let now = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)?
        .as_secs();
    let config: input::Runtime = input::read(&fixtures.join("runtime.json"))?;
    let plan = input::plan(fixtures, now)?;
    anyhow::ensure!(
        plan.expected().is_none(),
        "smoke requires initial signed plan"
    );
    anyhow::ensure!(
        plan.identity() != plan.successor().metadata,
        "regression requires plan/digest divergence"
    );
    anyhow::ensure!(
        config.oci.identity != config.mirror.identity,
        "distinct mirror identities required"
    );
    control::Control::enroll(root, plan.metadata().channel)?;
    let mut log = witness::Witness::enroll(&config, root, plan.witness())?;
    let mut publisher = publisher(&config, root)?;
    let mut receiver = receiver(&config, root)?;
    let outcome = publication::execute(&plan, &mut publisher, &mut receiver, &mut log, now);
    let receipt = match outcome {
        publication::Outcome::Published(receipt) => receipt,
        other => anyhow::bail!("actual governed publication did not succeed: {other:?}"),
    };
    publication::check_receipt(&plan, &receipt)
        .map_err(|error| anyhow::anyhow!("receipt: {error:?}"))?;
    anyhow::ensure!(receipt.state == plan.successor(), "published state differs");
    fs::write(
        root.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt)?,
    )?;
    fs::File::open(root.join("receipt.json"))?.sync_all()?;
    fs::File::open(root)?.sync_all()?;
    drop((publisher, receiver, log));
    negative(&config, root, &plan, now)?;
    println!(
        "governed-publication-exact metadata={} plan={}; stale-plan-conflict=preserved; durable-current-cas=verified; witness=actual-sigsum; administration=experimental-common-admin; deployment-authority=none",
        model::hex(&plan.successor().metadata),
        model::hex(&plan.identity())
    );
    Ok(())
}

fn negative(
    config: &input::Runtime,
    root: &path::Path,
    plan: &release_channel::planner::Plan,
    now: u64,
) -> anyhow::Result<()> {
    let mut publisher = publisher(config, root)?;
    let mut receiver = receiver(config, root)?;
    let mut log = witness::Witness::reopen(config, root, plan.witness())?;
    let before = fs::read(root.join("current.json"))?;
    let result = publication::execute(plan, &mut publisher, &mut receiver, &mut log, now);
    anyhow::ensure!(
        matches!(
            result,
            publication::Outcome::Blocked(model::Error::Conflict)
        ),
        "stale expected state was not rejected: {result:?}"
    );
    // Bypass execute's early current read to exercise the actual locked CAS
    // rejection, not merely planner or orchestration conflict checking.
    publication::Publisher::stage(&mut publisher, plan)
        .map_err(|error| anyhow::anyhow!("stale immutable staging: {error:?}"))?;
    anyhow::ensure!(
        publication::Publisher::commit(&mut publisher, plan) == publication::Commit::NotApplied,
        "durable CAS accepted stale expected state"
    );
    anyhow::ensure!(
        publication::Publisher::commit(&mut publisher, plan) == publication::Commit::NotApplied,
        "unstaged commit guard failed"
    );
    anyhow::ensure!(
        fs::read(root.join("current.json"))? == before,
        "conflict changed durable bytes"
    );
    let state = publication::Readback::current(&mut receiver, &plan.metadata().channel)
        .map_err(|error| anyhow::anyhow!("reopened current: {error:?}"))?;
    anyhow::ensure!(
        state == Some(plan.successor()),
        "reopened exact current differs"
    );
    for mirror in &plan.metadata().mirrors {
        let bytes =
            publication::Readback::metadata(&mut receiver, mirror, &plan.successor().metadata)
                .map_err(|error| anyhow::anyhow!("reopened transport: {error:?}"))?;
        anyhow::ensure!(bytes == plan.bytes(), "reopened exact metadata differs");
    }
    Ok(())
}
