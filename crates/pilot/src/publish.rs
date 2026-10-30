use crate::setup;
use release_channel::model;
use release_channel_transports::pilot;
use release_channel_transports::store;
use release_channel_witness::provider;

fn transport(config: &setup::Config, bytes: &[u8]) -> anyhow::Result<()> {
    let oci: pilot::Endpoint = serde_json::from_value(config.oci.clone())?;
    let mirror: pilot::Endpoint = serde_json::from_value(config.mirror.clone())?;
    let mut upload = pilot::oci(&oci).map_err(anyhow::Error::msg)?;
    let mut push = pilot::mirror(&mirror, true).map_err(anyhow::Error::msg)?;
    let identity = model::hash(bytes);
    for writer in [
        &mut upload as &mut dyn store::Store,
        &mut push as &mut dyn store::Store,
    ] {
        anyhow::ensure!(
            writer
                .put(bytes)
                .map_err(|_| anyhow::anyhow!("actual metadata upload"))?
                == identity,
            "uploaded identity mismatch"
        );
    }
    let mut reader = pilot::oci(&oci).map_err(anyhow::Error::msg)?;
    let mut pull = pilot::mirror(&mirror, false).map_err(anyhow::Error::msg)?;
    for readback in [
        &mut reader as &mut dyn store::Store,
        &mut pull as &mut dyn store::Store,
    ] {
        anyhow::ensure!(
            readback
                .get(&identity)
                .map_err(|_| anyhow::anyhow!("independent readback"))?
                == bytes,
            "transport split"
        );
    }
    Ok(())
}

pub(crate) fn current(root: &std::path::Path, metadata: &model::Metadata) -> anyhow::Result<()> {
    let secrets: setup::Secrets = crate::read(&root.join("secrets.json"))?;
    let before = setup::exchange(
        root,
        release_channel_index::model::Operation::Query,
        &secrets.writer,
    )?;
    let claim = claim(metadata)?;
    if release_channel_index::client::require_current(&before, &claim).is_ok() {
        return Ok(());
    }
    let staged = if before.pending.is_some() {
        before
    } else {
        match setup::exchange(
            root,
            release_channel_index::model::Operation::Reserve {
                expected_revision: before.revision,
                claim: claim.clone(),
            },
            &secrets.writer,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let observed = setup::exchange(
                    root,
                    release_channel_index::model::Operation::Query,
                    &secrets.writer,
                )?;
                if release_channel_index::client::require_current(&observed, &claim).is_ok() {
                    return Ok(());
                }
                anyhow::ensure!(observed.pending.is_some(), "reserve unresolved: {error}");
                observed
            }
        }
    };
    let pending = staged
        .pending
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing reservation"))?;
    anyhow::ensure!(
        pending.claim == claim
            && pending.status == release_channel_index::model::PendingStatus::Reserved,
        "different or orphan reservation requires explicit reconciliation"
    );
    let committed = match setup::exchange(
        root,
        release_channel_index::model::Operation::Commit {
            expected_revision: staged.revision,
            reservation: pending.reservation,
            expected_predecessor: claim.predecessor,
        },
        &secrets.writer,
    ) {
        Ok(snapshot) => snapshot,
        Err(_) => setup::exchange(
            root,
            release_channel_index::model::Operation::Query,
            &secrets.writer,
        )?,
    };
    release_channel_index::client::require_current(&committed, &claim).map_err(anyhow::Error::msg)
}

pub(crate) fn claim(
    metadata: &model::Metadata,
) -> anyhow::Result<release_channel_index::model::Claim> {
    Ok(release_channel_index::model::Claim {
        generation: metadata.generation,
        digest: model::hash(
            &metadata
                .bytes()
                .map_err(|_| anyhow::anyhow!("metadata framing"))?,
        ),
        predecessor: metadata.prior.map(|state| state.metadata),
    })
}

fn proof(config: &setup::Config, identity: model::Id) -> anyhow::Result<String> {
    let mut witness =
        release_channel_witness::sigsum::Process::new(release_channel_witness::sigsum::Config {
            executable: config.witness_program.clone().into(),
            policy: config.witness_policy.clone().into(),
            secret_key: Some(config.witness_secret.clone().into()),
            timeout: std::time::Duration::from_secs(30),
        })
        .map_err(|_| anyhow::anyhow!("actual witness unavailable"))?;
    let statement = release_channel_witness::types::Statement {
        metadata_hash: identity,
        signer: config.witness_signer.clone(),
    };
    let evidence = provider::Provider::append(&mut witness, &statement)
        .map_err(|_| anyhow::anyhow!("actual Sigsum append not proven"))?;
    let verified = provider::Provider::verify(&mut witness, &statement, &evidence.proof)
        .map_err(|_| anyhow::anyhow!("actual Sigsum proof invalid"))?;
    anyhow::ensure!(verified == evidence, "provider readback differs");
    Ok(evidence.proof)
}

pub fn run(root: &std::path::Path, phase: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        [
            "first", "second", "rotated", "control", "expired", "revoked", "split", "recovery"
        ]
        .contains(&phase),
        "exact pilot phase required"
    );
    let config: setup::Config = crate::read(&root.join("runtime.json"))?;
    let path = root.join(format!("{phase}.json"));
    let mut request: serde_json::Value = crate::read(&path)?;
    let metadata: model::Metadata = serde_json::from_value(request["metadata"].clone())?;
    let bytes = metadata
        .bytes()
        .map_err(|_| anyhow::anyhow!("canonical binary metadata"))?;
    let identity = model::hash(&bytes);
    transport(&config, &bytes)?;
    request["proof"] = serde_json::Value::String(proof(&config, identity)?);
    let pending = root.join(format!("{phase}.pending"));
    crate::save(&pending, &request)?;
    std::fs::rename(pending, &path)?;
    std::fs::File::open(root)?.sync_all()?;
    current(root, &metadata)?;
    if phase == "split" {
        let corrupt = std::path::Path::new(&config.mirror_directory)
            .join(format!("{}.metadata", model::hex(&identity)));
        anyhow::ensure!(
            corrupt.is_absolute() && corrupt.is_file(),
            "explicit owned mirror failure-injection object missing"
        );
        let mut changed = bytes;
        changed[0] ^= 1;
        std::fs::write(corrupt, changed)?;
    }
    println!(
        "actual-publisher phase={phase}; experimental-common-admin; deployment-authority=none"
    );
    Ok(())
}
