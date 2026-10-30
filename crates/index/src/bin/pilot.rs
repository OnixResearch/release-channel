use release_channel_index::client;
use release_channel_index::crypto;
use std::fs;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    program: String,
    args: Vec<String>,
    server_pin: [u8; 32],
    admin_secret: [u8; 32],
    writer_secret: [u8; 32],
    namespace: release_channel_index::model::Namespace,
    consumer_store: String,
}

fn call(
    config: &Config,
    operation: release_channel_index::model::Operation,
    nonce: u8,
    admin: bool,
) -> release_channel_index::Result<release_channel_index::model::Snapshot> {
    let key = ed25519_dalek::SigningKey::from_bytes(if admin {
        &config.admin_secret
    } else {
        &config.writer_secret
    });
    let request = crypto::authenticate(
        &key,
        release_channel_index::model::Request {
            namespace: config.namespace.clone(),
            challenge: [nonce; 32],
            operation,
        },
    )?;
    let mut command = std::process::Command::new(&config.program);
    command.args(&config.args);
    let reply = client::exchange(&mut command, &request, std::time::Duration::from_secs(10))?;
    client::verify_reply(&config.server_pin, &request.request, &reply, 1)
}

fn publish(
    config: &Config,
    claim: &release_channel_index::model::Claim,
    revision: u64,
    nonce: u8,
) -> release_channel_index::Result<release_channel_index::model::Snapshot> {
    let staged = call(
        config,
        release_channel_index::model::Operation::Reserve {
            expected_revision: revision,
            claim: claim.clone(),
        },
        nonce,
        false,
    )?;
    if client::require_current(&staged, claim).is_ok() {
        return Err("staged claim falsely current".into());
    }
    // Consumer-owned finalCAS surrogate: this pilot owns only this explicit store file.
    let existing = match fs::read(&config.consumer_store) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    let predecessor = existing
        .as_ref()
        .map(|bytes| serde_json::from_slice::<release_channel_index::model::Claim>(bytes))
        .transpose()
        .map_err(|e| e.to_string())?
        .map(|claim| claim.digest);
    if predecessor != claim.predecessor {
        return Err("consumer predecessor CAS failed; reservation retained".into());
    }
    fs::write(
        &config.consumer_store,
        serde_json::to_vec(claim).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let pending = staged.pending.ok_or("reservation missing")?;
    call(
        config,
        release_channel_index::model::Operation::Commit {
            expected_revision: staged.revision,
            reservation: pending.reservation,
            expected_predecessor: predecessor,
        },
        nonce + 1,
        false,
    )
}

fn run() -> release_channel_index::Result<()> {
    let path = std::env::args().nth(1).ok_or("usage: pilot CONFIG.json")?;
    let config: Config = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if std::path::Path::new(&config.consumer_store).exists() {
        return Err("pilot requires absent explicit consumer file".into());
    }
    call(
        &config,
        release_channel_index::model::Operation::Enroll {
            writer: ed25519_dalek::SigningKey::from_bytes(&config.writer_secret)
                .verifying_key()
                .to_bytes(),
        },
        1,
        true,
    )?;
    let first = release_channel_index::model::Claim {
        generation: 1,
        digest: [11; 32],
        predecessor: None,
    };
    let state = publish(&config, &first, 1, 2)?;
    client::require_current(&state, &first)?;
    let backup = fs::read(&config.consumer_store).map_err(|e| e.to_string())?;
    let second = release_channel_index::model::Claim {
        generation: 2,
        digest: [22; 32],
        predecessor: Some(first.digest),
    };
    let state = publish(&config, &second, state.revision, 4)?;
    client::require_current(&state, &second)?;
    fs::write(&config.consumer_store, backup).map_err(|e| e.to_string())?;
    let restored: release_channel_index::model::Claim =
        serde_json::from_slice(&fs::read(&config.consumer_store).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let external = call(
        &config,
        release_channel_index::model::Operation::Query,
        6,
        false,
    )?;
    if client::require_current(&external, &restored).is_ok() {
        return Err("whole consumer rollback accepted".into());
    }
    let third = release_channel_index::model::Claim {
        generation: 3,
        digest: [33; 32],
        predecessor: Some(second.digest),
    };
    let staged = call(
        &config,
        release_channel_index::model::Operation::Reserve {
            expected_revision: external.revision,
            claim: third.clone(),
        },
        7,
        false,
    )?;
    let orphan = call(
        &config,
        release_channel_index::model::Operation::Orphan {
            expected_revision: staged.revision,
            reservation: staged.pending.ok_or("missing staged claim")?.reservation,
        },
        8,
        false,
    )?;
    if client::require_current(&orphan, &third).is_ok()
        || client::require_current(&orphan, &second).is_ok()
    {
        return Err("orphan did not block current-state admission".into());
    }
    let recovered = recover(&config, &orphan, &second)?;
    println!(
        "{{\"policy\":\"EXPERIMENTAL\",\"signed_query\":true,\"whole_consumer_rollback_rejected\":true,\"orphan_blocks\":true,\"orphan_recovery_retains_highwater\":true,\"admin_independence_proven\":false,\"physical_host_independence_proven\":false,\"production_ready\":false,\"revision\":{}}}",
        recovered.revision
    );
    Ok(())
}

fn recover(
    config: &Config,
    orphan: &release_channel_index::model::Snapshot,
    prior: &release_channel_index::model::Claim,
) -> release_channel_index::Result<release_channel_index::model::Snapshot> {
    let pending = orphan.pending.as_ref().ok_or("missing orphan")?;
    let resolved = call(
        config,
        release_channel_index::model::Operation::ResolveOrphan {
            expected_revision: orphan.revision,
            reservation: pending.reservation,
        },
        9,
        false,
    )?;
    if resolved.highest != orphan.highest || client::require_current(&resolved, prior).is_ok() {
        return Err("resolution erased highwater or admitted stale head".into());
    }
    if call(
        config,
        release_channel_index::model::Operation::Reserve {
            expected_revision: resolved.revision,
            claim: pending.claim.clone(),
        },
        10,
        false,
    )
    .is_ok()
    {
        return Err("resolved generation reused".into());
    }
    // Explicit consumer-owned reconciliation restores the known committed head, not admission.
    fs::write(
        &config.consumer_store,
        serde_json::to_vec(prior).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let claim = release_channel_index::model::Claim {
        generation: 4,
        digest: [44; 32],
        predecessor: Some(prior.digest),
    };
    let current = publish(config, &claim, resolved.revision, 11)?;
    client::require_current(&current, &claim)?;
    Ok(current)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("index pilot: {error}");
        std::process::exit(1);
    }
}
