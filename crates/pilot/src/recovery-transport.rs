use crate::setup;
use release_channel_index::client;
use release_channel_index::crypto;
use release_channel_index::model;

pub fn query(root: &std::path::Path) -> anyhow::Result<(model::Request, model::SignedReply)> {
    exchange(root, model::Operation::Query, false)
}

/// Suppress only the actual provider's stdout, after its durable operation executes.
pub fn lose(root: &std::path::Path, operation: model::Operation) -> anyhow::Result<()> {
    anyhow::ensure!(
        exchange(root, operation, true).is_err(),
        "lost response was delivered"
    );
    Ok(())
}

fn exchange(
    root: &std::path::Path,
    operation: model::Operation,
    discard: bool,
) -> anyhow::Result<(model::Request, model::SignedReply)> {
    let config: setup::Config = crate::read(&root.join("runtime.json"))?;
    let secrets: setup::Secrets = crate::read(&root.join("secrets.json"))?;
    let signed = crypto::authenticate(
        &ed25519_dalek::SigningKey::from_bytes(&secrets.writer),
        model::Request {
            namespace: setup::namespace(),
            challenge: crate::random()?,
            operation,
        },
    )
    .map_err(anyhow::Error::msg)?;
    let mut command = if discard {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "exec \"$@\" >/dev/null", "discard-provider-reply"]);
        command.arg(&config.index_program);
        command
    } else {
        std::process::Command::new(&config.index_program)
    };
    command
        .arg("serve")
        .arg(root.join("index-root"))
        .arg(root.join("index-config.json"))
        .env_clear();
    let reply = client::exchange(&mut command, &signed, std::time::Duration::from_secs(10))
        .map_err(anyhow::Error::msg)?;
    let pin = ed25519_dalek::SigningKey::from_bytes(&secrets.server)
        .verifying_key()
        .to_bytes();
    client::verify_reply(&pin, &signed.request, &reply, 0).map_err(anyhow::Error::msg)?;
    Ok((signed.request, reply))
}
