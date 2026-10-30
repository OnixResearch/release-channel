use release_channel::model;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub oci: serde_json::Value,
    pub mirror: serde_json::Value,
    pub witness_program: String,
    pub witness_policy: String,
    pub witness_secret: String,
    pub witness_signer: String,
    pub index_program: String,
    pub mirror_directory: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Secrets {
    pub old: [model::Id; 2],
    pub new: [model::Id; 2],
    pub artifact: model::Id,
    pub admin: model::Id,
    pub server: model::Id,
    pub writer: model::Id,
}

pub fn namespace() -> release_channel_index::model::Namespace {
    release_channel_index::model::Namespace {
        channel: "experimental-release".into(),
        platform: "onixos-local".into(),
        track: "pilot".into(),
    }
}

pub fn exchange(
    root: &std::path::Path,
    operation: release_channel_index::model::Operation,
    key: &model::Id,
) -> anyhow::Result<release_channel_index::model::Snapshot> {
    let config: Config = crate::read(&root.join("runtime.json"))?;
    let secrets: Secrets = crate::read(&root.join("secrets.json"))?;
    let request = release_channel_index::crypto::authenticate(
        &ed25519_dalek::SigningKey::from_bytes(key),
        release_channel_index::model::Request {
            namespace: namespace(),
            challenge: crate::random()?,
            operation,
        },
    )
    .map_err(anyhow::Error::msg)?;
    let mut command = std::process::Command::new(&config.index_program);
    command
        .arg("serve")
        .arg(root.join("index-root"))
        .arg(root.join("index-config.json"))
        .env_clear();
    let response = release_channel_index::client::exchange(
        &mut command,
        &request,
        std::time::Duration::from_secs(10),
    )
    .map_err(anyhow::Error::msg)?;
    let pin = ed25519_dalek::SigningKey::from_bytes(&secrets.server)
        .verifying_key()
        .to_bytes();
    release_channel_index::client::verify_reply(&pin, &request.request, &response, 0)
        .map_err(anyhow::Error::msg)
}

pub fn prepare(root: &std::path::Path, config: &std::path::Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.is_absolute() && !root.exists(),
        "new absolute fixture root required"
    );
    let config: Config = crate::read(config)?;
    std::fs::create_dir(root)?;
    std::fs::set_permissions(root, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let secrets = Secrets {
        old: [crate::random()?, crate::random()?],
        new: [crate::random()?, crate::random()?],
        artifact: crate::random()?,
        admin: crate::random()?,
        server: crate::random()?,
        writer: crate::random()?,
    };
    crate::save(&root.join("runtime.json"), &config)?;
    crate::save(&root.join("secrets.json"), &secrets)?;
    crate::save(&root.join("writer.json"), &secrets.writer)?;
    let admin = ed25519_dalek::SigningKey::from_bytes(&secrets.admin)
        .verifying_key()
        .to_bytes();
    crate::save(
        &root.join("index-config.json"),
        &serde_json::json!({"admin":admin,"server_secret":secrets.server}),
    )?;
    release_channel_index::provider::Provider::initialize(
        &root.join("index-root"),
        admin,
        ed25519_dalek::SigningKey::from_bytes(&secrets.server),
    )
    .map_err(anyhow::Error::msg)?;
    let writer = ed25519_dalek::SigningKey::from_bytes(&secrets.writer)
        .verifying_key()
        .to_bytes();
    exchange(
        root,
        release_channel_index::model::Operation::Enroll { writer },
        &secrets.admin,
    )?;
    crate::fixtures::generate(root, &config, &secrets)?;
    let executable = std::env::current_exe()?;
    let mut hooks = serde_json::Map::new();
    for phase in [
        "first", "second", "rotated", "control", "expired", "revoked", "split", "recovery",
    ] {
        let hook = root.join(format!("publish-{phase}"));
        let quote =
            |path: &std::path::Path| format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"));
        // Recovery first resolves an actual orphan and then publishes its authenticated successor.
        let operation = if phase == "recovery" {
            "recover".to_owned()
        } else {
            "publish".to_owned()
        };
        let argument = if phase == "recovery" {
            "supersede"
        } else {
            phase
        };
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\nexec {} {operation} {} {argument}\n",
                quote(&executable),
                quote(root)
            ),
        )?;
        std::fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        hooks.insert(
            phase.into(),
            serde_json::Value::String(hook.to_string_lossy().into()),
        );
    }
    crate::save(&root.join("hooks.json"), &hooks)
}
