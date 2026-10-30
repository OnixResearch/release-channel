use std::fs;
fn run() -> release_channel_index::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: experiment NEW_ROOT PROVIDER_BINARY PILOT_BINARY".into());
    }
    let root = std::path::Path::new(&args[1]);
    private_directory(root)?;
    let provider = fs::canonicalize(&args[2]).map_err(|e| e.to_string())?;
    let pilot = fs::canonicalize(&args[3]).map_err(|e| e.to_string())?;
    for (label, seed) in [("process-host-a", 41), ("process-host-b", 61)] {
        let host = root.join(label);
        private_directory(&host)?;
        let admin = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let server = ed25519_dalek::SigningKey::from_bytes(&[seed + 1; 32]);
        let config = host.join("server.json");
        let store = host.join("retained");
        fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "admin": admin.verifying_key().to_bytes(), "server_secret": server.to_bytes(),
            }))
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        private_file(&config)?;
        let status = std::process::Command::new(&provider)
            .arg("init")
            .arg(&store)
            .arg(&config)
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("provider initialization failed".into());
        }
        let client = host.join("client.json");
        fs::write(&client, serde_json::to_vec(&serde_json::json!({
            "program": provider, "args": ["serve", store.to_str().ok_or("non-UTF8 root")?, config.to_str().ok_or("non-UTF8 config")?],
            "server_pin": server.verifying_key().to_bytes(), "admin_secret": admin.to_bytes(), "writer_secret": ed25519_dalek::SigningKey::from_bytes(&[seed + 2; 32]).to_bytes(),
            "namespace": {"channel":"experimental", "platform":"linux", "track":label},
            "consumer_store":host.join("consumer.json"),
        })).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        private_file(&client)?;
        let output = std::process::Command::new(&pilot)
            .arg(&client)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        println!(
            "{}",
            serde_json::json!({"host_label": label, "receipt": serde_json::from_slice::<serde_json::Value>(&output.stdout).map_err(|e| e.to_string())?,
            "common_os_and_administrator": true, "deterministic_test_keys_only": true})
        );
    }
    Ok(())
}

fn private_directory(path: &std::path::Path) -> release_channel_index::Result<()> {
    let mut builder = fs::DirBuilder::new();
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path).map_err(|e| e.to_string())
}

fn private_file(path: &std::path::Path) -> release_channel_index::Result<()> {
    fs::set_permissions(
        path,
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("index experiment: {error}");
        std::process::exit(1);
    }
}
