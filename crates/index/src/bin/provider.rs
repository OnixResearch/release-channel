use std::fs;
use std::io;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    admin: [u8; 32],
    server_secret: [u8; 32],
}

fn run() -> release_channel_index::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: provider init|serve ROOT CONFIG.json".into());
    }
    let config: Config = serde_json::from_slice(&fs::read(&args[3]).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let key = ed25519_dalek::SigningKey::from_bytes(&config.server_secret);
    let root = std::path::Path::new(&args[2]);
    match args[1].as_str() {
        "init" => {
            release_channel_index::provider::Provider::initialize(root, config.admin, key)?;
        }
        "serve" => {
            let provider =
                release_channel_index::provider::Provider::open(root, config.admin, key)?;
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(
                &mut std::io::Read::take(
                    io::stdin(),
                    (release_channel_index::model::MAX_FRAME + 1) as u64,
                ),
                &mut bytes,
            )
            .map_err(|e| e.to_string())?;
            if bytes.len() > release_channel_index::model::MAX_FRAME {
                return Err("request exceeds bound".into());
            }
            let request: release_channel_index::model::SignedRequest =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            let response = provider.handle(&request)?;
            println!(
                "{}",
                serde_json::to_string(&response).map_err(|e| e.to_string())?
            );
        }
        _ => return Err("unsupported provider command".into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("index provider: {error}");
        std::process::exit(1);
    }
}
