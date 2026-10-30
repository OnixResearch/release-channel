mod cases;
mod fixtures;
mod publish;
mod recovery;
#[path = "recovery-auth.rs"]
mod recovery_auth;
#[path = "recovery-transport.rs"]
mod recovery_transport;
mod setup;
mod signing;
use release_channel::model;

pub fn read<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> anyhow::Result<T> {
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, 1_048_577), &mut bytes)?;
    anyhow::ensure!(bytes.len() <= 1_048_576, "bounded pilot input");
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn save<T: serde::Serialize>(path: &std::path::Path, value: &T) -> anyhow::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec(value)?)?;
    file.sync_all()?;
    Ok(())
}

pub fn random() -> anyhow::Result<model::Id> {
    let mut bytes = [0; 32];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut bytes)?;
    Ok(bytes)
}

fn execute() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(args.len() == 4, "prepare ROOT CONFIG | publish ROOT PHASE");
    let root = std::path::Path::new(&args[2]);
    anyhow::ensure!(root.is_absolute(), "absolute pilot root");
    match args[1].as_str() {
        "prepare" => setup::prepare(root, std::path::Path::new(&args[3])),
        "publish" => publish::run(root, &args[3]),
        "recover" if args[3] == "run" => recovery::run(root),
        _ => anyhow::bail!("unsupported pilot operation"),
    }
}

fn main() -> std::process::ExitCode {
    match execute() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("actual channel pilot refused: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
