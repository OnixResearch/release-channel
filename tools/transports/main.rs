use release_channel_transports::pilot;

fn main() -> std::process::ExitCode {
    match execute() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: release-channel-transport-pilot /absolute/operator-config.json\n\
Requires existing authorized OCI repository (POST blob initiation, PUT SHA256 completion, PUT/GET OCI manifest, GET digest), \
static HTTPS metadata namespace (PUT <blake3>.metadata and GET, opaque versioned binary MIME), explicit bounded-http generated \
profiles denying retries/redirects, DER trust roots and optional Authorization environment variable \
per independently constructed upload/readback endpoint. Config fields: metadata, oci_upload, \
oci_readback, mirror_upload, mirror_readback. Endpoint fields: identity [32 bytes], url, repository \
(OCI only), profile (generated JSON object), roots [absolute DER paths], authorization_env. \
This pilot does not claim channel CAS, witness acceptance, or governed publication.".into());
    }
    let path = pilot::absolute(&args[1])?;
    let input = std::fs::read(path).map_err(|_| "operator configuration unavailable")?;
    let config = serde_json::from_slice(&input).map_err(|_| "invalid operator configuration")?;
    pilot::run(config)
}
