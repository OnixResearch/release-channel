use crate::{http, store};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub identity: [u8; 32],
    pub url: String,
    pub repository: Option<String>,
    pub profile: serde_json::Value,
    pub roots: Vec<String>,
    pub authorization_env: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub metadata: String,
    pub oci_upload: Endpoint,
    pub oci_readback: Endpoint,
    pub mirror_upload: Endpoint,
    pub mirror_readback: Endpoint,
}

struct Credentials {
    variable: Option<String>,
}

impl bounded_http::CredentialPort for Credentials {
    fn resolve(
        &mut self,
        slot: &bounded_http::core::CredentialSlotId,
        maximum_bytes: u64,
    ) -> Result<bounded_http::SecretValue, bounded_http::CredentialFailure> {
        if slot.as_str() != "operator-authorization" {
            return Err(bounded_http::CredentialFailure::Missing);
        }
        let variable = self
            .variable
            .as_ref()
            .ok_or(bounded_http::CredentialFailure::Missing)?;
        let value =
            std::env::var(variable).map_err(|_| bounded_http::CredentialFailure::Unavailable)?;
        bounded_http::SecretValue::new(value.into_bytes(), maximum_bytes)
    }
}

pub fn absolute(path: &str) -> Result<std::path::PathBuf, String> {
    let path = std::path::PathBuf::from(path);
    if !path.is_absolute() {
        return Err("operator paths must be absolute".into());
    }
    Ok(path)
}

/// Reads at most the explicit byte limit plus one overflow-detection byte.
pub fn read_bounded(path: &str, byte_limit: u64) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(absolute(path)?).map_err(|_| "operator input unavailable")?;
    let bound = byte_limit
        .checked_add(1)
        .ok_or("invalid operator input byte limit")?;
    let mut limited = std::io::Read::take(file, bound);
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut limited, &mut bytes)
        .map_err(|_| "operator input read failed")?;
    if bytes.len() as u64 > byte_limit {
        return Err("operator input exceeds byte limit".into());
    }
    Ok(bytes)
}

fn shell(endpoint: &Endpoint) -> Result<http::Http, String> {
    let profile = bounded_http::parse_generated_profile(&endpoint.profile.to_string())
        .map_err(|_| "invalid explicit HTTP profile")?;
    const ROOT_COUNT_LIMIT: usize = 16;
    const CERTIFICATE_BYTES_LIMIT: u64 = 65_536;
    if endpoint.roots.is_empty() || endpoint.roots.len() > ROOT_COUNT_LIMIT {
        return Err("explicit trust anchor count outside bound".into());
    }
    let certificates = endpoint
        .roots
        .iter()
        .map(|path| read_bounded(path, CERTIFICATE_BYTES_LIMIT))
        .collect::<Result<Vec<_>, String>>()?;
    let tls = bounded_http::RustlsTls::from_der_certificates(certificates)
        .map_err(|_| "invalid explicit DER trust anchors")?;
    let secrets = if endpoint.authorization_env.is_some() {
        vec![
            bounded_http::core::SecretHeaderSlot::new("authorization", "operator-authorization")
                .map_err(|_| "invalid credential slot")?,
        ]
    } else {
        Vec::new()
    };
    let client = bounded_http::Client::new(bounded_http::ClientPorts {
        resolver: Box::new(bounded_http::SystemResolver::default()),
        transport: Box::new(bounded_http::TcpTransport),
        tls: Box::new(tls),
        clock: Box::new(bounded_http::SystemClock::new()),
        timer: Box::new(bounded_http::ThreadTimer),
        credentials: Box::new(Credentials {
            variable: endpoint.authorization_env.clone(),
        }),
    });
    const PENDING_RECEIPTS: usize = 4;
    http::Http::new(profile.request, secrets, Box::new(client), PENDING_RECEIPTS)
        .map_err(|_| "profile must deny redirects and retries".into())
}

/// Builds a fresh OCI client using only this endpoint's explicit authority.
pub fn oci(endpoint: &Endpoint) -> Result<store::Oci, String> {
    store::Oci::new(
        endpoint.identity,
        endpoint.url.clone(),
        endpoint
            .repository
            .clone()
            .ok_or("OCI repository required")?,
        shell(endpoint)?,
    )
    .map_err(|_| "invalid OCI authority".into())
}

/// Builds a fresh static metadata client; receivers must pass `false`.
pub fn mirror(endpoint: &Endpoint, writable: bool) -> Result<store::Static, String> {
    store::Static::new(
        endpoint.identity,
        endpoint.url.clone(),
        writable,
        shell(endpoint)?,
    )
    .map_err(|_| "invalid static metadata namespace".into())
}

/// Performs real uploads and independent GETs. Does not claim governed channel commit.
pub fn run(config: Config) -> Result<(), String> {
    const METADATA_LIMIT: u64 = 1_048_576;
    let bytes = read_bounded(&config.metadata, METADATA_LIMIT)?;
    let mut upload = oci(&config.oci_upload)?;
    let mut readback = oci(&config.oci_readback)?;
    let mut put = mirror(&config.mirror_upload, true)?;
    let mut get = mirror(&config.mirror_readback, false)?;
    if config.oci_upload.identity != config.oci_readback.identity
        || config.mirror_upload.identity != config.mirror_readback.identity
        || config.oci_upload.identity == config.mirror_upload.identity
    {
        return Err("two distinct mirror identities must match their readers".into());
    }
    let result = transfer(&bytes, &mut upload, &mut readback)
        .and_then(|_| transfer(&bytes, &mut put, &mut get));
    for shell in [
        &mut upload.http,
        &mut readback.http,
        &mut put.http,
        &mut get.http,
    ] {
        for receipt in shell.take_receipts() {
            println!(
                "{}",
                bounded_http::render_receipt(&receipt).map_err(|_| "receipt rendering failed")?
            );
        }
    }
    result?;
    println!(
        "immutable-readback-exact blake3:{} sha256:{}; channel-commit=not-attempted",
        crate::hex(&crate::digest(&bytes)),
        crate::hex(&crate::sha256(&bytes))
    );
    Ok(())
}

fn transfer(
    bytes: &[u8],
    upload: &mut dyn store::Store,
    reader: &mut dyn store::Store,
) -> Result<(), String> {
    let id = upload
        .put(bytes)
        .map_err(|e| format!("upload failed: {e:?}"))?;
    let observed = reader
        .get(&id)
        .map_err(|e| format!("independent readback failed: {e:?}"))?;
    if observed != bytes {
        return Err("independent readback differs from exact input bytes".into());
    }
    Ok(())
}
