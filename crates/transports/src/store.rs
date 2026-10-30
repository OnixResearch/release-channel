use crate::http;
use bounded_http::core;

/// Channel BLAKE3 identity is distinct from OCI's SHA256 blob identity.
const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const METADATA_TYPE: &str = "application/vnd.onix.release-channel.metadata.v1";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u8,
    media_type: String,
    artifact_type: String,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: String,
    size: usize,
}

/// Immutable objects in an existing operator-authorized namespace.
pub trait Store {
    fn identity(&self) -> [u8; 32];
    fn put(&mut self, bytes: &[u8]) -> Result<[u8; 32], crate::Error>;
    fn get(&mut self, id: &[u8; 32]) -> Result<Vec<u8>, crate::Error>;
}

pub struct Oci {
    id: [u8; 32],
    origin: String,
    repository: String,
    pub http: http::Http,
}

impl Oci {
    /// Origin is HTTPS authority only; repository is an existing registry namespace.
    pub fn new(
        id: [u8; 32],
        origin: String,
        repository: String,
        http: http::Http,
    ) -> Result<Self, crate::Error> {
        validate_origin(&origin)?;
        if repository.is_empty()
            || repository.split('/').any(|segment| {
                segment.is_empty()
                    || segment == "."
                    || segment == ".."
                    || !segment.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                    })
            })
        {
            return Err(crate::Error::Policy);
        }
        Ok(Self {
            id,
            origin,
            repository,
            http,
        })
    }

    fn manifest(&self, id: &[u8; 32]) -> String {
        format!(
            "{}/v2/{}/manifests/metadata-{}",
            self.origin,
            self.repository,
            crate::hex(id)
        )
    }

    fn upload_url(&self, location: &str) -> Result<String, crate::Error> {
        let prefix = format!("/v2/{}/blobs/uploads/", self.repository);
        let relative = if location.starts_with('/') {
            location
        } else {
            location
                .strip_prefix(&self.origin)
                .ok_or(crate::Error::Policy)?
        };
        let path = relative.split('?').next().ok_or(crate::Error::Policy)?;
        let session = path.strip_prefix(&prefix).ok_or(crate::Error::Policy)?;
        if session.is_empty()
            || !session
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(crate::Error::Policy);
        }
        let url = format!("{}{}", self.origin, relative);
        core::CanonicalUrl::parse_https(&url).map_err(|_| crate::Error::Policy)?;
        Ok(url)
    }

    fn upload(&mut self, bytes: &[u8]) -> Result<Descriptor, crate::Error> {
        let digest = format!("sha256:{}", crate::hex(&crate::sha256(bytes)));
        let start = format!("{}/v2/{}/blobs/uploads/", self.origin, self.repository);
        let response = self
            .http
            .request(core::HttpMethod::Post, &start, &[], Vec::new())?;
        require_status(response.status, &[202])?;
        let location = response
            .headers
            .iter()
            .find(|h| h.name().as_str() == "location")
            .ok_or(crate::Error::Protocol)?
            .value();
        let mut upload = self.upload_url(location)?;
        upload.push(if upload.contains('?') { '&' } else { '?' });
        upload.push_str(&format!("digest={digest}"));
        let response = self.http.request(
            core::HttpMethod::Put,
            &upload,
            bytes,
            vec![header("content-type", "application/octet-stream")?],
        )?;
        require_status(response.status, &[201])?;
        Ok(Descriptor {
            media_type: METADATA_TYPE.into(),
            digest,
            size: bytes.len(),
        })
    }
}

impl Store for Oci {
    fn identity(&self) -> [u8; 32] {
        self.id
    }

    fn put(&mut self, bytes: &[u8]) -> Result<[u8; 32], crate::Error> {
        let id = crate::digest(bytes);
        let config = self.upload(bytes)?;
        let manifest = Manifest {
            schema_version: 2,
            media_type: MANIFEST_TYPE.into(),
            artifact_type: METADATA_TYPE.into(),
            config,
            layers: Vec::new(),
        };
        let encoded = serde_json::to_vec(&manifest).map_err(|_| crate::Error::Protocol)?;
        let response = self.http.request(
            core::HttpMethod::Put,
            &self.manifest(&id),
            &encoded,
            vec![header("content-type", MANIFEST_TYPE)?],
        )?;
        require_status(response.status, &[201])?;
        Ok(id)
    }

    fn get(&mut self, id: &[u8; 32]) -> Result<Vec<u8>, crate::Error> {
        let response = self.http.request(
            core::HttpMethod::Get,
            &self.manifest(id),
            &[],
            vec![header("accept", MANIFEST_TYPE)?],
        )?;
        require_status(response.status, &[200])?;
        let manifest: Manifest =
            serde_json::from_slice(&response.bytes).map_err(|_| crate::Error::Protocol)?;
        if manifest.schema_version != 2
            || manifest.media_type != MANIFEST_TYPE
            || manifest.artifact_type != METADATA_TYPE
            || !manifest.layers.is_empty()
            || manifest.config.media_type != METADATA_TYPE
        {
            return Err(crate::Error::Protocol);
        }
        let encoded = manifest
            .config
            .digest
            .strip_prefix("sha256:")
            .ok_or(crate::Error::Protocol)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(crate::Error::Protocol);
        }
        let url = format!(
            "{}/v2/{}/blobs/{}",
            self.origin, self.repository, manifest.config.digest
        );
        let response = self
            .http
            .request(core::HttpMethod::Get, &url, &[], Vec::new())?;
        require_status(response.status, &[200])?;
        if response.bytes.len() != manifest.config.size
            || crate::hex(&crate::sha256(&response.bytes)) != encoded
        {
            return Err(crate::Error::Digest);
        }
        verify(id, response.bytes)
    }
}

/// Static HTTPS metadata namespace on an existing cache/mirror server.
/// PUT is the chosen uploader protocol; no Nix store or narinfo mutation is implied.
pub struct Static {
    id: [u8; 32],
    base: String,
    writable: bool,
    pub http: http::Http,
}

impl Static {
    pub fn new(
        id: [u8; 32],
        base: String,
        writable: bool,
        http: http::Http,
    ) -> Result<Self, crate::Error> {
        core::CanonicalUrl::parse_https(&base).map_err(|_| crate::Error::Policy)?;
        if base.contains('?')
            || base.contains('#')
            || base.ends_with('/')
            || base.contains("..")
            || base.contains('%')
        {
            return Err(crate::Error::Policy);
        }
        Ok(Self {
            id,
            base,
            writable,
            http,
        })
    }

    fn object(&self, id: &[u8; 32]) -> String {
        format!("{}/{}.metadata", self.base, crate::hex(id))
    }
}

impl Store for Static {
    fn identity(&self) -> [u8; 32] {
        self.id
    }

    fn put(&mut self, bytes: &[u8]) -> Result<[u8; 32], crate::Error> {
        if !self.writable {
            return Err(crate::Error::Policy);
        }
        let id = crate::digest(bytes);
        let response = self.http.request(
            core::HttpMethod::Put,
            &self.object(&id),
            bytes,
            vec![header("content-type", METADATA_TYPE)?],
        )?;
        require_status(response.status, &[200, 201, 204])?;
        Ok(id)
    }

    fn get(&mut self, id: &[u8; 32]) -> Result<Vec<u8>, crate::Error> {
        let response =
            self.http
                .request(core::HttpMethod::Get, &self.object(id), &[], Vec::new())?;
        require_status(response.status, &[200])?;
        verify(id, response.bytes)
    }
}

fn validate_origin(origin: &str) -> Result<(), crate::Error> {
    let authority = origin
        .strip_prefix("https://")
        .ok_or(crate::Error::Policy)?;
    if authority.contains(['/', '?', '#']) || authority.is_empty() {
        return Err(crate::Error::Policy);
    }
    core::CanonicalUrl::parse_https(origin).map_err(|_| crate::Error::Policy)?;
    Ok(())
}

fn require_status(status: u16, allowed: &[u16]) -> Result<(), crate::Error> {
    if allowed.contains(&status) {
        Ok(())
    } else {
        Err(crate::Error::Status(status))
    }
}

fn verify(id: &[u8; 32], bytes: Vec<u8>) -> Result<Vec<u8>, crate::Error> {
    if &crate::digest(&bytes) == id {
        Ok(bytes)
    } else {
        Err(crate::Error::Digest)
    }
}

fn header(name: &str, value: &str) -> Result<core::PublicHeader, crate::Error> {
    core::PublicHeader::new(name, value).map_err(|_| crate::Error::Request)
}
