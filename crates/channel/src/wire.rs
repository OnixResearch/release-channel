use crate::authentication;
use crate::model;

pub const MAX_WIRE_BYTES: usize = 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 2048;

/// JSON envelopes only; metadata identity is always the versioned binary framing.
/// The byte cap and serde-json recursion limit are checked without echoing payloads.
pub fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, model::Error> {
    if max_bytes == 0 || max_bytes > MAX_WIRE_BYTES || bytes.len() > max_bytes {
        return Err(model::Error::Bounds);
    }
    serde_json::from_slice(bytes).map_err(|_| model::Error::Encoding)
}

pub fn carriers(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<Vec<authentication::Carrier>, model::Error> {
    let carriers: Vec<authentication::Carrier> = decode(bytes, max_bytes)?;
    if carriers.len() > model::MAX_SIGNATURES {
        return Err(model::Error::Bounds);
    }
    Ok(carriers)
}

/// Decode transport metadata, never JSON or a mutable discovery selector.
pub fn metadata(bytes: &[u8]) -> Result<model::Metadata, model::Error> {
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(model::Error::Bounds);
    }
    let remainder = bytes
        .strip_prefix(model::METADATA_DOMAIN)
        .ok_or(model::Error::Encoding)?;
    let mut cursor = Cursor {
        remaining: remainder,
    };
    let channel = cursor.id()?;
    let release = cursor.id()?;
    let readiness = cursor.id()?;
    let evidence = cursor.id()?;
    let policy = cursor.id()?;
    let delegation = cursor.id()?;
    let revocation = cursor.id()?;
    let trust = cursor.id()?;
    let generation = cursor.number()?;
    let issued_at = cursor.number()?;
    let expires_at = cursor.number()?;
    let count = usize::try_from(cursor.number()?).map_err(|_| model::Error::Bounds)?;
    if count == 0 || count > model::MAX_MIRRORS {
        return Err(model::Error::Bounds);
    }
    let mut mirrors = Vec::with_capacity(count);
    for _ in 0..count {
        mirrors.push(cursor.id()?);
    }
    let prior = match cursor.read::<1>()?[0] {
        0 => None,
        1 => Some(model::State {
            channel: cursor.id()?,
            generation: cursor.number()?,
            metadata: cursor.id()?,
            trust: cursor.id()?,
        }),
        _ => return Err(model::Error::Encoding),
    };
    if !cursor.remaining.is_empty() {
        return Err(model::Error::Encoding);
    }
    let metadata = model::Metadata {
        channel,
        generation,
        release,
        readiness,
        evidence,
        policy,
        delegation,
        revocation,
        trust,
        mirrors,
        prior,
        issued_at,
        expires_at,
    };
    validate_metadata(&metadata)?;
    Ok(metadata)
}

pub fn json_metadata(bytes: &[u8], max_bytes: usize) -> Result<model::Metadata, model::Error> {
    let metadata: model::Metadata = decode(bytes, max_bytes)?;
    validate_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_metadata(metadata: &model::Metadata) -> Result<(), model::Error> {
    if metadata.mirrors.is_empty() || metadata.mirrors.len() > model::MAX_MIRRORS {
        return Err(model::Error::Bounds);
    }
    if [
        metadata.channel,
        metadata.release,
        metadata.readiness,
        metadata.evidence,
        metadata.policy,
        metadata.delegation,
        metadata.revocation,
        metadata.trust,
    ]
    .iter()
    .chain(metadata.mirrors.iter())
    .any(|id| !model::nonzero(id))
    {
        return Err(model::Error::Identity);
    }
    if metadata.generation == 0 || metadata.expires_at <= metadata.issued_at {
        return Err(model::Error::Encoding);
    }
    if metadata.mirrors.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(model::Error::Mirror);
    }
    if let Some(prior) = metadata.prior
        && (prior.channel != metadata.channel
            || prior.generation == 0
            || !model::nonzero(&prior.metadata)
            || !model::nonzero(&prior.trust))
    {
        return Err(model::Error::Identity);
    }
    Ok(())
}

struct Cursor<'a> {
    remaining: &'a [u8],
}
impl Cursor<'_> {
    fn read<const N: usize>(&mut self) -> Result<[u8; N], model::Error> {
        let field = self.remaining.get(..N).ok_or(model::Error::Encoding)?;
        let array = field.try_into().map_err(|_| model::Error::Encoding)?;
        self.remaining = &self.remaining[N..];
        Ok(array)
    }

    fn number(&mut self) -> Result<u64, model::Error> {
        Ok(u64::from_le_bytes(self.read()?))
    }

    fn id(&mut self) -> Result<model::Id, model::Error> {
        let id = self.read()?;
        if !model::nonzero(&id) {
            return Err(model::Error::Identity);
        }
        Ok(id)
    }
}
