pub fn message<T: serde::Serialize>(domain: &[u8], value: &T) -> crate::Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let mut bytes = Vec::with_capacity(domain.len() + encoded.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

pub fn sign<T: serde::Serialize>(
    key: &ed25519_dalek::SigningKey,
    domain: &[u8],
    value: &T,
) -> crate::Result<Vec<u8>> {
    Ok(ed25519_dalek::Signer::sign(key, &message(domain, value)?)
        .to_bytes()
        .to_vec())
}

pub fn verify<T: serde::Serialize>(
    key: &[u8; 32],
    domain: &[u8],
    value: &T,
    signature: &[u8],
) -> crate::Result<()> {
    let public = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|e| e.to_string())?;
    let signature = ed25519_dalek::Signature::from_slice(signature).map_err(|e| e.to_string())?;
    public
        .verify_strict(&message(domain, value)?, &signature)
        .map_err(|e| e.to_string())
}

pub fn authenticate(
    key: &ed25519_dalek::SigningKey,
    request: crate::model::Request,
) -> crate::Result<crate::model::SignedRequest> {
    request.namespace.validate()?;
    let signature = sign(key, b"release-channel-index/request/v1\0", &request)?;
    Ok(crate::model::SignedRequest { request, signature })
}

pub fn reservation(request: &crate::model::SignedRequest) -> crate::Result<[u8; 32]> {
    Ok(<sha2::Sha256 as sha2::Digest>::digest(message(
        b"release-channel-index/reservation/v1\0",
        request,
    )?)
    .into())
}

pub fn request_digest(request: &crate::model::Request) -> crate::Result<[u8; 32]> {
    Ok(<sha2::Sha256 as sha2::Digest>::digest(message(
        b"release-channel-index/request-digest/v1\0",
        request,
    )?)
    .into())
}
