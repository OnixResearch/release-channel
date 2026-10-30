use release_channel_transports::{http, store};

fn profile() -> bounded_http::core::RequestProfiles {
    let json = r#"{
      "schema_version":1,"profile_id":"test.v1",
      "destination":{"id":"test.v1","hosts":[{"kind":"exact","value":"api.example.test"}],
        "ports":[443],"address":{"allow_private":false,"allow_loopback":false,
        "allow_link_local":false,"allow_multicast":false,"allow_unspecified":false}},
      "tls":{"id":"test.v1","minimum_version":"1.3"},
      "redirect":{"max_hops":0,"allow_cross_authority":false,"forward_credentials_same_authority":false},
      "retry":{"max_attempts":1,"delay_ms":0},
      "deadlines":{"resolve_ms":100,"connect_ms":100,"tls_ms":100,"first_byte_ms":100,
        "body_ms":100,"idle_ms":100,"total_ms":1000},
      "resources":{"request_body_bytes":1024,"wire_response_bytes":1024,"decoded_response_bytes":1024,
        "retained_prefix_bytes":1024,"header_bytes":4096,"header_count":32,"chunk_bytes":1024,
        "decompression_ratio":4,"resolver_candidates":1,"connections":1,"credential_bytes":1024},
      "non_claims":["does not authorize egress","does not establish remote trust or response truth",
        "does not prove operation idempotency","does not replace consumer credentials or release policy"]
    }"#;
    bounded_http::parse_generated_profile(json).unwrap().request
}

fn shell(responses: &[&str]) -> http::Http {
    let peer = "93.184.216.34:443".parse().unwrap();
    let scripts = responses
        .iter()
        .map(|response| bounded_http::MemoryConnectionScript {
            selected: peer,
            actual: peer,
            response: response.as_bytes().to_vec(),
            failure: None,
            read_failure: None,
        })
        .collect();
    let ports = bounded_http::ClientPorts {
        resolver: Box::new(bounded_http::MemoryResolver::new(vec![
            Ok(vec![peer]);
            responses.len()
        ])),
        transport: Box::new(bounded_http::MemoryTransport::new(scripts)),
        tls: Box::new(bounded_http::MemoryTls {
            failure: None,
            version: bounded_http::core::TlsVersion::Tls13,
        }),
        clock: Box::new(bounded_http::MemoryClock::new(vec![0])),
        timer: Box::new(bounded_http::MemoryTimer::default()),
        credentials: Box::new(bounded_http::MemoryCredentials::new(Vec::new())),
    };
    const PENDING_RECEIPTS: usize = 4;
    http::Http::new(
        profile(),
        Vec::new(),
        Box::new(bounded_http::Client::new(ports)),
        PENDING_RECEIPTS,
    )
    .unwrap()
}

fn oci(responses: &[&str]) -> store::Oci {
    store::Oci::new(
        [1; 32],
        "https://api.example.test".into(),
        "metadata".into(),
        shell(responses),
    )
    .unwrap()
}

fn mirror(responses: &[&str], writable: bool) -> store::Static {
    store::Static::new(
        [2; 32],
        "https://api.example.test/metadata".into(),
        writable,
        shell(responses),
    )
    .unwrap()
}

#[test]
fn oci_upload_and_independent_digest_readback() {
    let mut publisher = oci(&[
        "HTTP/1.1 202 Accepted\r\nLocation: /v2/metadata/blobs/uploads/session?_state=x%3D\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
    ]);
    let id = store::Store::put(&mut publisher, b"abc").unwrap();
    let body = serde_json::json!({"schemaVersion":2,
        "mediaType":"application/vnd.oci.image.manifest.v1+json",
        "artifactType":"application/vnd.onix.release-channel.metadata.v1",
        "config":{"mediaType":"application/vnd.onix.release-channel.metadata.v1",
        "digest":format!("sha256:{}", release_channel_transports::hex(&release_channel_transports::sha256(b"abc"))),
        "size":3},"layers":[]}).to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let mut reader = oci(&[&response, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"]);
    assert_eq!(store::Store::get(&mut reader, &id).unwrap(), b"abc");
    assert_eq!(id, release_channel_transports::digest(b"abc"));
}

#[test]
fn static_put_and_independent_readback() {
    let mut publisher = mirror(&["HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"], true);
    let id = store::Store::put(&mut publisher, b"abc").unwrap();
    let mut reader = mirror(&["HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"], false);
    assert_eq!(store::Store::get(&mut reader, &id).unwrap(), b"abc");
}

#[test]
fn upload_location_cannot_exfiltrate_credentials() {
    let mut publisher = oci(&[
        "HTTP/1.1 202 Accepted\r\nLocation: https://attacker.test/v2/metadata/blobs/uploads/session\r\nContent-Length: 0\r\n\r\n",
    ]);
    assert_eq!(
        store::Store::put(&mut publisher, b"abc"),
        Err(release_channel_transports::Error::Policy)
    );
}

#[test]
fn missing_digest_bytes_and_denied_authority_fail_closed() {
    let id = release_channel_transports::digest(b"abc");
    let mut corrupt = mirror(&["HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz"], false);
    assert_eq!(
        store::Store::get(&mut corrupt, &id),
        Err(release_channel_transports::Error::Digest)
    );
    let mut denied = oci(&["HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"]);
    assert_eq!(
        store::Store::put(&mut denied, b"abc"),
        Err(release_channel_transports::Error::Status(401))
    );
    let mut reader = mirror(&[], false);
    assert_eq!(
        store::Store::put(&mut reader, b"abc"),
        Err(release_channel_transports::Error::Policy)
    );
}

#[test]
fn short_upload_response_is_uncertain_not_success() {
    let mut publisher = mirror(
        &["HTTP/1.1 201 Created\r\nContent-Length: 3\r\n\r\nx"],
        true,
    );
    assert!(matches!(
        store::Store::put(&mut publisher, b"abc"),
        Err(release_channel_transports::Error::Uncertain
            | release_channel_transports::Error::Incomplete)
    ));
}

fn manifest_response(bytes: &[u8], artifact: &str) -> String {
    let body = serde_json::json!({"schemaVersion":2,
        "mediaType":"application/vnd.oci.image.manifest.v1+json", "artifactType":artifact,
        "config":{"mediaType":"application/vnd.onix.release-channel.metadata.v1",
        "digest":format!("sha256:{}", release_channel_transports::hex(&release_channel_transports::sha256(bytes))),
        "size":bytes.len()},"layers":[]}).to_string();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
}

#[test]
fn manifest_cannot_change_channel_identity_or_artifact_kind() {
    let id = release_channel_transports::digest(b"abc");
    let response = manifest_response(b"xyz", "application/vnd.onix.release-channel.metadata.v1");
    let mut reader = oci(&[&response, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz"]);
    assert_eq!(
        store::Store::get(&mut reader, &id),
        Err(release_channel_transports::Error::Digest)
    );
    let wrong = manifest_response(b"abc", "application/example-unrelated");
    let mut reader = oci(&[&wrong]);
    assert_eq!(
        store::Store::get(&mut reader, &id),
        Err(release_channel_transports::Error::Protocol)
    );
}
