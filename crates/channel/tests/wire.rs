mod support;
use release_channel::authentication;
use release_channel::model;
use release_channel::wire;

#[test]
fn canonical_metadata_roundtrips_genesis_and_successor_exactly() {
    let mut f = support::Fixture::new();
    let first = f.plan();
    let bytes = first.bytes();
    assert_eq!(model::Metadata::from_bytes(bytes).unwrap(), f.metadata);
    assert_eq!(
        model::Metadata::from_bytes(bytes).unwrap().bytes().unwrap(),
        bytes
    );
    f.metadata.prior = Some(first.successor());
    f.metadata.generation = 2;
    f.sign();
    let next = f.plan();
    assert_eq!(
        model::Metadata::from_bytes(next.bytes()).unwrap(),
        f.metadata
    );
    assert_eq!(
        model::Metadata::from_bytes(next.bytes()).unwrap().prior,
        Some(first.successor())
    );
}

#[test]
fn canonical_metadata_rejects_all_truncations_trailing_and_bad_option() {
    let f = support::Fixture::new();
    let bytes = f.metadata.bytes().unwrap();
    for end in 0..bytes.len() {
        assert!(
            model::Metadata::from_bytes(&bytes[..end]).is_err(),
            "accepted truncation {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        model::Metadata::from_bytes(&trailing).unwrap_err(),
        model::Error::Encoding
    );
    let mut bad_option = bytes.clone();
    *bad_option.last_mut().unwrap() = 2;
    assert_eq!(
        model::Metadata::from_bytes(&bad_option).unwrap_err(),
        model::Error::Encoding
    );
    let mut bad_prefix = bytes;
    bad_prefix[0] ^= 1;
    assert_eq!(
        model::Metadata::from_bytes(&bad_prefix).unwrap_err(),
        model::Error::Encoding
    );
}

#[test]
fn canonical_metadata_rejects_oversized_counts_and_invalid_identities() {
    let f = support::Fixture::new();
    let mut bytes = f.metadata.bytes().unwrap();
    let count_offset = model::METADATA_DOMAIN.len() + 8 * 32 + 3 * 8;
    bytes[count_offset..count_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        model::Metadata::from_bytes(&bytes).unwrap_err(),
        model::Error::Bounds
    );
    assert_eq!(
        model::Metadata::from_bytes(&vec![0; wire::MAX_METADATA_BYTES + 1]).unwrap_err(),
        model::Error::Bounds
    );
    let mut invalid = f.metadata.clone();
    invalid.release = [0; 32];
    assert_eq!(
        model::Metadata::from_bytes(&invalid.bytes().unwrap()).unwrap_err(),
        model::Error::Identity
    );
    invalid = f.metadata;
    invalid.mirrors.reverse();
    assert_eq!(
        model::Metadata::from_bytes(&invalid.bytes().unwrap()).unwrap_err(),
        model::Error::Mirror
    );
}

#[test]
fn json_envelopes_are_strict_bounded_and_signature_width_exact() {
    let carrier = authentication::Carrier {
        public_key: [5; 32],
        signature: [42; 64],
        generation: 1,
    };
    let bytes = serde_json::to_vec(&vec![carrier]).unwrap();
    let decoded = wire::carriers(&bytes, wire::MAX_WIRE_BYTES).unwrap();
    assert_eq!(decoded[0].public_key, [5; 32]);
    assert_eq!(decoded[0].signature, [42; 64]);
    assert_eq!(
        wire::carriers(&bytes, bytes.len() - 1).unwrap_err(),
        model::Error::Bounds
    );
    for length in [63, 65] {
        let invalid = serde_json::json!([{ "public_key": vec![5; 32],
            "signature": vec![42; length], "generation": 1 }]);
        assert_eq!(
            wire::carriers(&serde_json::to_vec(&invalid).unwrap(), wire::MAX_WIRE_BYTES)
                .unwrap_err(),
            model::Error::Encoding
        );
    }
    let invalid = serde_json::json!([{ "public_key": vec![5; 32],
        "signature": vec![42; 64], "generation": 1, "secret": "never echo this" }]);
    assert_eq!(
        wire::carriers(&serde_json::to_vec(&invalid).unwrap(), wire::MAX_WIRE_BYTES).unwrap_err(),
        model::Error::Encoding
    );
}

#[test]
fn unknown_fields_and_oversized_metadata_are_not_wire_admission() {
    let f = support::Fixture::new();
    let mut object = serde_json::to_value(&f.metadata).unwrap();
    object["unexpected"] = serde_json::json!(true);
    let bytes = serde_json::to_vec(&object).unwrap();
    assert_eq!(
        wire::json_metadata(&bytes, wire::MAX_WIRE_BYTES).unwrap_err(),
        model::Error::Encoding
    );
    let mut metadata = f.metadata;
    metadata.mirrors = vec![[6; 32]; model::MAX_MIRRORS + 1];
    let bytes = serde_json::to_vec(&metadata).unwrap();
    assert_eq!(
        wire::json_metadata(&bytes, wire::MAX_WIRE_BYTES).unwrap_err(),
        model::Error::Bounds
    );
}
