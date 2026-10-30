mod support;
use release_channel::authentication;
use release_channel::model;
use release_channel::planner;

fn install(f: &mut support::Fixture, seed: u8) {
    for (index, trusted) in f.policy.authentication.trusted_keys.iter_mut().enumerate() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed + index as u8; 32]);
        trusted.key_identity =
            artifact_auth_ed25519::public_key_identity(key.verifying_key().as_bytes());
    }
    f.sign();
}

fn carriers(
    policy: &model::Policy,
    metadata: &model::Metadata,
    seed: u8,
) -> Vec<authentication::Carrier> {
    policy
        .authentication
        .trusted_keys
        .iter()
        .enumerate()
        .map(|(index, trusted)| {
            let key = ed25519_dalek::SigningKey::from_bytes(&[seed + index as u8; 32]);
            let statement = artifact_auth_core::ArtifactStatement {
                schema: artifact_auth_core::STATEMENT_SCHEMA_V1.into(),
                scope: authentication::scope(metadata).unwrap(),
                producer_id: trusted.producer_id.clone(),
                key_id: trusted.key_id.clone(),
                key_identity: trusted.key_identity.clone(),
            };
            let bytes = artifact_auth_core::canonical_statement_bytes(&statement).unwrap();
            let signature = ed25519_dalek::Signer::sign(&key, &bytes);
            authentication::Carrier {
                public_key: key.verifying_key().to_bytes(),
                signature: signature.to_bytes(),
                generation: trusted.generation,
            }
        })
        .collect()
}

#[test]
fn real_threshold_signatures_reject_tampering_and_duplicate_keys() {
    let mut f = support::Fixture::new();
    install(&mut f, 40);
    let valid = carriers(&f.policy, &f.metadata, 40);
    f.signatures = authentication::verify(&f.policy, &f.metadata, &valid).unwrap();
    assert_eq!(f.plan().successor().generation, 1);
    let mut tampered = valid.clone();
    tampered[0].signature[0] ^= 1;
    assert_eq!(
        authentication::verify(&f.policy, &f.metadata, &tampered).unwrap_err(),
        model::Error::Authentication
    );
    let duplicate = vec![valid[0].clone(), valid[0].clone()];
    assert_eq!(
        authentication::verify(&f.policy, &f.metadata, &duplicate).unwrap_err(),
        model::Error::Authentication
    );
    f.metadata.evidence = [99; 32];
    assert_eq!(
        authentication::verify(&f.policy, &f.metadata, &valid).unwrap_err(),
        model::Error::Authentication
    );
}

#[test]
fn real_rotation_requires_old_and_new_key_sets_on_exact_new_metadata() {
    let mut f = support::Fixture::new();
    install(&mut f, 40);
    let old_policy = f.policy.clone();
    let old_carriers = carriers(&f.policy, &f.metadata, 40);
    f.signatures = authentication::verify(&f.policy, &f.metadata, &old_carriers).unwrap();
    let prior = f.plan().successor();
    f.metadata.prior = Some(prior);
    f.metadata.generation = 2;
    f.metadata.trust = [44; 32];
    f.policy.trust = [44; 32];
    f.policy.delegations[0].trust = [44; 32];
    install(&mut f, 50);
    let new_carriers = carriers(&f.policy, &f.metadata, 50);
    f.signatures = authentication::verify(&f.policy, &f.metadata, &new_carriers).unwrap();
    let old_carriers = carriers(&old_policy, &f.metadata, 40);
    let old_evidence = authentication::verify(&old_policy, &f.metadata, &old_carriers).unwrap();
    let mut request = f.request();
    assert_eq!(planner::plan(&request).unwrap_err(), model::Error::Rotation);
    request.rotation = Some(planner::Rotation {
        previous_policy: &old_policy,
        previous_signatures: &old_evidence,
    });
    assert_eq!(planner::plan(&request).unwrap().successor().trust, [44; 32]);
    let mut corrupt = old_carriers;
    corrupt[1].signature[10] ^= 1;
    assert_eq!(
        authentication::verify(&old_policy, &f.metadata, &corrupt).unwrap_err(),
        model::Error::Authentication
    );
}

#[test]
fn direct_encoder_and_signature_boundary_reject_oversized_metadata() {
    let mut f = support::Fixture::new();
    f.metadata.mirrors = vec![[6; 32]; model::MAX_MIRRORS + 1];
    assert_eq!(f.metadata.bytes().unwrap_err(), model::Error::Bounds);
    assert_eq!(
        authentication::scope(&f.metadata).unwrap_err(),
        model::Error::Bounds
    );
    assert_eq!(
        authentication::verify(&f.policy, &f.metadata, &[]).unwrap_err(),
        model::Error::Bounds
    );
    assert_eq!(
        authentication::authenticate(&f.policy, &f.metadata, &[]).unwrap_err(),
        model::Error::Bounds
    );
}
