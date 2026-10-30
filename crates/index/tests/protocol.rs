use release_channel_index::client;
use release_channel_index::crypto;
use release_channel_index::transition;
fn namespace() -> release_channel_index::model::Namespace {
    release_channel_index::model::Namespace {
        channel: "release".into(),
        platform: "linux".into(),
        track: "stable".into(),
    }
}

fn request(
    operation: release_channel_index::model::Operation,
) -> release_channel_index::model::SignedRequest {
    crypto::authenticate(
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        release_channel_index::model::Request {
            namespace: namespace(),
            challenge: [9; 32],
            operation,
        },
    )
    .expect("sign request")
}

#[test]
fn reserved_and_orphan_claims_never_become_current() {
    let mut state = release_channel_index::model::Snapshot {
        revision: 1,
        highest: None,
        committed: None,
        pending: None,
    };
    let claim = release_channel_index::model::Claim {
        generation: 4,
        digest: [3; 32],
        predecessor: None,
    };
    transition::apply(
        &mut state,
        &request(release_channel_index::model::Operation::Reserve {
            expected_revision: 1,
            claim: claim.clone(),
        }),
    )
    .expect("reserve");
    assert_eq!(state.highest, Some(claim.clone()));
    assert!(client::require_current(&state, &claim).is_err());
    let reservation = state.pending.as_ref().expect("pending").reservation;
    transition::apply(
        &mut state,
        &request(release_channel_index::model::Operation::Orphan {
            expected_revision: 2,
            reservation,
        }),
    )
    .expect("orphan");
    assert!(
        transition::apply(
            &mut state,
            &request(release_channel_index::model::Operation::Commit {
                expected_revision: 3,
                reservation,
                expected_predecessor: None,
            })
        )
        .is_err()
    );
    assert!(client::require_current(&state, &claim).is_err());
}

#[test]
fn finalize_requires_exact_reservation_predecessor_and_revision() {
    let mut state = release_channel_index::model::Snapshot {
        revision: 1,
        highest: None,
        committed: None,
        pending: None,
    };
    let claim = release_channel_index::model::Claim {
        generation: 1,
        digest: [1; 32],
        predecessor: None,
    };
    transition::apply(
        &mut state,
        &request(release_channel_index::model::Operation::Reserve {
            expected_revision: 1,
            claim: claim.clone(),
        }),
    )
    .expect("reserve");
    for (revision, reservation, predecessor) in [
        (1, [0; 32], None),
        (2, [0; 32], None),
        (
            2,
            state.pending.as_ref().expect("pending").reservation,
            Some([4; 32]),
        ),
    ] {
        assert!(
            transition::apply(
                &mut state,
                &request(release_channel_index::model::Operation::Commit {
                    expected_revision: revision,
                    reservation,
                    expected_predecessor: predecessor,
                })
            )
            .is_err()
        );
    }
    let reservation = state.pending.as_ref().expect("pending").reservation;
    transition::apply(
        &mut state,
        &request(release_channel_index::model::Operation::Commit {
            expected_revision: 2,
            reservation,
            expected_predecessor: None,
        }),
    )
    .expect("commit");
    client::require_current(&state, &claim).expect("exact current");
    assert!(
        transition::apply(
            &mut state,
            &request(release_channel_index::model::Operation::Reserve {
                expected_revision: 3,
                claim
            })
        )
        .is_err()
    );
}

#[test]
fn signature_binds_challenge_namespace_revision_and_state() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let query = request(release_channel_index::model::Operation::Query).request;
    let reply = release_channel_index::model::Reply {
        namespace: namespace(),
        challenge: query.challenge,
        request_digest: crypto::request_digest(&query).expect("request digest"),
        snapshot: release_channel_index::model::Snapshot {
            revision: 5,
            highest: None,
            committed: None,
            pending: None,
        },
    };
    let signature = crypto::sign(&key, b"release-channel-index/reply/v1\0", &reply).expect("sign");
    let signed = release_channel_index::model::SignedReply { reply, signature };
    client::verify_reply(&key.verifying_key().to_bytes(), &query, &signed, 5).expect("verify");
    assert!(client::verify_reply(&[0; 32], &query, &signed, 5).is_err());
    assert!(client::verify_reply(&key.verifying_key().to_bytes(), &query, &signed, 6).is_err());
    let mut wrong_operation = query.clone();
    wrong_operation.operation = release_channel_index::model::Operation::Orphan {
        expected_revision: 5,
        reservation: [0; 32],
    };
    assert!(
        client::verify_reply(
            &key.verifying_key().to_bytes(),
            &wrong_operation,
            &signed,
            5
        )
        .is_err()
    );
    let mut altered = signed.clone();
    altered.reply.snapshot.revision = 6;
    assert!(client::verify_reply(&key.verifying_key().to_bytes(), &query, &altered, 5).is_err());
    let mut replay = query.clone();
    replay.challenge = [8; 32];
    assert!(client::verify_reply(&key.verifying_key().to_bytes(), &replay, &signed, 5).is_err());
    replay = query;
    replay.namespace.track = "other".into();
    assert!(client::verify_reply(&key.verifying_key().to_bytes(), &replay, &signed, 5).is_err());
}

#[test]
fn orphan_resolution_preserves_highwater_and_requires_strict_supersession() {
    let mut state = release_channel_index::model::Snapshot {
        revision: 1,
        highest: None,
        committed: None,
        pending: None,
    };
    let abandoned = release_channel_index::model::Claim {
        generation: 8,
        digest: [8; 32],
        predecessor: None,
    };
    transition::apply(
        &mut state,
        &request(release_channel_index::model::Operation::Reserve {
            expected_revision: 1,
            claim: abandoned.clone(),
        }),
    )
    .expect("reserve");
    let reservation = state.pending.as_ref().expect("pending").reservation;
    assert!(
        transition::apply(
            &mut state,
            &request(release_channel_index::model::Operation::ResolveOrphan {
                expected_revision: 2,
                reservation,
            })
        )
        .is_err()
    );
    transition::apply(
        &mut state,
        &request(release_channel_index::model::Operation::Orphan {
            expected_revision: 2,
            reservation,
        }),
    )
    .expect("mark orphan");
    transition::apply(
        &mut state,
        &request(release_channel_index::model::Operation::ResolveOrphan {
            expected_revision: 3,
            reservation,
        }),
    )
    .expect("resolve orphan");
    state.validate().expect("resolved state remains reopenable");
    assert_eq!(state.highest, Some(abandoned.clone()));
    assert!(client::require_current(&state, &abandoned).is_err());
    assert!(
        transition::apply(
            &mut state,
            &request(release_channel_index::model::Operation::Reserve {
                expected_revision: 4,
                claim: abandoned,
            })
        )
        .is_err()
    );
    let next = release_channel_index::model::Claim {
        generation: 9,
        digest: [9; 32],
        predecessor: None,
    };
    transition::apply(
        &mut state,
        &request(release_channel_index::model::Operation::Reserve {
            expected_revision: 4,
            claim: next.clone(),
        }),
    )
    .expect("strictly advance retained highwater");
    let reservation = state.pending.as_ref().expect("pending").reservation;
    transition::apply(
        &mut state,
        &request(release_channel_index::model::Operation::Commit {
            expected_revision: 5,
            reservation,
            expected_predecessor: None,
        }),
    )
    .expect("finalize superseding generation");
    client::require_current(&state, &next).expect("superseding claim is current");
}
