mod support;
use release_channel::model;
use release_channel::planner;
use release_channel::supersession;
use release_channel_index::crypto;
use release_channel_index::model as index;

fn signed(prior: model::State) -> (index::Request, index::SignedReply, model::Id) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[61; 32]);
    let query = index::Request {
        namespace: index::Namespace {
            channel: "release".into(),
            platform: "linux".into(),
            track: "stable".into(),
        },
        challenge: [62; 32],
        operation: index::Operation::Query,
    };
    let reply = index::Reply {
        namespace: query.namespace.clone(),
        challenge: query.challenge,
        request_digest: crypto::request_digest(&query).unwrap(),
        snapshot: index::Snapshot {
            revision: 8,
            committed: Some(index::Claim {
                generation: prior.generation,
                digest: prior.metadata,
                predecessor: None,
            }),
            highest: Some(index::Claim {
                generation: 2,
                digest: [63; 32],
                predecessor: Some(prior.metadata),
            }),
            pending: None,
        },
    };
    let signature = crypto::sign(&key, b"release-channel-index/reply/v1\0", &reply).unwrap();
    (
        query,
        index::SignedReply { reply, signature },
        key.verifying_key().to_bytes(),
    )
}

#[test]
fn only_authenticated_strict_supersession_bridges_the_retained_predecessor() {
    let mut fixture = support::Fixture::new();
    let prior = fixture.plan().successor();
    let (query, reply, pin) = signed(prior);
    let proof = supersession::Supersession::verify(
        &supersession::Context {
            pin: &pin,
            namespace: &query.namespace,
            minimum_revision: 8,
            predecessor: prior,
        },
        &query,
        &reply,
    )
    .unwrap();
    fixture.metadata.prior = Some(prior);
    fixture.metadata.generation = 3;
    fixture.sign();
    let mut request = fixture.request();
    assert!(matches!(
        planner::plan(&request),
        Err(model::Error::Rollback)
    ));
    request.supersession = Some(&proof);
    assert_eq!(planner::plan(&request).unwrap().successor().generation, 3);
    fixture.metadata.generation = 2;
    fixture.sign();
    let mut request = fixture.request();
    request.supersession = Some(&proof);
    assert!(matches!(
        planner::plan(&request),
        Err(model::Error::Rollback)
    ));
    fixture.metadata.prior.as_mut().unwrap().trust = [64; 32];
    fixture.metadata.generation = 3;
    fixture.sign();
    let mut request = fixture.request();
    request.supersession = Some(&proof);
    assert!(matches!(
        planner::plan(&request),
        Err(model::Error::Rollback)
    ));
}

#[test]
fn authority_nonce_namespace_revision_and_committed_predecessor_are_mandatory() {
    let prior = support::Fixture::new().plan().successor();
    let (query, reply, pin) = signed(prior);
    let mut context = supersession::Context {
        pin: &pin,
        namespace: &query.namespace,
        minimum_revision: 8,
        predecessor: prior,
    };
    let mut changed = query.clone();
    changed.challenge[0] ^= 1;
    assert!(supersession::Supersession::verify(&context, &changed, &reply).is_err());
    changed = query.clone();
    changed.namespace.track = "other".into();
    assert!(supersession::Supersession::verify(&context, &changed, &reply).is_err());
    let mut forged = reply.clone();
    forged.reply.snapshot.highest.as_mut().unwrap().generation = 1;
    assert!(supersession::Supersession::verify(&context, &query, &forged).is_err());
    context.minimum_revision = 9;
    assert!(supersession::Supersession::verify(&context, &query, &reply).is_err());
    context.minimum_revision = 8;
    context.predecessor.metadata = [65; 32];
    assert!(supersession::Supersession::verify(&context, &query, &reply).is_err());
    let wrong_pin = [66; 32];
    context.pin = &wrong_pin;
    assert!(supersession::Supersession::verify(&context, &query, &reply).is_err());
}

#[test]
fn valid_signature_never_turns_a_pending_claim_into_supersession_authority() {
    let prior = support::Fixture::new().plan().successor();
    let (query, mut reply, pin) = signed(prior);
    let context = supersession::Context {
        pin: &pin,
        namespace: &query.namespace,
        minimum_revision: 8,
        predecessor: prior,
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[61; 32]);
    for status in [index::PendingStatus::Reserved, index::PendingStatus::Orphan] {
        reply.reply.snapshot.pending = Some(index::Pending {
            reservation: [67; 32],
            claim: reply.reply.snapshot.highest.clone().unwrap(),
            status,
        });
        reply.signature =
            crypto::sign(&key, b"release-channel-index/reply/v1\0", &reply.reply).unwrap();
        assert!(matches!(
            supersession::Supersession::verify(&context, &query, &reply),
            Err(model::Error::Conflict)
        ));
    }
}
