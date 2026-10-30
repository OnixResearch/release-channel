mod support;
use release_channel::model;
use release_channel::planner;

#[test]
fn threshold_and_exact_identity_are_required() {
    let mut f = support::Fixture::new();
    let plan = f.plan();
    assert_eq!(plan.successor().generation, 1);
    f.signatures.pop();
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Authentication
    );
    f.sign();
    f.signatures[1] = f.signatures[0].clone();
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Authentication
    );
    f.sign();
    f.metadata.release = [13; 32];
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::MixMatch
    );
}

#[test]
fn stale_readiness_revocation_and_freeze_are_blocked() {
    let mut f = support::Fixture::new();
    f.facts.readiness_expires = 20;
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Readiness
    );
    f.facts.readiness_expires = 90;
    f.facts.revocation_expires = 20;
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Revocation
    );
    f.facts.revocation_expires = 90;
    f.metadata.expires_at = 20;
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Freeze
    );
}

#[test]
fn revoked_keys_and_unbound_currentness_cannot_authorize() {
    let mut f = support::Fixture::new();
    f.policy.authentication.trusted_keys[0].currentness =
        artifact_auth_core::KeyCurrentness::Revoked;
    f.sign();
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Authentication
    );
    f.policy.authentication.trusted_keys[0].currentness =
        artifact_auth_core::KeyCurrentness::Current;
    f.policy.authentication.trusted_keys[0]
        .currentness_ref
        .digest_hex = "ab".repeat(32);
    f.sign();
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Revocation
    );
}

#[test]
fn delegation_scope_and_mirror_agreement_are_required() {
    let mut f = support::Fixture::new();
    f.policy.delegations[0].last_generation = 0;
    f.sign();
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Delegation
    );
    f.policy.delegations[0].last_generation = 10;
    f.sign();
    f.metadata.mirrors.reverse();
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Mirror
    );
}

#[test]
fn rotation_requires_both_old_and_new_thresholds() {
    let mut f = support::Fixture::new();
    let prior = f.plan().successor();
    let previous_policy = f.policy.clone();
    f.metadata.prior = Some(prior);
    f.metadata.generation = 2;
    f.metadata.trust = [14; 32];
    f.policy.trust = [14; 32];
    f.policy.delegations[0].trust = [14; 32];
    for key in &mut f.policy.authentication.trusted_keys {
        key.key_identity.digest_hex = if key.key_id == "key-1" {
            "ab".repeat(32)
        } else {
            "cd".repeat(32)
        };
    }
    f.sign();
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Rotation
    );
    let mut old = support::Fixture::new();
    old.metadata = f.metadata.clone();
    old.sign();
    // Sign the new policy context, not the old policy identity.
    for signature in &mut old.signatures {
        signature.statement.scope = release_channel::authentication::scope(&f.metadata).unwrap();
    }
    let mut request = f.request();
    request.rotation = Some(planner::Rotation {
        previous_policy: &previous_policy,
        previous_signatures: &old.signatures,
    });
    assert_eq!(planner::plan(&request).unwrap().successor().trust, [14; 32]);
    let insufficient = &old.signatures[..1];
    request.rotation = Some(planner::Rotation {
        previous_policy: &previous_policy,
        previous_signatures: insufficient,
    });
    assert_eq!(planner::plan(&request).unwrap_err(), model::Error::Rotation);
}

#[test]
fn stale_plan_and_rollback_have_no_planning_escape() {
    let mut f = support::Fixture::new();
    let first = f.plan();
    assert!(!first.valid_at(90));
    assert!(!first.valid_at(9));
    f.metadata.prior = Some(first.successor());
    f.sign();
    assert_eq!(
        planner::plan(&f.request()).unwrap_err(),
        model::Error::Rollback
    );
    f.metadata.generation = 2;
    f.sign();
    assert_eq!(f.plan().expected(), Some(first.successor()));
}
