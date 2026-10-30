mod support;
use release_channel::consumer;
use release_channel::model;
use release_channel::planner;
use release_channel::publication;

struct Durable {
    state: Option<model::State>,
    commit: publication::Commit,
}
impl consumer::Store for Durable {
    fn load(&mut self, _: &model::Id) -> Result<Option<model::State>, model::Error> {
        Ok(self.state)
    }
    fn compare_exchange(
        &mut self,
        expected: Option<model::State>,
        successor: model::State,
    ) -> publication::Commit {
        if self.state != expected {
            return publication::Commit::NotApplied;
        }
        if self.commit != publication::Commit::NotApplied {
            self.state = Some(successor);
        }
        self.commit
    }
}
fn artifact(f: &support::Fixture) -> consumer::ArtifactAdmission {
    consumer::ArtifactAdmission {
        release: f.metadata.release,
        readiness: f.metadata.readiness,
        evidence: f.metadata.evidence,
        complete: true,
    }
}

#[test]
fn enrolled_consumer_advances_only_after_complete_artifact_admission() {
    let mut f = support::Fixture::new();
    let first = f.plan();
    let first_receipt = distribution(&first);
    let mut store = Durable {
        state: None,
        commit: publication::Commit::Applied,
    };
    let mut request = consumer::Admission {
        plan: &first,
        distribution: &first_receipt,
        history: consumer::History::Bootstrap {
            channel: f.metadata.channel,
            trust: f.metadata.trust,
        },
        artifact: artifact(&f),
        now: 20,
    };
    request.artifact.complete = false;
    assert_eq!(
        consumer::admit(&mut store, &request),
        consumer::Outcome::Blocked(model::Error::MixMatch)
    );
    assert_eq!(store.state, None);
    request.artifact.complete = true;
    assert_eq!(
        consumer::admit(&mut store, &request),
        consumer::Outcome::Admitted(first.successor())
    );
    f.metadata.prior = Some(first.successor());
    f.metadata.generation = 2;
    f.sign();
    let next = f.plan();
    let next_receipt = distribution(&next);
    let upgrade = consumer::Admission {
        plan: &next,
        history: consumer::History::Retained(first.successor()),
        distribution: &next_receipt,
        artifact: artifact(&f),
        now: 20,
    };
    assert_eq!(
        consumer::admit(&mut store, &upgrade),
        consumer::Outcome::Admitted(next.successor())
    );
    assert_eq!(
        consumer::admit(&mut store, &request),
        consumer::Outcome::Blocked(model::Error::MissingState)
    );
}

#[test]
fn missing_and_rolled_back_storage_do_not_reset_history() {
    let mut f = support::Fixture::new();
    let first = f.plan().successor();
    f.metadata.prior = Some(first);
    f.metadata.generation = 2;
    f.sign();
    let plan = f.plan();
    let receipt = distribution(&plan);
    let request = consumer::Admission {
        plan: &plan,
        history: consumer::History::Retained(first),
        distribution: &receipt,
        artifact: artifact(&f),
        now: 20,
    };
    let mut store = Durable {
        state: None,
        commit: publication::Commit::Applied,
    };
    assert_eq!(
        consumer::admit(&mut store, &request),
        consumer::Outcome::Blocked(model::Error::MissingState)
    );
    store.state = Some(model::State {
        generation: 0,
        ..first
    });
    assert_eq!(
        consumer::admit(&mut store, &request),
        consumer::Outcome::Blocked(model::Error::Rollback)
    );
    store.state = Some(model::State {
        metadata: [99; 32],
        ..first
    });
    assert_eq!(
        consumer::admit(&mut store, &request),
        consumer::Outcome::Blocked(model::Error::Rollback)
    );
}

#[test]
fn uncertain_durable_commit_never_claims_admission() {
    let f = support::Fixture::new();
    let plan = f.plan();
    let receipt = distribution(&plan);
    let mut store = Durable {
        state: None,
        commit: publication::Commit::Unknown,
    };
    let request = consumer::Admission {
        plan: &plan,
        distribution: &receipt,
        history: consumer::History::Bootstrap {
            channel: f.metadata.channel,
            trust: f.metadata.trust,
        },
        artifact: artifact(&f),
        now: 20,
    };
    assert_eq!(
        consumer::admit(&mut store, &request),
        consumer::Outcome::Uncertain {
            expected: None,
            successor: plan.successor()
        }
    );
    assert_eq!(
        consumer::admit(&mut store, &request),
        consumer::Outcome::Blocked(model::Error::MissingState)
    );
}

#[test]
fn consumer_rejects_inconsistent_distribution_before_cas() {
    let f = support::Fixture::new();
    let plan = f.plan();
    let mut receipt = distribution(&plan);
    receipt.witness.consistent = false;
    let mut store = Durable {
        state: None,
        commit: publication::Commit::Applied,
    };
    let request = consumer::Admission {
        plan: &plan,
        distribution: &receipt,
        history: consumer::History::Bootstrap {
            channel: f.metadata.channel,
            trust: f.metadata.trust,
        },
        artifact: artifact(&f),
        now: 20,
    };
    assert_eq!(
        consumer::admit(&mut store, &request),
        consumer::Outcome::Blocked(model::Error::Witness)
    );
    assert_eq!(store.state, None);
}
pub fn distribution(plan: &planner::Plan) -> release_channel::publication::Receipt {
    release_channel::publication::Receipt {
        plan: plan.identity(),
        state: plan.successor(),
        publisher: [30; 32],
        readback: [31; 32],
        mirrors: plan.metadata().mirrors.clone(),
        witness: release_channel::publication::WitnessObservation {
            provider: plan.witness(),
            metadata: plan.successor().metadata,
            appended: true,
            included: true,
            consistent: true,
            checkpoint: [32; 32],
        },
    }
}
