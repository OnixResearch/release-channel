use crate::model;
use crate::planner;
use crate::publication;

/// Provider owns atomic durable compare-and-swap and cross-process serialization.
/// Unknown means quarantine, not permission to reset or blindly retry history.
pub trait Store {
    fn load(&mut self, channel: &model::Id) -> Result<Option<model::State>, model::Error>;
    fn compare_exchange(
        &mut self,
        expected: Option<model::State>,
        successor: model::State,
    ) -> publication::Commit;
}

#[derive(Clone, Copy, Debug)]
pub enum History {
    /// Explicit first enrollment, never inferred from an absent file.
    Bootstrap {
        channel: model::Id,
        trust: model::Id,
    },
    /// An independently retained durable lower bound, including exact trust and identity.
    Retained(model::State),
}

#[derive(Clone, Copy, Debug)]
pub struct ArtifactAdmission {
    pub release: model::Id,
    pub readiness: model::Id,
    pub evidence: model::Id,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Admission<'a> {
    pub plan: &'a planner::Plan,
    pub distribution: &'a publication::Receipt,
    pub history: History,
    pub artifact: ArtifactAdmission,
    pub now: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Admitted(model::State),
    Blocked(model::Error),
    Uncertain {
        expected: Option<model::State>,
        successor: model::State,
    },
}

pub fn admit(store: &mut impl Store, request: &Admission<'_>) -> Outcome {
    if !request.plan.valid_at(request.now) {
        return Outcome::Blocked(model::Error::Expired);
    }
    if let Err(error) = publication::check_receipt(request.plan, request.distribution) {
        return Outcome::Blocked(error);
    }
    let metadata = request.plan.metadata();
    let artifact = request.artifact;
    if !artifact.complete
        || (artifact.release, artifact.readiness, artifact.evidence)
            != (metadata.release, metadata.readiness, metadata.evidence)
    {
        return Outcome::Blocked(model::Error::MixMatch);
    }
    let current = match store.load(&metadata.channel) {
        Ok(state) => state,
        Err(error) => return Outcome::Blocked(error),
    };
    if let Err(error) = check_history(request, current) {
        return Outcome::Blocked(error);
    }
    let successor = request.plan.successor();
    match store.compare_exchange(current, successor) {
        publication::Commit::NotApplied => return Outcome::Blocked(model::Error::Conflict),
        publication::Commit::Unknown => {
            return Outcome::Uncertain {
                expected: current,
                successor,
            };
        }
        publication::Commit::Applied => {}
    }
    match store.load(&metadata.channel) {
        Ok(Some(observed)) if observed == successor => Outcome::Admitted(successor),
        _ => Outcome::Uncertain {
            expected: current,
            successor,
        },
    }
}

fn check_history(
    request: &Admission<'_>,
    current: Option<model::State>,
) -> Result<(), model::Error> {
    let plan = request.plan;
    match request.history {
        History::Bootstrap { channel, trust } => {
            if current.is_some()
                || plan.expected().is_some()
                || channel != plan.metadata().channel
                || trust != plan.metadata().trust
                || plan.metadata().generation != 1
            {
                return Err(model::Error::MissingState);
            }
        }
        History::Retained(floor) => {
            let observed = current.ok_or(model::Error::MissingState)?;
            if observed.channel != floor.channel
                || observed.generation < floor.generation
                || (observed.generation == floor.generation && observed != floor)
            {
                return Err(model::Error::Rollback);
            }
            // No gap skipping: a caller must validate each trust transition explicitly.
            if plan.expected() != Some(observed) {
                return Err(model::Error::Rollback);
            }
            if observed != floor {
                return Err(model::Error::Conflict);
            }
        }
    }
    Ok(())
}
