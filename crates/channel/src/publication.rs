use crate::model;
use crate::planner;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    Applied,
    NotApplied,
    Unknown,
}

/// Stage immutable bytes, then conditionally replace exactly the expected state.
/// A transport without real compare-and-swap must delegate commit to an authority port.
pub trait Publisher {
    fn identity(&self) -> model::Id;
    fn stage(&mut self, plan: &planner::Plan) -> Result<(), model::Error>;
    fn commit(&mut self, plan: &planner::Plan) -> Commit;
}

/// Independently acquired observations, never publisher-returned write echoes.
pub trait Readback {
    fn identity(&self) -> model::Id;
    fn metadata(&mut self, mirror: &model::Id, id: &model::Id) -> Result<Vec<u8>, model::Error>;
    fn current(&mut self, channel: &model::Id) -> Result<Option<model::State>, model::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessObservation {
    pub provider: model::Id,
    pub metadata: model::Id,
    pub appended: bool,
    pub included: bool,
    pub consistent: bool,
    pub checkpoint: model::Id,
}

pub trait Witness {
    fn observe(
        &mut self,
        metadata: model::Id,
        bytes: &[u8],
    ) -> Result<WitnessObservation, model::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub plan: model::Id,
    pub state: model::State,
    pub publisher: model::Id,
    pub readback: model::Id,
    pub mirrors: Vec<model::Id>,
    pub witness: WitnessObservation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Published(Receipt),
    /// No current-state commit was attempted (immutable uploads may exist).
    Blocked(model::Error),
    /// Commit may have happened. Never retry blindly; reopen and reconcile.
    Uncertain {
        plan: model::Id,
        expected: Option<model::State>,
        successor: model::State,
    },
}

pub fn execute(
    plan: &planner::Plan,
    publisher: &mut impl Publisher,
    readback: &mut impl Readback,
    witness: &mut impl Witness,
    now: u64,
) -> Outcome {
    if !plan.valid_at(now) {
        return Outcome::Blocked(model::Error::Expired);
    }
    if !model::nonzero(&publisher.identity())
        || !model::nonzero(&readback.identity())
        || publisher.identity() == readback.identity()
    {
        return Outcome::Blocked(model::Error::Policy);
    }
    match readback.current(&plan.metadata().channel) {
        Ok(current) if current == plan.expected() => {}
        Ok(_) => return Outcome::Blocked(model::Error::Conflict),
        Err(error) => return Outcome::Blocked(error),
    }
    if let Err(error) = publisher.stage(plan) {
        return Outcome::Blocked(error);
    }
    if let Err(error) = mirrors(plan, readback) {
        return Outcome::Blocked(error);
    }
    let observation = match witness.observe(plan.successor().metadata, plan.bytes()) {
        Ok(observation) if valid_witness(plan, &observation) => observation,
        Ok(_) => return Outcome::Blocked(model::Error::Witness),
        Err(error) => return Outcome::Blocked(error),
    };
    match publisher.commit(plan) {
        Commit::NotApplied => return Outcome::Blocked(model::Error::Conflict),
        Commit::Unknown => return uncertain(plan),
        Commit::Applied => {}
    }
    match readback.current(&plan.metadata().channel) {
        Ok(Some(state)) if state == plan.successor() => {}
        _ => return uncertain(plan),
    }
    Outcome::Published(Receipt {
        plan: plan.identity(),
        state: plan.successor(),
        publisher: publisher.identity(),
        readback: readback.identity(),
        mirrors: plan.metadata().mirrors.clone(),
        witness: observation,
    })
}

fn mirrors(plan: &planner::Plan, readback: &mut impl Readback) -> Result<(), model::Error> {
    for mirror in &plan.metadata().mirrors {
        let bytes = readback.metadata(mirror, &plan.successor().metadata)?;
        if bytes != plan.bytes() {
            return Err(model::Error::Mirror);
        }
    }
    Ok(())
}

fn valid_witness(plan: &planner::Plan, observation: &WitnessObservation) -> bool {
    observation.provider == plan.witness()
        && observation.metadata == plan.successor().metadata
        && observation.appended
        && observation.included
        && observation.consistent
        && model::nonzero(&observation.checkpoint)
}

fn uncertain(plan: &planner::Plan) -> Outcome {
    Outcome::Uncertain {
        plan: plan.identity(),
        expected: plan.expected(),
        successor: plan.successor(),
    }
}

/// Supplied adapter facts remain observations, not artifact or deployment authority.
pub fn check_receipt(plan: &planner::Plan, receipt: &Receipt) -> Result<(), model::Error> {
    if receipt.plan != plan.identity() || receipt.state != plan.successor() {
        return Err(model::Error::MixMatch);
    }
    if receipt.mirrors != plan.metadata().mirrors {
        return Err(model::Error::Mirror);
    }
    if !model::nonzero(&receipt.publisher)
        || !model::nonzero(&receipt.readback)
        || receipt.publisher == receipt.readback
    {
        return Err(model::Error::Policy);
    }
    if !valid_witness(plan, &receipt.witness) {
        return Err(model::Error::Witness);
    }
    Ok(())
}
