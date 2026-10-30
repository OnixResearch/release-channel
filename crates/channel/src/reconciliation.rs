use crate::model;
use crate::planner;

pub struct Blake3;
impl transactional_reconciliation_core::Blake3IdentityDeriver for Blake3 {
    fn derive_identity(
        &self,
        bytes: &[u8],
    ) -> Result<
        transactional_reconciliation_core::Identity,
        transactional_reconciliation_core::CoreError,
    > {
        transactional_reconciliation_core::Identity::new(model::hash(bytes))
    }
}

/// Reuse canonical transactional planning for exact predecessor/successor CAS facts.
pub fn intent(
    plan: &planner::Plan,
) -> Result<transactional_reconciliation_core::PublicationIntent, model::Error> {
    let convert = |id| {
        transactional_reconciliation_core::Identity::new(id).map_err(|_| model::Error::Identity)
    };
    let metadata = plan.metadata();
    let desired = convert(plan.successor().metadata)?;
    let policy = convert(metadata.policy)?;
    let channel = convert(metadata.channel)?;
    let revision = transactional_reconciliation_core::Revision::observed(
        plan.expected().map_or(0, |s| s.generation),
    );
    let operation = transactional_reconciliation_core::OperationDraft::new(
        channel,
        desired,
        transactional_reconciliation_core::Generation::observed(metadata.generation),
        policy,
    );
    let bound =
        transactional_reconciliation_core::Bound::new(1).map_err(|_| model::Error::Bounds)?;
    let input = transactional_reconciliation_core::PlanningInput::new(
        revision,
        desired,
        policy,
        vec![],
        vec![operation],
    );
    let immutable = transactional_reconciliation_core::build_plan(
        &Blake3,
        transactional_reconciliation_core::Limits::new(bound, bound),
        input,
    )
    .map_err(|_| model::Error::Policy)?;
    let current =
        transactional_reconciliation_core::CurrentFacts::new(revision, desired, policy, vec![]);
    transactional_reconciliation_core::plan_publication(&immutable, &current, desired)
        .map_err(|_| model::Error::Conflict)
}

/// Reopening after uncertainty is observational: it never publishes or retries.
pub fn recover(
    plan: &planner::Plan,
    observed: Option<model::State>,
) -> Result<transactional_reconciliation_core::PublicationClassification, model::Error> {
    let intent = intent(plan)?;
    let observation = if observed == Some(plan.successor()) {
        transactional_reconciliation_core::PublicationObservation::Applied {
            predecessor: intent.expected_revision(),
            successor: intent.successor_revision(),
            successor_content_identity: intent.successor_content_identity(),
        }
    } else if observed == plan.expected() {
        transactional_reconciliation_core::PublicationObservation::NotApplied {
            current_revision: intent.expected_revision(),
        }
    } else {
        return Err(model::Error::Conflict);
    };
    Ok(transactional_reconciliation_core::classify_publication(
        &intent,
        observation,
    ))
}
