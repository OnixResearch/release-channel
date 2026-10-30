use crate::crypto;
pub fn apply(
    state: &mut crate::model::Snapshot,
    request: &crate::model::SignedRequest,
) -> crate::Result<bool> {
    match &request.request.operation {
        crate::model::Operation::Query => return Ok(false),
        crate::model::Operation::Enroll { .. } => return Err("already enrolled".into()),
        crate::model::Operation::Reserve {
            expected_revision,
            claim,
        } => {
            revision(state, *expected_revision)?;
            if state.pending.is_some() {
                return Err("unresolved reservation blocks advancement".into());
            }
            let predecessor = state.committed.as_ref().map(|c| c.digest);
            if claim.predecessor != predecessor
                || claim.generation == 0
                || state
                    .highest
                    .as_ref()
                    .is_some_and(|c| claim.generation <= c.generation)
            {
                return Err("claim does not advance exact predecessor/high-water".into());
            }
            state.highest = Some(claim.clone());
            state.pending = Some(crate::model::Pending {
                reservation: crypto::reservation(request)?,
                claim: claim.clone(),
                status: crate::model::PendingStatus::Reserved,
            });
        }
        crate::model::Operation::Commit {
            expected_revision,
            reservation,
            expected_predecessor,
        } => {
            revision(state, *expected_revision)?;
            let pending = pending(state, reservation)?;
            if pending.status != crate::model::PendingStatus::Reserved
                || pending.claim.predecessor != *expected_predecessor
                || state.committed.as_ref().map(|c| c.digest) != *expected_predecessor
            {
                return Err("commit predecessor or reservation status mismatch".into());
            }
            state.committed = Some(pending.claim.clone());
            state.pending = None;
        }
        crate::model::Operation::Orphan {
            expected_revision,
            reservation,
        } => {
            revision(state, *expected_revision)?;
            pending(state, reservation)?;
            state.pending.as_mut().ok_or("missing reservation")?.status =
                crate::model::PendingStatus::Orphan;
        }
        crate::model::Operation::ResolveOrphan {
            expected_revision,
            reservation,
        } => {
            revision(state, *expected_revision)?;
            if pending(state, reservation)?.status != crate::model::PendingStatus::Orphan {
                return Err("only explicit orphan reservations may be resolved".into());
            }
            state.pending = None;
        }
    }
    state.revision = state.revision.checked_add(1).ok_or("revision exhausted")?;
    Ok(true)
}

fn revision(state: &crate::model::Snapshot, expected: u64) -> crate::Result<()> {
    if state.revision != expected || expected == u64::MAX {
        return Err("revision CAS mismatch".into());
    }
    Ok(())
}

fn pending<'a>(
    state: &'a crate::model::Snapshot,
    reservation: &[u8; 32],
) -> crate::Result<&'a crate::model::Pending> {
    state
        .pending
        .as_ref()
        .filter(|p| &p.reservation == reservation)
        .ok_or("reservation mismatch".into())
}
