mod support;
use release_channel::model;
use release_channel::planner;
use release_channel::publication;
use std::cell;
use std::rc;

type Shared = rc::Rc<cell::RefCell<Option<model::State>>>;
struct Writer {
    current: Shared,
    commit: publication::Commit,
}
impl publication::Publisher for Writer {
    fn identity(&self) -> model::Id {
        [30; 32]
    }
    fn stage(&mut self, _: &planner::Plan) -> Result<(), model::Error> {
        Ok(())
    }
    fn commit(&mut self, plan: &planner::Plan) -> publication::Commit {
        if self.commit != publication::Commit::NotApplied {
            *self.current.borrow_mut() = Some(plan.successor());
        }
        self.commit
    }
}
struct Reader {
    current: Shared,
    bytes: Vec<u8>,
    split: bool,
}
impl publication::Readback for Reader {
    fn identity(&self) -> model::Id {
        [31; 32]
    }
    fn metadata(&mut self, mirror: &model::Id, _: &model::Id) -> Result<Vec<u8>, model::Error> {
        if self.split && *mirror == [7; 32] {
            Ok(vec![0])
        } else {
            Ok(self.bytes.clone())
        }
    }
    fn current(&mut self, _: &model::Id) -> Result<Option<model::State>, model::Error> {
        Ok(*self.current.borrow())
    }
}
struct Log {
    consistent: bool,
}
impl publication::Witness for Log {
    fn observe(
        &mut self,
        metadata: model::Id,
        _: &[u8],
    ) -> Result<publication::WitnessObservation, model::Error> {
        Ok(publication::WitnessObservation {
            provider: [5; 32],
            metadata,
            appended: true,
            included: true,
            consistent: self.consistent,
            checkpoint: [32; 32],
        })
    }
}
fn ports(plan: &planner::Plan) -> (Writer, Reader, Log) {
    let current = rc::Rc::new(cell::RefCell::new(plan.expected()));
    (
        Writer {
            current: current.clone(),
            commit: publication::Commit::Applied,
        },
        Reader {
            current,
            bytes: plan.bytes().to_vec(),
            split: false,
        },
        Log { consistent: true },
    )
}

#[test]
fn exact_mirrors_witness_and_control_readback_produce_bounded_receipt() {
    let plan = support::Fixture::new().plan();
    let (mut writer, mut reader, mut log) = ports(&plan);
    let result = publication::execute(&plan, &mut writer, &mut reader, &mut log, 20);
    match result {
        publication::Outcome::Published(receipt) => {
            assert_eq!(receipt.state, plan.successor());
            assert_eq!(receipt.mirrors, vec![[6; 32], [7; 32]]);
            assert_eq!(receipt.witness.metadata, plan.successor().metadata);
            assert_ne!(receipt.publisher, receipt.readback);
        }
        other => panic!("expected bounded publication: {other:?}"),
    }
}

#[test]
fn split_mirror_or_inconsistent_log_never_updates_current() {
    let plan = support::Fixture::new().plan();
    let (mut writer, mut reader, mut log) = ports(&plan);
    reader.split = true;
    assert_eq!(
        publication::execute(&plan, &mut writer, &mut reader, &mut log, 20),
        publication::Outcome::Blocked(model::Error::Mirror)
    );
    assert_eq!(*reader.current.borrow(), None);
    reader.split = false;
    log.consistent = false;
    assert_eq!(
        publication::execute(&plan, &mut writer, &mut reader, &mut log, 20),
        publication::Outcome::Blocked(model::Error::Witness)
    );
    assert_eq!(*reader.current.borrow(), None);
}

#[test]
fn interrupted_commit_is_uncertain_even_if_write_became_visible() {
    let plan = support::Fixture::new().plan();
    let (mut writer, mut reader, mut log) = ports(&plan);
    writer.commit = publication::Commit::Unknown;
    assert!(matches!(
        publication::execute(&plan, &mut writer, &mut reader, &mut log, 20),
        publication::Outcome::Uncertain { .. }
    ));
    assert_eq!(*reader.current.borrow(), Some(plan.successor()));
    assert_eq!(
        release_channel::reconciliation::recover(&plan, *reader.current.borrow()).unwrap(),
        transactional_reconciliation_core::PublicationClassification::Published
    );
    assert_eq!(
        release_channel::reconciliation::recover(&plan, None).unwrap(),
        transactional_reconciliation_core::PublicationClassification::NotPublished
    );
    let alien = model::State {
        channel: [99; 32],
        ..plan.successor()
    };
    assert_eq!(
        release_channel::reconciliation::recover(&plan, Some(alien)).unwrap_err(),
        model::Error::Conflict
    );
}
