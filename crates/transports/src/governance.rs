use crate::store;
use channel::{model, planner, publication};

/// Operator authority for the channel pointer, separate from immutable object upload.
/// Implementations MUST perform atomic expected-state comparison, not GET then PUT.
/// A network timeout after submission MUST return Unknown, never NotApplied.
pub trait ControlPort {
    fn compare_exchange(
        &mut self,
        expected: Option<model::State>,
        successor: model::State,
    ) -> publication::Commit;
    fn current(&mut self, channel: &model::Id) -> Result<Option<model::State>, model::Error>;
}

pub struct GovernedPublisher {
    pub id: model::Id,
    pub stores: Vec<Box<dyn store::Store>>,
    pub control: Box<dyn ControlPort>,
    staged: Option<model::Id>,
}

impl GovernedPublisher {
    pub fn new(
        id: model::Id,
        stores: Vec<Box<dyn store::Store>>,
        control: Box<dyn ControlPort>,
    ) -> Self {
        Self {
            id,
            stores,
            control,
            staged: None,
        }
    }
}

impl publication::Publisher for GovernedPublisher {
    fn identity(&self) -> model::Id {
        self.id
    }

    fn stage(&mut self, plan: &planner::Plan) -> Result<(), model::Error> {
        self.staged = None;
        if self.stores.len() != plan.metadata().mirrors.len() {
            return Err(model::Error::Mirror);
        }
        for mirror in &plan.metadata().mirrors {
            let matches = self
                .stores
                .iter()
                .filter(|s| &s.identity() == mirror)
                .count();
            if matches != 1 {
                return Err(model::Error::Mirror);
            }
            let store = self
                .stores
                .iter_mut()
                .find(|s| &s.identity() == mirror)
                .ok_or(model::Error::Mirror)?;
            let id = store.put(plan.bytes()).map_err(map_error)?;
            if id != plan.successor().metadata {
                return Err(model::Error::Identity);
            }
        }
        self.staged = Some(plan.identity());
        Ok(())
    }

    fn commit(&mut self, plan: &planner::Plan) -> publication::Commit {
        if self.staged.take() != Some(plan.identity()) {
            return publication::Commit::NotApplied;
        }
        self.control
            .compare_exchange(plan.expected(), plan.successor())
    }
}

/// Read-only independently constructed clients, not a publisher's response echo.
pub struct Receiver {
    pub id: model::Id,
    pub stores: Vec<Box<dyn store::Store>>,
    pub control: Box<dyn ControlPort>,
}

impl publication::Readback for Receiver {
    fn identity(&self) -> model::Id {
        self.id
    }

    fn metadata(&mut self, mirror: &model::Id, id: &model::Id) -> Result<Vec<u8>, model::Error> {
        if self
            .stores
            .iter()
            .filter(|s| &s.identity() == mirror)
            .count()
            != 1
        {
            return Err(model::Error::Mirror);
        }
        let store = self
            .stores
            .iter_mut()
            .find(|s| &s.identity() == mirror)
            .ok_or(model::Error::Mirror)?;
        store.get(id).map_err(map_error)
    }

    fn current(&mut self, channel: &model::Id) -> Result<Option<model::State>, model::Error> {
        self.control.current(channel)
    }
}

fn map_error(error: crate::Error) -> model::Error {
    match error {
        crate::Error::Uncertain => model::Error::Uncertain,
        crate::Error::Digest => model::Error::Identity,
        crate::Error::Policy => model::Error::Policy,
        _ => model::Error::Transport,
    }
}
