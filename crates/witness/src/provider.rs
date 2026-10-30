use crate::types;

/// Implementors must verify the signer, log signature, inclusion and explicit
/// witness quorum before returning evidence. Transport success is not evidence.
pub trait Provider {
    fn append(&mut self, statement: &types::Statement) -> Result<types::Evidence, types::Error>;
    fn verify(
        &mut self,
        statement: &types::Statement,
        proof: &str,
    ) -> Result<types::Evidence, types::Error>;
    fn consistency(
        &mut self,
        previous: &types::Checkpoint,
        observed: &types::Checkpoint,
    ) -> Result<(), types::Error>;
}
