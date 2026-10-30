use crate::model;
use crate::publication;
use release_channel_witness::provider;
use release_channel_witness::state;
use release_channel_witness::types;

/// Sigsum adapter over independently enrolled durable witness history.
/// Construction never silently establishes a trust-on-first-use checkpoint.
pub struct Sigsum<P: provider::Provider> {
    history: state::Monotonic<P>,
    provider: model::Id,
    signer: String,
}

impl<P: provider::Provider> Sigsum<P> {
    pub fn new(
        history: state::Monotonic<P>,
        identity: model::Id,
        signer: String,
    ) -> Result<Self, model::Error> {
        if !model::nonzero(&identity)
            || history.checkpoint().is_none()
            || signer.len() != 64
            || !signer.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(model::Error::Policy);
        }
        Ok(Self {
            history,
            provider: identity,
            signer,
        })
    }
}

impl<P: provider::Provider> publication::Witness for Sigsum<P> {
    fn observe(
        &mut self,
        metadata: model::Id,
        bytes: &[u8],
    ) -> Result<publication::WitnessObservation, model::Error> {
        if model::hash(bytes) != metadata {
            return Err(model::Error::Identity);
        }
        let statement = types::Statement {
            metadata_hash: metadata,
            signer: self.signer.clone(),
        };
        let evidence = self
            .history
            .append(&statement)
            .map_err(|_| model::Error::Witness)?;
        if evidence.statement != statement {
            return Err(model::Error::Witness);
        }
        let checkpoint = &evidence.checkpoint;
        let mut framed = Vec::with_capacity(256);
        framed.extend_from_slice(b"release-channel.sigsum-checkpoint.v1\0");
        for text in [&checkpoint.log, &checkpoint.root] {
            framed.extend_from_slice(&(text.len() as u64).to_le_bytes());
            framed.extend_from_slice(text.as_bytes());
        }
        framed.extend_from_slice(&checkpoint.size.to_le_bytes());
        Ok(publication::WitnessObservation {
            provider: self.provider,
            metadata,
            appended: true,
            included: true,
            consistent: true,
            checkpoint: model::hash(&framed),
        })
    }
}
