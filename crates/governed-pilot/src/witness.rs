use crate::input;
use release_channel::{model, publication};
use release_channel_witness::{provider, sigsum, state, types};
use std::{path, time};

pub struct Witness {
    provider: model::Id,
    signer: String,
    log: state::Monotonic<sigsum::Process>,
}

impl Witness {
    fn process(config: &input::Runtime) -> anyhow::Result<sigsum::Process> {
        Ok(sigsum::Process::new(sigsum::Config {
            executable: config.witness_program.clone().into(),
            policy: config.witness_policy.clone().into(),
            secret_key: Some(config.witness_secret.clone().into()),
            timeout: time::Duration::from_secs(60),
        })?)
    }

    /// Explicit smoke enrollment, not independent administration or discovery.
    /// Bootstrap evidence comes from actual append and verified signed inclusion.
    pub fn enroll(
        config: &input::Runtime,
        root: &path::Path,
        provider: model::Id,
    ) -> anyhow::Result<Self> {
        let mut process = Self::process(config)?;
        let statement = types::Statement {
            metadata_hash: model::hash(b"release-channel.governed-pilot.bootstrap.v1"),
            signer: config.witness_signer.clone(),
        };
        let evidence = provider::Provider::append(&mut process, &statement)?;
        let log = state::Monotonic::enroll(process, root.join("witness.json"), &evidence)?;
        Ok(Self {
            provider,
            signer: config.witness_signer.clone(),
            log,
        })
    }

    pub fn reopen(
        config: &input::Runtime,
        root: &path::Path,
        provider: model::Id,
    ) -> anyhow::Result<Self> {
        let log = state::Monotonic::open(Self::process(config)?, root.join("witness.json"))?;
        Ok(Self {
            provider,
            signer: config.witness_signer.clone(),
            log,
        })
    }
}

impl publication::Witness for Witness {
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
        // Monotonic validates the real checkpoint consistency path from the
        // enrolled baseline and durably retains it. Verify inclusion again,
        // rather than accepting the publisher's append response as readback.
        let evidence = self.log.append(&statement).map_err(map_error)?;
        let verified = self
            .log
            .verify(&statement, &evidence.proof)
            .map_err(map_error)?;
        if evidence != verified {
            return Err(model::Error::Witness);
        }
        let checkpoint =
            serde_json::to_vec(&verified.checkpoint).map_err(|_| model::Error::Witness)?;
        Ok(publication::WitnessObservation {
            provider: self.provider,
            metadata,
            appended: true,
            included: true,
            consistent: true,
            checkpoint: model::hash(&checkpoint),
        })
    }
}

fn map_error(error: types::Error) -> model::Error {
    match error {
        types::Error::Uncertain(_) => model::Error::Uncertain,
        _ => model::Error::Witness,
    }
}
