use crate::{bounded, provider, types};
use std::{fs, io, path, time};

pub struct Config {
    pub executable: path::PathBuf,
    pub policy: path::PathBuf,
    pub secret_key: Option<path::PathBuf>,
    pub timeout: time::Duration,
}

pub struct Process {
    executable: path::PathBuf,
    policy: String,
    secret_key: Option<path::PathBuf>,
    timeout: time::Duration,
}

#[derive(serde::Deserialize)]
struct Response {
    evidence: Option<types::Evidence>,
    error: Option<String>,
    kind: Option<String>,
}

impl Process {
    pub fn new(config: Config) -> Result<Self, types::Error> {
        if config.timeout.is_zero() || config.timeout > time::Duration::from_secs(600) {
            return Err(types::Error::Invalid("timeout must be in (0,600s]".into()));
        }
        let file = fs::File::open(config.policy)
            .map_err(|_| types::Error::Unavailable("cannot read witness policy".into()))?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut io::Read::take(file, 65537), &mut bytes)
            .map_err(|_| types::Error::Unavailable("cannot read witness policy".into()))?;
        if bytes.len() > 65536 {
            return Err(types::Error::Invalid("policy exceeds 64KiB".into()));
        }
        let policy = String::from_utf8(bytes)
            .map_err(|_| types::Error::Invalid("policy is not UTF-8".into()))?;
        Ok(Self {
            executable: config.executable,
            policy,
            secret_key: config.secret_key,
            timeout: config.timeout,
        })
    }

    fn request(&self, mut request: serde_json::Value) -> Result<Response, types::Error> {
        request["policy"] = serde_json::json!(self.policy);
        request["secret"] = serde_json::json!(self.secret_key);
        request["timeout_ms"] = serde_json::json!(self.timeout.as_millis() as u64);
        let input = serde_json::to_vec(&request)
            .map_err(|_| types::Error::Invalid("request encoding".into()))?;
        if input.len() > 256 * 1024 {
            return Err(types::Error::Invalid("request too large".into()));
        }
        let bytes = bounded::run(&self.executable, &input, self.timeout)?;
        let response: Response = serde_json::from_slice(&bytes)
            .map_err(|_| types::Error::Unavailable("invalid provider response".into()))?;
        if let Some(error) = &response.error {
            return Err(match response.kind.as_deref() {
                Some("quorum") => types::Error::Quorum(error.clone()),
                Some("invalid") => types::Error::Invalid(error.clone()),
                Some("uncertain") => types::Error::Uncertain(error.clone()),
                _ => types::Error::Unavailable(error.clone()),
            });
        }
        Ok(response)
    }

    fn evidence(
        &self,
        operation: &str,
        statement: &types::Statement,
        proof: &str,
    ) -> Result<types::Evidence, types::Error> {
        let result = self.request(
            serde_json::json!({"operation":operation,"statement":statement,"proof":proof}),
        );
        let response = result.map_err(|error| match (operation, error) {
            ("append", types::Error::Unavailable(_)) => {
                types::Error::Uncertain("submission outcome unknown".into())
            }
            (_, other) => other,
        })?;
        let evidence = response
            .evidence
            .ok_or_else(|| types::Error::Invalid("missing evidence".into()))?;
        if evidence.statement != *statement {
            return Err(types::Error::Invalid("provider changed statement".into()));
        }
        Ok(evidence)
    }
}

impl provider::Provider for Process {
    fn append(&mut self, statement: &types::Statement) -> Result<types::Evidence, types::Error> {
        self.evidence("append", statement, "")
    }

    fn verify(
        &mut self,
        statement: &types::Statement,
        proof: &str,
    ) -> Result<types::Evidence, types::Error> {
        self.evidence("verify", statement, proof)
    }

    fn consistency(
        &mut self,
        previous: &types::Checkpoint,
        observed: &types::Checkpoint,
    ) -> Result<(), types::Error> {
        self.request(
            serde_json::json!({"operation":"consistency","previous":previous,"observed":observed}),
        )?;
        Ok(())
    }
}
