use crate::{provider, types};
use std::{fs, io, path};

/// Exclusive local rollback fence, not administrator-independent storage.
/// A missing file is rejected; enroll an operator-approved signed baseline first.
pub struct Monotonic<P> {
    provider: P,
    path: path::PathBuf,
    evidence: Option<types::Evidence>,
    lock: fs::File,
    uncertain: bool,
}

impl<P: provider::Provider> Monotonic<P> {
    pub fn open(mut provider: P, path: path::PathBuf) -> Result<Self, types::Error> {
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("lock"))
            .map_err(durability)?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(durability)?;
        let file = fs::File::open(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                types::Error::Invalid("checkpoint state is not enrolled".into())
            } else {
                durability(error)
            }
        })?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut io::Read::take(file, 256 * 1024 + 1), &mut bytes)
            .map_err(durability)?;
        if bytes.len() > 256 * 1024 {
            return Err(types::Error::Invalid("state too large".into()));
        }
        let evidence: Option<types::Evidence> =
            Some(serde_json::from_slice(&bytes).map_err(durability)?);
        if let Some(saved) = &evidence {
            let checked = provider.verify(&saved.statement, &saved.proof)?;
            if checked != *saved {
                return Err(types::Error::Invalid("state evidence mismatch".into()));
            }
        }
        Ok(Self {
            provider,
            path,
            evidence,
            lock,
            uncertain: false,
        })
    }

    /// Explicitly approve an initial signed checkpoint; never overwrites history.
    pub fn enroll(
        mut provider: P,
        path: path::PathBuf,
        evidence: &types::Evidence,
    ) -> Result<Self, types::Error> {
        let checked = provider.verify(&evidence.statement, &evidence.proof)?;
        if checked != *evidence {
            return Err(types::Error::Invalid("enrollment evidence mismatch".into()));
        }
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("lock"))
            .map_err(durability)?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(durability)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(path::Path::new("."));
        let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(durability)?;
        serde_json::to_writer(staged.as_file_mut(), evidence).map_err(durability)?;
        staged.as_file().sync_all().map_err(durability)?;
        staged.persist_noclobber(&path).map_err(durability)?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(durability)?;
        Ok(Self {
            provider,
            path,
            evidence: Some(evidence.clone()),
            lock,
            uncertain: false,
        })
    }
    pub fn checkpoint(&self) -> Option<&types::Checkpoint> {
        self.evidence.as_ref().map(|evidence| &evidence.checkpoint)
    }

    pub fn append(
        &mut self,
        statement: &types::Statement,
    ) -> Result<types::Evidence, types::Error> {
        self.ready()?;
        let evidence = self.provider.append(statement)?;
        self.accept(statement, evidence)
    }

    pub fn verify(
        &mut self,
        statement: &types::Statement,
        proof: &str,
    ) -> Result<types::Evidence, types::Error> {
        self.ready()?;
        let evidence = self.provider.verify(statement, proof)?;
        self.accept(statement, evidence)
    }

    fn ready(&self) -> Result<(), types::Error> {
        if self.uncertain {
            return Err(types::Error::Uncertain(
                "reopen state after publication failure".into(),
            ));
        }
        Ok(())
    }

    fn accept(
        &mut self,
        statement: &types::Statement,
        evidence: types::Evidence,
    ) -> Result<types::Evidence, types::Error> {
        if evidence.statement != *statement {
            return Err(types::Error::Invalid("statement mismatch".into()));
        }
        if let Some(previous) = self.checkpoint() {
            check_order(previous, &evidence.checkpoint)?;
            let previous = previous.clone();
            self.provider.consistency(&previous, &evidence.checkpoint)?;
        }
        self.uncertain = true;
        persist(&self.path, &evidence)?;
        self.evidence = Some(evidence.clone());
        self.uncertain = false;
        Ok(evidence)
    }
}

impl<P> Drop for Monotonic<P> {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.lock);
    }
}

fn check_order(
    previous: &types::Checkpoint,
    observed: &types::Checkpoint,
) -> Result<(), types::Error> {
    if previous.log != observed.log {
        return Err(types::Error::Invalid(
            "log changed; separate state required".into(),
        ));
    }
    if observed.size < previous.size {
        return Err(types::Error::Rollback {
            previous: previous.size,
            observed: observed.size,
        });
    }
    if observed.size == previous.size && observed.root != previous.root {
        return Err(types::Error::Fork {
            previous: previous.clone(),
            observed: observed.clone(),
        });
    }
    Ok(())
}

fn persist(path: &path::Path, evidence: &types::Evidence) -> Result<(), types::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(path::Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(durability)?;
    serde_json::to_writer(staged.as_file_mut(), evidence).map_err(durability)?;
    staged.as_file().sync_all().map_err(durability)?;
    staged.persist(path).map_err(durability)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(durability)
}

fn durability(error: impl std::fmt::Display) -> types::Error {
    types::Error::Durability(error.to_string())
}
