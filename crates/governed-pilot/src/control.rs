use cap_std::fs;
use release_channel::{model, publication};
use release_channel_transports::governance;
use std::{io, path};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    channel: model::Id,
    current: Option<model::State>,
}

/// Local, common-administrator authority. Each operation locks and reopens state.
/// The directory capability, rather than a subsequently re-resolved pathname,
/// bounds every control-plane file access.
pub struct Control {
    root: fs::Dir,
    writable: bool,
}

impl Control {
    pub fn enroll(root: &path::Path, channel: model::Id) -> anyhow::Result<()> {
        std::fs::create_dir(root)?;
        let control = Self::open(root, true)?;
        let _lock = control.lock()?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = control.root.open_with("current.json", &options)?;
        serde_json::to_writer(
            &mut file,
            &Record {
                channel,
                current: None,
            },
        )?;
        file.sync_all()?;
        control.sync()?;
        Ok(())
    }

    pub fn open(root: &path::Path, writable: bool) -> anyhow::Result<Self> {
        anyhow::ensure!(root.is_absolute(), "absolute control root required");
        Ok(Self {
            root: fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())?,
            writable,
        })
    }

    fn lock(&self) -> anyhow::Result<std::fs::File> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        let lock = self.root.open_with("control.lock", &options)?.into_std();
        fs2::FileExt::lock_exclusive(&lock)?;
        Ok(lock)
    }

    fn read(&self) -> anyhow::Result<Record> {
        let file = self.root.open("current.json")?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut io::Read::take(file, 4097), &mut bytes)?;
        anyhow::ensure!(bytes.len() <= 4096, "control record exceeds bound");
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Directory capabilities may be path-only descriptors; reopen "." relative to the
    /// held capability for a readable descriptor that fsync accepts.
    fn sync(&self) -> anyhow::Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;
        // SAFETY: openat receives a live directory descriptor and a static NUL-terminated
        // path; a successful result is a fresh descriptor owned by the File below.
        let descriptor = unsafe { libc::openat(self.root.as_raw_fd(), c".".as_ptr(), flags) };
        anyhow::ensure!(descriptor >= 0, "control directory reopen: {}", io::Error::last_os_error());
        // SAFETY: descriptor is fresh, valid and not owned elsewhere.
        unsafe { std::fs::File::from_raw_fd(descriptor) }.sync_all()?;
        Ok(())
    }

    fn replace(&self, record: &Record) -> anyhow::Result<()> {
        // The stable control.lock serializes recovery and replacement; pending
        // is never read as authority after a crash.
        match self.root.remove_file("pending.json") {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = self.root.open_with("pending.json", &options)?;
        serde_json::to_writer(&mut file, record)?;
        file.sync_all()?;
        self.root
            .rename("pending.json", &self.root, "current.json")?;
        self.sync()
    }

    fn exchange(
        &self,
        expected: Option<model::State>,
        successor: model::State,
    ) -> anyhow::Result<publication::Commit> {
        anyhow::ensure!(self.writable, "receiver has no write authority");
        let _lock = self.lock()?;
        let record = self.read()?;
        if record.channel != successor.channel || record.current != expected {
            return Ok(publication::Commit::NotApplied);
        }
        let next = expected.map_or(Some(1), |state| state.generation.checked_add(1));
        anyhow::ensure!(
            next == Some(successor.generation),
            "invalid successor generation"
        );
        anyhow::ensure!(
            model::nonzero(&successor.metadata) && model::nonzero(&successor.trust),
            "invalid successor identity"
        );
        self.replace(&Record {
            channel: record.channel,
            current: Some(successor),
        })?;
        Ok(publication::Commit::Applied)
    }
}

impl governance::ControlPort for Control {
    fn compare_exchange(
        &mut self,
        expected: Option<model::State>,
        successor: model::State,
    ) -> publication::Commit {
        // Any failure during durable replacement can follow rename. Never
        // misreport it as a conflict or as proof that no commit happened.
        self.exchange(expected, successor)
            .unwrap_or(publication::Commit::Unknown)
    }

    fn current(&mut self, channel: &model::Id) -> Result<Option<model::State>, model::Error> {
        let _lock = self.lock().map_err(|_| model::Error::Transport)?;
        let record = self.read().map_err(|_| model::Error::Transport)?;
        if &record.channel != channel {
            return Err(model::Error::Identity);
        }
        Ok(record.current)
    }
}
