use crate::crypto;
use crate::transition;
use std::fs;
const MAX_STATE: usize = 1_048_576;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    namespace: crate::model::Namespace,
    writer: [u8; 32],
    snapshot: crate::model::Snapshot,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Database {
    admin: [u8; 32],
    server: [u8; 32],
    entries: Vec<Entry>,
}

pub struct Provider {
    root: std::path::PathBuf,
    admin: [u8; 32],
    key: ed25519_dalek::SigningKey,
}

impl Provider {
    pub fn initialize(
        root: &std::path::Path,
        admin: [u8; 32],
        key: ed25519_dalek::SigningKey,
    ) -> crate::Result<Self> {
        let mut directory = fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut directory, 0o700);
        directory.create(root).map_err(|e| e.to_string())?;
        let database = Database {
            admin,
            server: key.verifying_key().to_bytes(),
            entries: Vec::new(),
        };
        let provider = Self {
            root: root.into(),
            admin,
            key,
        };
        provider.persist(&database)?;
        Ok(provider)
    }

    pub fn open(
        root: &std::path::Path,
        admin: [u8; 32],
        key: ed25519_dalek::SigningKey,
    ) -> crate::Result<Self> {
        let provider = Self {
            root: root.into(),
            admin,
            key,
        };
        provider.load()?;
        Ok(provider)
    }

    pub fn handle(
        &self,
        request: &crate::model::SignedRequest,
    ) -> crate::Result<crate::model::SignedReply> {
        request.request.namespace.validate()?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join("lock"))
            .map_err(|e| e.to_string())?;
        fs2::FileExt::lock_exclusive(&lock).map_err(|e| e.to_string())?;
        let mut database = self.load()?;
        let namespace = &request.request.namespace;
        let index = database
            .entries
            .iter()
            .position(|entry| &entry.namespace == namespace);
        let snapshot = self.execute(&mut database, index, request)?;
        let reply = crate::model::Reply {
            namespace: namespace.clone(),
            challenge: request.request.challenge,
            request_digest: crypto::request_digest(&request.request)?,
            snapshot,
        };
        let signature = crypto::sign(&self.key, b"release-channel-index/reply/v1\0", &reply)?;
        Ok(crate::model::SignedReply { reply, signature })
    }

    fn execute(
        &self,
        database: &mut Database,
        index: Option<usize>,
        request: &crate::model::SignedRequest,
    ) -> crate::Result<crate::model::Snapshot> {
        if let crate::model::Operation::Enroll { writer } = &request.request.operation {
            crypto::verify(
                &self.admin,
                b"release-channel-index/request/v1\0",
                &request.request,
                &request.signature,
            )?;
            if index.is_some() || database.entries.len() >= crate::model::MAX_NAMESPACES {
                return Err("enrollment denied".into());
            }
            ed25519_dalek::VerifyingKey::from_bytes(writer).map_err(|e| e.to_string())?;
            let snapshot = crate::model::Snapshot {
                revision: 1,
                highest: None,
                committed: None,
                pending: None,
            };
            database.entries.push(Entry {
                namespace: request.request.namespace.clone(),
                writer: *writer,
                snapshot: snapshot.clone(),
            });
            self.persist(database)?;
            return Ok(snapshot);
        }
        let entry = &mut database.entries[index.ok_or("namespace not explicitly enrolled")?];
        crypto::verify(
            &entry.writer,
            b"release-channel-index/request/v1\0",
            &request.request,
            &request.signature,
        )?;
        let changed = transition::apply(&mut entry.snapshot, request)?;
        let snapshot = entry.snapshot.clone();
        if changed {
            self.persist(database)?;
        }
        Ok(snapshot)
    }

    fn load(&self) -> crate::Result<Database> {
        let file = std::fs::File::open(self.root.join("state.json")).map_err(|e| e.to_string())?;
        if file.metadata().map_err(|e| e.to_string())?.len() > MAX_STATE as u64 {
            return Err("provider state exceeds bound".into());
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(file, (MAX_STATE + 1) as u64),
            &mut bytes,
        )
        .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_STATE {
            return Err("provider state exceeds bound".into());
        }
        let database: Database = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if database.admin != self.admin
            || database.server != self.key.verifying_key().to_bytes()
            || database.entries.len() > crate::model::MAX_NAMESPACES
        {
            return Err("provider trust/state mismatch".into());
        }
        let mut namespaces = std::collections::BTreeSet::new();
        for entry in &database.entries {
            entry.namespace.validate()?;
            entry.snapshot.validate()?;
            ed25519_dalek::VerifyingKey::from_bytes(&entry.writer).map_err(|e| e.to_string())?;
            if !namespaces.insert(&entry.namespace) {
                return Err("duplicate durable namespace".into());
            }
        }
        if self.root.join("pending.json").exists() || self.root.join("uncertain").exists() {
            return Err("uncertain provider write requires operator recovery".into());
        }
        Ok(database)
    }

    fn persist(&self, database: &Database) -> crate::Result<()> {
        let bytes = serde_json::to_vec(database).map_err(|e| e.to_string())?;
        if bytes.len() > MAX_STATE {
            return Err("provider state exceeds bound".into());
        }
        let marker = self.root.join("uncertain");
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&marker)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        std::fs::File::open(&self.root)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| e.to_string())?;
        let temporary = self.root.join("pending.json");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut file, &bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(&temporary, self.root.join("state.json")).map_err(|e| e.to_string())?;
        std::fs::File::open(&self.root)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| e.to_string())?;
        fs::remove_file(marker).map_err(|e| e.to_string())?;
        std::fs::File::open(&self.root)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| e.to_string())
    }
}
