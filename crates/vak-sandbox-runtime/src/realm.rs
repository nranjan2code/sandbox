//! Durable workspace copies. Control state and journals are never in the jailed workspace.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use vak_sandbox_core::path::confined;
use vak_sandbox_env::{sha256_bytes, sha256_file};

const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 50_000;
type Result<T> = io::Result<T>;
fn invalid(message: impl ToString) -> io::Error {
    io::Error::other(message.to_string())
}
fn safe(root: &Path, relative: &str) -> Result<PathBuf> {
    confined(root, relative).map_err(invalid)
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value).map_err(invalid)
}
fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 32 * 1024 * 1024 {
        return Err(invalid("Invalid or oversized control file"));
    }
    serde_json::from_slice(&fs::read(path)?).map_err(invalid)
}
fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}
fn atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| invalid("Missing parent"))?;
    let temporary = parent.join(format!(".vaksb-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
        }
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    atomic(path, &encode(value)?, 0o600)
}
fn id(value: &str) -> Result<()> {
    if Uuid::parse_str(value).is_ok() {
        Ok(())
    } else {
        Err(invalid("Invalid realm or transaction ID"))
    }
}

pub fn excluded(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        ".git", ".vak", ".ssh", ".aws", ".azure", ".kube", ".docker", ".npmrc", ".netrc",
    ]
    .contains(&lower.as_str())
        || lower == ".env"
        || lower.starts_with(".env.")
        || [
            "credential",
            "secret",
            "token",
            "privatekey",
            "private_key",
            "private-key",
        ]
        .iter()
        .any(|s| lower.contains(s))
        || lower.starts_with("id_rsa")
        || lower.starts_with("id_ed25519")
        || lower.starts_with("id_ecdsa")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
}
fn protected(relative: &str) -> bool {
    Path::new(relative)
        .components()
        .any(|c| excluded(&c.as_os_str().to_string_lossy()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Version {
    pub kind: String,
    pub hash: String,
    pub bytes: u64,
    pub mode: u32,
}
pub type Manifest = BTreeMap<String, Version>;
fn version(path: &Path) -> Result<Option<Version>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() || !(meta.is_file() || meta.is_dir()) {
        return Err(invalid(
            "Symlinks and special files are not supported in Realms",
        ));
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = 0o600;
    if meta.len() > MAX_BYTES && meta.is_file() {
        return Err(invalid("File exceeds the Realm size limit"));
    }
    Ok(Some(Version {
        kind: if meta.is_dir() { "directory" } else { "file" }.into(),
        hash: if meta.is_file() {
            sha256_file(path).map_err(invalid)?
        } else {
            String::new()
        },
        bytes: if meta.is_file() { meta.len() } else { 0 },
        mode,
    }))
}
fn scan(root: &Path, skip_excluded: bool) -> Result<Manifest> {
    fn visit(
        root: &Path,
        directory: &Path,
        skip: bool,
        entries: &mut Manifest,
        total: &mut u64,
    ) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("Realm paths must be UTF-8"))?;
            if skip && excluded(&name) {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(invalid)?
                .to_str()
                .ok_or_else(|| invalid("Realm paths must be UTF-8"))?
                .to_owned();
            if relative.len() > 512 {
                return Err(invalid("Realm paths may not exceed 512 UTF-8 bytes"));
            }
            let path = safe(root, &relative)?;
            let v = version(&path)?.ok_or_else(|| invalid("File changed while scanning"))?;
            *total += v.bytes;
            if *total > MAX_BYTES || entries.len() >= MAX_ENTRIES {
                return Err(invalid("Realm exceeds 512 MiB or 50,000 entries"));
            }
            let directory = v.kind == "directory";
            entries.insert(relative, v);
            if directory {
                visit(root, &path, skip, entries, total)?;
            }
        }
        Ok(())
    }
    let mut entries = Manifest::new();
    visit(root, root, skip_excluded, &mut entries, &mut 0)?;
    if encode(&entries)?.len() > 8 * 1024 * 1024 {
        return Err(invalid("Realm manifest exceeds the 8 MiB metadata limit"));
    }
    Ok(entries)
}
fn copy_manifest(from: &Path, to: &Path, manifest: &Manifest) -> Result<()> {
    private_dir(to)?;
    for (name, expected) in manifest {
        let source = safe(from, name)?;
        let target = safe(to, name)?;
        if version(&source)?.as_ref() != Some(expected) {
            return Err(invalid(
                "Source changed while copying; retry from a fresh review",
            ));
        }
        if expected.kind == "directory" {
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            atomic(&target, &fs::read(&source)?, expected.mode)?;
        }
    }
    // Directory modes are applied last so read-only directories do not break the copy.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for (name, expected) in manifest.iter().rev().filter(|(_, v)| v.kind == "directory") {
            fs::set_permissions(safe(to, name)?, fs::Permissions::from_mode(expected.mode))?;
        }
    }
    if scan(to, false)? != *manifest {
        return Err(invalid(
            "Copied workspace does not match its recorded manifest",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmRecord {
    pub realm_id: String,
    pub workspace: PathBuf,
    pub base_path: Option<PathBuf>,
    pub created_at: String,
    pub status: String,
    pub baseline: Manifest,
    pub last_transaction: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub path: String,
    pub before: Option<Version>,
    pub after: Option<Version>,
    pub conflict: bool,
    pub blocked: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub realm_id: String,
    pub fingerprint: String,
    pub changes: Vec<Change>,
    pub can_promote: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    id: String,
    realm_id: String,
    base_path: PathBuf,
    phase: String,
    changes: Vec<Change>,
    previous_baseline: Manifest,
    new_baseline: Manifest,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub transaction_id: String,
    pub realm_id: String,
    pub phase: String,
    pub paths: Vec<String>,
}

/// OS file locks survive neither process exit nor crashes; lock files are stable
/// and are never unlinked, avoiding split-lock races between independent CLIs.
pub struct RealmLease {
    pub record: RealmRecord,
    _lock: File,
}
#[derive(Debug)]
pub struct RealmStore {
    root: PathBuf,
}
impl RealmStore {
    pub fn open(root: &Path) -> Result<Self> {
        private_dir(root)?;
        for name in [
            "realms",
            "state",
            "state/records",
            "state/locks",
            "state/promotions",
            "state/snapshots",
        ] {
            private_dir(&root.join(name))?;
        }
        Ok(Self {
            root: root.canonicalize()?,
        })
    }
    fn lock(&self, key: &str) -> Result<File> {
        let file = private_options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join("state/locks").join(key))?;
        file.try_lock()
            .map_err(|_| invalid("Realm or project is busy in another operation"))?;
        Ok(file)
    }
    fn metadata(&self, realm_id: &str) -> Result<PathBuf> {
        id(realm_id)?;
        safe(&self.root, &format!("state/records/{realm_id}.json"))
    }
    pub fn audit(&self, event: &str, realm_id: &str, details: serde_json::Value) -> Result<()> {
        let file = private_options()
            .write(true)
            .read(true)
            .create(true)
            .truncate(false)
            .open(self.root.join("state/locks/audit"))?;
        file.lock()?;
        let mut audit = private_options()
            .create(true)
            .append(true)
            .open(self.root.join("state/audit.jsonl"))?;
        let mut line = serde_json::to_vec(&serde_json::json!({"at": chrono::Utc::now().to_rfc3339(), "event": event, "realm_id": realm_id, "details": details})).map_err(invalid)?;
        line.push(b'\n');
        audit.write_all(&line)?;
        audit.sync_all()
    }
    pub fn summary(record: &RealmRecord) -> serde_json::Value {
        serde_json::json!({"realm_id": record.realm_id, "workspace": record.workspace, "base_path": record.base_path, "created_at": record.created_at, "status": record.status, "last_transaction": record.last_transaction, "entries": record.baseline.len(), "bytes": record.baseline.values().map(|v| v.bytes).sum::<u64>()})
    }
    pub fn save(&self, record: &RealmRecord) -> Result<()> {
        atomic_json(&self.metadata(&record.realm_id)?, record)
    }
    pub fn lease(&self, realm_id: &str) -> Result<RealmLease> {
        id(realm_id)?;
        let lock = self.lock(realm_id)?;
        let record: RealmRecord = read_json(&self.metadata(realm_id)?)?;
        if record.realm_id != realm_id
            || record.workspace != self.root.join("realms").join(realm_id).join("workspace")
        {
            return Err(invalid("Invalid realm ownership"));
        }
        safe(&self.root, &format!("realms/{realm_id}/workspace"))?;
        Ok(RealmLease {
            record,
            _lock: lock,
        })
    }
    pub fn create(&self, source: Option<&Path>) -> Result<RealmRecord> {
        let _creation_lock = self.lock("creation")?;
        if self.list()?.len() >= 32 {
            return Err(invalid(
                "At most 32 Realms may be retained; destroy an unused Realm first",
            ));
        }
        let base_path = source.map(Path::canonicalize).transpose()?;
        if let Some(base) = &base_path {
            if !base.is_dir()
                || base.parent().is_none()
                || ["/Users", "/home", "/System", "/Library", "/private", "/var"]
                    .iter()
                    .any(|v| base == Path::new(v))
                || std::env::var_os("HOME").is_some_and(|home| base == Path::new(&home))
                || self.root.starts_with(base)
                || base.starts_with(&self.root)
            {
                return Err(invalid(
                    "Choose a project folder separate from the Realm control store",
                ));
            }
        }
        let realm_id = Uuid::new_v4().to_string();
        let workspace = self.root.join("realms").join(&realm_id).join("workspace");
        let baseline = if let Some(base) = &base_path {
            scan(base, true)?
        } else {
            Manifest::new()
        };
        private_dir(&workspace)?;
        let mut record = RealmRecord {
            realm_id: realm_id.clone(),
            workspace: workspace.clone(),
            base_path,
            created_at: chrono::Utc::now().to_rfc3339(),
            status: "creating".into(),
            baseline,
            last_transaction: None,
        };
        self.save(&record)?;
        let result = (|| {
            if let Some(base) = &record.base_path {
                copy_manifest(base, &workspace, &record.baseline)?;
            }
            record.status = "ready".into();
            self.save(&record)?;
            self.audit(
                "created",
                &record.realm_id,
                serde_json::json!({"project": record.base_path}),
            )?;
            Ok(record)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(self.root.join("realms").join(&realm_id));
            let _ = fs::remove_file(self.metadata(&realm_id)?);
        }
        result
    }
    pub fn list(&self) -> Result<Vec<RealmRecord>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(self.root.join("state/records"))? {
            let entry = entry?;
            if entry.path().extension().is_some_and(|v| v == "json") {
                let record: RealmRecord = read_json(&entry.path())?;
                id(&record.realm_id)?;
                records.push(record);
            }
        }
        records.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(records)
    }
    pub fn review(&self, record: &RealmRecord) -> Result<Review> {
        let current = scan(&record.workspace, false)?;
        let mut changes = Vec::new();
        for name in record
            .baseline
            .keys()
            .chain(current.keys())
            .collect::<BTreeSet<_>>()
        {
            let before = record.baseline.get(name).cloned();
            let after = current.get(name).cloned();
            if before == after {
                continue;
            }
            let observed = record
                .base_path
                .as_ref()
                .map(|base| safe(base, name).and_then(|p| version(&p)))
                .transpose()?
                .flatten();
            let blocked = protected(name)
                || before
                    .as_ref()
                    .zip(after.as_ref())
                    .is_some_and(|(a, b)| a.kind != b.kind);
            changes.push(Change {
                path: name.clone(),
                conflict: record.base_path.is_none() || observed != before,
                before,
                after,
                blocked,
            });
        }
        let fingerprint = sha256_bytes(&encode(&(
            record.realm_id.as_str(),
            &record.baseline,
            &current,
            &changes,
        ))?);
        let can_promote = record.status == "ready"
            && !changes.is_empty()
            && changes.len() <= 200
            && !changes.iter().any(|c| c.conflict || c.blocked);
        Ok(Review {
            realm_id: record.realm_id.clone(),
            fingerprint,
            changes,
            can_promote,
        })
    }
    pub fn snapshot(&self, record: &RealmRecord) -> Result<Review> {
        let review = self.review(record)?;
        atomic_json(
            &self
                .root
                .join("state/snapshots")
                .join(format!("{}-{}.json", record.realm_id, review.fingerprint)),
            &review,
        )?;
        self.audit(
            "snapshot",
            &record.realm_id,
            serde_json::json!({"fingerprint": review.fingerprint, "changes": review.changes.len()}),
        )?;
        Ok(review)
    }
    pub fn read_file(
        &self,
        record: &RealmRecord,
        relative: &str,
        offset: u64,
        original: bool,
    ) -> Result<serde_json::Value> {
        if original && !record.baseline.contains_key(relative) {
            return Err(invalid("No original file in this Realm baseline"));
        }
        let root = if original {
            record
                .base_path
                .as_ref()
                .ok_or_else(|| invalid("No original project"))?
        } else {
            &record.workspace
        };
        let path = safe(root, relative)?;
        let v = version(&path)?.ok_or_else(|| invalid("File not found"))?;
        if v.kind != "file" || offset > v.bytes {
            return Err(invalid("Expected a file and a byte offset within its size"));
        }
        use std::io::{Seek, SeekFrom};
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        file.take(16 * 1024).read_to_end(&mut bytes)?;
        Ok(
            serde_json::json!({"path": relative, "version": v, "offset": offset, "next_offset": offset + bytes.len() as u64, "text": String::from_utf8_lossy(&bytes), "lossy": std::str::from_utf8(&bytes).is_err()}),
        )
    }
    fn transaction_path(&self, transaction_id: &str) -> Result<PathBuf> {
        id(transaction_id)?;
        safe(&self.root, &format!("state/promotions/{transaction_id}"))
    }
    fn pending(&self, record: &RealmRecord) -> Result<Vec<Transaction>> {
        let mut result = Vec::new();
        for entry in fs::read_dir(self.root.join("state/promotions"))? {
            let entry = entry?;
            let path = entry.path().join("transaction.json");
            if !path.exists() {
                continue;
            }
            let txn: Transaction = read_json(&path)?;
            if txn.realm_id == record.realm_id && Some(&txn.base_path) != record.base_path.as_ref()
            {
                return Err(invalid("Invalid transaction project ownership"));
            }
            if txn.realm_id == record.realm_id
                && ["prepared", "applying", "rolling_back"].contains(&txn.phase.as_str())
            {
                result.push(txn);
            }
        }
        Ok(result)
    }
    fn project_lock(&self, record: &RealmRecord) -> Result<File> {
        let base = record
            .base_path
            .as_ref()
            .ok_or_else(|| invalid("This realm has no original project"))?;
        self.lock(&format!(
            "project-{}",
            sha256_bytes(base.as_os_str().as_encoded_bytes())
        ))
    }
    fn receipt(txn: &Transaction) -> Receipt {
        Receipt {
            transaction_id: txn.id.clone(),
            realm_id: txn.realm_id.clone(),
            phase: txn.phase.clone(),
            paths: txn.changes.iter().map(|c| c.path.clone()).collect(),
        }
    }
    pub fn promote(
        &self,
        lease: &mut RealmLease,
        fingerprint: &str,
        paths: &[String],
    ) -> Result<Receipt> {
        let _project_lock = self.project_lock(&lease.record)?;
        if !self.pending(&lease.record)?.is_empty() {
            return Err(invalid(
                "Recover the interrupted promotion before proceeding",
            ));
        }
        let review = self.review(&lease.record)?;
        if !review.can_promote
            || review.fingerprint != fingerprint
            || paths
                != review
                    .changes
                    .iter()
                    .map(|c| c.path.clone())
                    .collect::<Vec<_>>()
        {
            return Err(invalid(
                "Promotion review is stale, incomplete, blocked or conflicting. Take a fresh snapshot.",
            ));
        }
        let transaction_id = Uuid::new_v4().to_string();
        let directory = self.root.join("state/promotions").join(&transaction_id);
        private_dir(&directory)?;
        private_dir(&directory.join("before"))?;
        private_dir(&directory.join("after"))?;
        let base = lease
            .record
            .base_path
            .clone()
            .ok_or_else(|| invalid("No original project"))?;
        let mut txn = Transaction {
            id: transaction_id,
            realm_id: lease.record.realm_id.clone(),
            base_path: base.clone(),
            phase: "prepared".into(),
            changes: review.changes,
            previous_baseline: lease.record.baseline.clone(),
            new_baseline: scan(&lease.record.workspace, false)?,
        };
        for (index, change) in txn.changes.iter().enumerate() {
            for (root, version, folder) in [
                (&base, &change.before, "before"),
                (&lease.record.workspace, &change.after, "after"),
            ] {
                if let Some(v) = version.as_ref().filter(|v| v.kind == "file") {
                    let source = safe(root, &change.path)?;
                    let bytes = fs::read(&source)?;
                    if sha256_bytes(&bytes) != v.hash {
                        return Err(invalid("File changed during review staging"));
                    }
                    atomic(
                        &directory.join(folder).join(index.to_string()),
                        &bytes,
                        0o600,
                    )?;
                }
            }
        }
        // Every backup and immutable candidate is durable before the first host mutation.
        atomic_json(&directory.join("transaction.json"), &txn)?;
        txn.phase = "applying".into();
        atomic_json(&directory.join("transaction.json"), &txn)?;
        let apply = (|| {
            for change in &txn.changes {
                if version(&safe(&base, &change.path)?)? != change.before {
                    return Err(invalid("Original project changed after review"));
                }
            }
            for (index, change) in txn
                .changes
                .iter()
                .enumerate()
                .filter(|(_, c)| c.after.is_some())
            {
                if version(&safe(&base, &change.path)?)? != change.before {
                    return Err(invalid("Original project changed immediately before apply"));
                }
                self.apply_version(
                    &base,
                    &change.path,
                    &change.after,
                    &directory.join("after").join(index.to_string()),
                )?;
            }
            for change in txn.changes.iter().rev().filter(|c| c.after.is_none()) {
                if version(&safe(&base, &change.path)?)? != change.before {
                    return Err(invalid(
                        "Original project changed immediately before deletion",
                    ));
                }
                self.apply_version(&base, &change.path, &None, Path::new(""))?;
            }
            Ok(())
        })();
        if let Err(error) = apply {
            let recovered = self.restore(&mut txn, &directory);
            return Err(invalid(format!(
                "Promotion failed: {error}. Recovery: {}",
                if recovered.is_ok() {
                    "rolled back"
                } else {
                    "requires explicit recovery"
                }
            )));
        }
        txn.phase = "committed".into();
        atomic_json(&directory.join("transaction.json"), &txn)?;
        lease.record.baseline = txn.new_baseline.clone();
        lease.record.last_transaction = Some(txn.id.clone());
        self.save(&lease.record)?;
        self.audit(
            "promoted",
            &lease.record.realm_id,
            serde_json::to_value(Self::receipt(&txn)).map_err(invalid)?,
        )?;
        Ok(Self::receipt(&txn))
    }
    fn apply_version(
        &self,
        base: &Path,
        relative: &str,
        wanted: &Option<Version>,
        staged: &Path,
    ) -> Result<()> {
        let target = safe(base, relative)?;
        if let Some(v) = wanted {
            if v.kind == "directory" {
                fs::create_dir_all(&target)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&target, fs::Permissions::from_mode(v.mode))?;
                }
            } else {
                let bytes = fs::read(staged)?;
                if sha256_bytes(&bytes) != v.hash {
                    return Err(invalid("Promotion backup or candidate integrity failed"));
                }
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                atomic(&target, &bytes, v.mode)?;
            }
        } else if let Some(v) = version(&target)? {
            if v.kind == "directory" {
                fs::remove_dir(&target)?;
            } else {
                fs::remove_file(&target)?;
            }
        }
        if let Some(parent) = target.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
    fn restore(&self, txn: &mut Transaction, directory: &Path) -> Result<()> {
        // Refuse rollback over subsequent user edits, even during crash recovery.
        for c in &txn.changes {
            let current = version(&safe(&txn.base_path, &c.path)?)?;
            if current != c.before && current != c.after {
                return Err(invalid(format!("Recovery conflict: {}", c.path)));
            }
        }
        txn.phase = "rolling_back".into();
        atomic_json(&directory.join("transaction.json"), txn)?;
        for (index, c) in txn
            .changes
            .iter()
            .enumerate()
            .filter(|(_, c)| c.before.is_some())
        {
            self.apply_version(
                &txn.base_path,
                &c.path,
                &c.before,
                &directory.join("before").join(index.to_string()),
            )?;
        }
        for c in txn.changes.iter().rev().filter(|c| c.before.is_none()) {
            self.apply_version(&txn.base_path, &c.path, &None, Path::new(""))?;
        }
        txn.phase = "rolled_back".into();
        atomic_json(&directory.join("transaction.json"), txn)
    }
    pub fn last_receipt(&self, record: &RealmRecord) -> Result<Option<Receipt>> {
        record
            .last_transaction
            .as_ref()
            .map(|transaction_id| {
                let txn: Transaction = read_json(
                    &self
                        .transaction_path(transaction_id)?
                        .join("transaction.json"),
                )?;
                if txn.realm_id != record.realm_id
                    || Some(&txn.base_path) != record.base_path.as_ref()
                {
                    return Err(invalid("Invalid receipt ownership"));
                }
                Ok(Self::receipt(&txn))
            })
            .transpose()
    }
    pub fn recovery_paths(&self, record: &RealmRecord) -> Result<Vec<String>> {
        Ok(self
            .pending(record)?
            .iter()
            .flat_map(|txn| txn.changes.iter().map(|c| c.path.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }
    pub fn rollback(
        &self,
        lease: &mut RealmLease,
        transaction_id: &str,
        paths: &[String],
    ) -> Result<Receipt> {
        let _project_lock = self.project_lock(&lease.record)?;
        let directory = self.transaction_path(transaction_id)?;
        let mut txn: Transaction = read_json(&directory.join("transaction.json"))?;
        if txn.realm_id != lease.record.realm_id
            || Some(&txn.base_path) != lease.record.base_path.as_ref()
            || lease.record.last_transaction.as_deref() != Some(transaction_id)
            || txn.phase != "committed"
        {
            return Err(invalid(
                "Only this Realm's most recent committed promotion can be rolled back",
            ));
        }
        if paths
            != txn
                .changes
                .iter()
                .map(|c| c.path.clone())
                .collect::<Vec<_>>()
        {
            return Err(invalid("Rollback paths do not match the reviewed receipt"));
        }
        // A committed rollback must match the exact promoted state, not a partial transaction.
        for c in &txn.changes {
            if version(&safe(&txn.base_path, &c.path)?)? != c.after {
                return Err(invalid(
                    "Original project changed since promotion; rollback refused",
                ));
            }
        }
        self.restore(&mut txn, &directory)?;
        lease.record.baseline = txn.previous_baseline.clone();
        lease.record.last_transaction = None;
        self.save(&lease.record)?;
        self.audit(
            "rolled_back",
            &lease.record.realm_id,
            serde_json::to_value(Self::receipt(&txn)).map_err(invalid)?,
        )?;
        Ok(Self::receipt(&txn))
    }
    pub fn recover(&self, lease: &mut RealmLease, paths: &[String]) -> Result<Vec<Receipt>> {
        if paths != self.recovery_paths(&lease.record)? {
            return Err(invalid("Recovery paths changed; review the current status"));
        }
        if lease.record.status == "creating" {
            return Err(invalid(
                "Realm creation was interrupted. Discard the partial copy and create a fresh Realm.",
            ));
        }
        let _project_lock = self.project_lock(&lease.record)?;
        let mut receipts = Vec::new();
        for mut txn in self.pending(&lease.record)? {
            let directory = self.transaction_path(&txn.id)?;
            self.restore(&mut txn, &directory)?;
            lease.record.baseline = txn.previous_baseline.clone();
            receipts.push(Self::receipt(&txn));
        }
        // Resolve a commit that reached disk before its Realm metadata update.
        for entry in fs::read_dir(self.root.join("state/promotions"))? {
            let entry = entry?;
            let p = entry.path().join("transaction.json");
            if !p.exists() {
                continue;
            }
            let txn: Transaction = read_json(&p)?;
            if txn.realm_id == lease.record.realm_id
                && txn.phase == "committed"
                && lease.record.baseline == txn.previous_baseline
            {
                lease.record.baseline = txn.new_baseline;
                lease.record.last_transaction = Some(txn.id);
            }
        }
        if let Some(transaction_id) = &lease.record.last_transaction {
            let txn: Transaction = read_json(
                &self
                    .transaction_path(transaction_id)?
                    .join("transaction.json"),
            )?;
            if txn.phase == "rolled_back" {
                lease.record.baseline = txn.previous_baseline;
                lease.record.last_transaction = None;
            }
        }
        lease.record.status = "ready".into();
        self.save(&lease.record)?;
        self.audit(
            "recovered",
            &lease.record.realm_id,
            serde_json::to_value(&receipts).map_err(invalid)?,
        )?;
        Ok(receipts)
    }
    pub fn destroy(&self, lease: &RealmLease) -> Result<()> {
        if !self.pending(&lease.record)?.is_empty() {
            return Err(invalid(
                "Recover pending promotion before destroying the Realm",
            ));
        }
        // Retain transaction receipts and backups outside the disposable workspace.
        match fs::remove_dir_all(self.root.join("realms").join(&lease.record.realm_id)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        };
        fs::remove_file(self.metadata(&lease.record.realm_id)?)?;
        self.audit("destroyed", &lease.record.realm_id, serde_json::json!({}))?;
        Ok(())
    }
    pub fn ensure_ready(&self, record: &RealmRecord) -> Result<()> {
        if record.status != "ready" || !self.pending(record)?.is_empty() {
            return Err(invalid(
                "Realm is interrupted or has a pending promotion; use explicit recovery",
            ));
        }
        for entry in fs::read_dir(self.root.join("state/promotions"))? {
            let path = entry?.path().join("transaction.json");
            if !path.exists() {
                continue;
            }
            let txn: Transaction = read_json(&path)?;
            if txn.realm_id == record.realm_id
                && ((txn.phase == "committed"
                    && record.baseline == txn.previous_baseline
                    && record.last_transaction.as_deref() != Some(&txn.id))
                    || (txn.phase == "rolled_back"
                        && record.last_transaction.as_deref() == Some(&txn.id)))
            {
                return Err(invalid(
                    "Promotion receipt and Realm metadata need recovery",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    fn fixture() -> (TempDir, RealmStore, PathBuf, String) {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("project");
        fs::create_dir(&project).unwrap();
        fs::write(project.join("existing.txt"), "before").unwrap();
        fs::write(project.join(".env"), "fixture only").unwrap();
        let store = RealmStore::open(&temp.path().join("control")).unwrap();
        let realm = store.create(Some(&project)).unwrap();
        (temp, store, project, realm.realm_id)
    }
    fn edit(store: &RealmStore, realm_id: &str) -> Review {
        let lease = store.lease(realm_id).unwrap();
        fs::write(lease.record.workspace.join("existing.txt"), "after").unwrap();
        fs::create_dir(lease.record.workspace.join("new-dir")).unwrap();
        fs::write(lease.record.workspace.join("new-dir/new.txt"), "new").unwrap();
        store.snapshot(&lease.record).unwrap()
    }
    fn paths(review: &Review) -> Vec<String> {
        review.changes.iter().map(|c| c.path.clone()).collect()
    }
    #[test]
    fn survives_restart_promotes_exact_bytes_and_rolls_back_creates_and_changes() {
        let (temp, store, project, realm_id) = fixture();
        let review = edit(&store, &realm_id);
        assert_eq!(
            fs::read_to_string(project.join("existing.txt")).unwrap(),
            "before"
        );
        drop(store);
        let reopened = RealmStore::open(&temp.path().join("control")).unwrap();
        let mut lease = reopened.lease(&realm_id).unwrap();
        assert!(!lease.record.workspace.join(".env").exists());
        assert!(review.can_promote);
        let receipt = reopened
            .promote(&mut lease, &review.fingerprint, &paths(&review))
            .unwrap();
        assert_eq!(
            fs::read_to_string(project.join("existing.txt")).unwrap(),
            "after"
        );
        assert_eq!(
            fs::read_to_string(project.join("new-dir/new.txt")).unwrap(),
            "new"
        );
        assert!(reopened.review(&lease.record).unwrap().changes.is_empty());
        reopened
            .rollback(&mut lease, &receipt.transaction_id, &paths(&review))
            .unwrap();
        assert_eq!(
            fs::read_to_string(project.join("existing.txt")).unwrap(),
            "before"
        );
        assert!(!project.join("new-dir").exists());
        assert_eq!(
            fs::read_to_string(project.join(".env")).unwrap(),
            "fixture only"
        );
    }
    #[test]
    fn refuses_stale_candidates_original_conflicts_and_incomplete_review_paths() {
        let (_temp, store, project, realm_id) = fixture();
        let review = edit(&store, &realm_id);
        let mut lease = store.lease(&realm_id).unwrap();
        assert!(store.promote(&mut lease, &review.fingerprint, &[]).is_err());
        fs::write(
            lease.record.workspace.join("existing.txt"),
            "another candidate",
        )
        .unwrap();
        assert!(
            store
                .promote(&mut lease, &review.fingerprint, &paths(&review))
                .is_err()
        );
        let review = store.snapshot(&lease.record).unwrap();
        fs::write(project.join("existing.txt"), "user edit").unwrap();
        assert!(
            store
                .promote(&mut lease, &review.fingerprint, &paths(&review))
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(project.join("existing.txt")).unwrap(),
            "user edit"
        );
    }
    #[test]
    fn deletes_restore_and_rollback_never_overwrites_a_later_user_edit() {
        let (_temp, store, project, realm_id) = fixture();
        let mut lease = store.lease(&realm_id).unwrap();
        fs::remove_file(lease.record.workspace.join("existing.txt")).unwrap();
        let review = store.snapshot(&lease.record).unwrap();
        let receipt = store
            .promote(&mut lease, &review.fingerprint, &paths(&review))
            .unwrap();
        assert!(!project.join("existing.txt").exists());
        fs::write(project.join("existing.txt"), "later user edit").unwrap();
        assert!(
            store
                .rollback(&mut lease, &receipt.transaction_id, &paths(&review))
                .is_err()
        );
        fs::remove_file(project.join("existing.txt")).unwrap();
        store
            .rollback(&mut lease, &receipt.transaction_id, &paths(&review))
            .unwrap();
        assert_eq!(
            fs::read_to_string(project.join("existing.txt")).unwrap(),
            "before"
        );
    }
    #[test]
    fn recovers_interrupted_transaction_from_durable_backups() {
        let (temp, store, project, realm_id) = fixture();
        let review = edit(&store, &realm_id);
        let mut lease = store.lease(&realm_id).unwrap();
        let receipt = store
            .promote(&mut lease, &review.fingerprint, &paths(&review))
            .unwrap();
        let directory = store.transaction_path(&receipt.transaction_id).unwrap();
        let mut txn: Transaction = read_json(&directory.join("transaction.json")).unwrap();
        txn.phase = "applying".into();
        atomic_json(&directory.join("transaction.json"), &txn).unwrap();
        drop(lease);
        drop(store);
        let reopened = RealmStore::open(&temp.path().join("control")).unwrap();
        let mut lease = reopened.lease(&realm_id).unwrap();
        assert!(reopened.ensure_ready(&lease.record).is_err());
        assert!(reopened.destroy(&lease).is_err());
        let receipts = reopened.recover(&mut lease, &paths(&review)).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].phase, "rolled_back");
        assert_eq!(
            fs::read_to_string(project.join("existing.txt")).unwrap(),
            "before"
        );
        assert!(!project.join("new-dir").exists());
    }
    #[test]
    fn locks_paths_and_protected_files_fail_closed() {
        let (_temp, store, _project, realm_id) = fixture();
        let lease = store.lease(&realm_id).unwrap();
        assert!(store.lease(&realm_id).is_err());
        assert!(store.lease("../../").is_err());
        assert!(
            store
                .read_file(&lease.record, "../state", 0, false)
                .is_err()
        );
        fs::write(lease.record.workspace.join(".env"), "new secret").unwrap();
        assert!(!store.snapshot(&lease.record).unwrap().can_promote);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", lease.record.workspace.join("escape"))
                .unwrap();
            assert!(store.snapshot(&lease.record).is_err());
        }
    }
    #[test]
    fn failed_directory_delete_restores_files_without_removing_excluded_data() {
        let (_temp, store, project, realm_id) = fixture();
        drop(store.lease(&realm_id).unwrap());
        fs::create_dir(project.join("folder")).unwrap();
        fs::write(project.join("folder/a.txt"), "a").unwrap();
        fs::write(project.join("folder/.env"), "keep").unwrap();
        let second = store.create(Some(&project)).unwrap();
        let mut lease = store.lease(&second.realm_id).unwrap();
        fs::remove_dir_all(lease.record.workspace.join("folder")).unwrap();
        let review = store.snapshot(&lease.record).unwrap();
        assert!(
            store
                .promote(&mut lease, &review.fingerprint, &paths(&review))
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(project.join("folder/a.txt")).unwrap(),
            "a"
        );
        assert_eq!(
            fs::read_to_string(project.join("folder/.env")).unwrap(),
            "keep"
        );
    }
}

#[cfg(test)]
mod crash_tests {
    use super::*;
    use tempfile::TempDir;
    #[test]
    fn partial_apply_and_metadata_crashes_recover_without_replay() {
        let temp = TempDir::new().unwrap();
        let project = temp.path().join("project");
        fs::create_dir(&project).unwrap();
        fs::write(project.join("a"), "a0").unwrap();
        fs::write(project.join("b"), "b0").unwrap();
        let store = RealmStore::open(&temp.path().join("control")).unwrap();
        let record = store.create(Some(&project)).unwrap();
        let mut lease = store.lease(&record.realm_id).unwrap();
        fs::write(lease.record.workspace.join("a"), "a1").unwrap();
        fs::write(lease.record.workspace.join("b"), "b1").unwrap();
        let review = store.snapshot(&lease.record).unwrap();
        let paths: Vec<_> = review.changes.iter().map(|c| c.path.clone()).collect();
        let receipt = store
            .promote(&mut lease, &review.fingerprint, &paths)
            .unwrap();
        let directory = store.transaction_path(&receipt.transaction_id).unwrap();
        let mut txn: Transaction = read_json(&directory.join("transaction.json")).unwrap();
        // Commit reached disk, but the following metadata write did not.
        lease.record.baseline = txn.previous_baseline.clone();
        lease.record.last_transaction = None;
        store.save(&lease.record).unwrap();
        store.recover(&mut lease, &[]).unwrap();
        assert!(store.review(&lease.record).unwrap().changes.is_empty());
        // Rollback reached disk, but its metadata write did not.
        store.restore(&mut txn, &directory).unwrap();
        store.recover(&mut lease, &[]).unwrap();
        assert_eq!(lease.record.baseline, txn.previous_baseline);
        assert!(lease.record.last_transaction.is_none());
        // A new invocation discovers an applying journal with only one file written.
        txn.phase = "applying".into();
        atomic_json(&directory.join("transaction.json"), &txn).unwrap();
        store
            .apply_version(
                &project,
                &txn.changes[0].path,
                &txn.changes[0].after,
                &directory.join("after/0"),
            )
            .unwrap();
        drop(lease);
        let reopened = RealmStore::open(&temp.path().join("control")).unwrap();
        let mut lease = reopened.lease(&record.realm_id).unwrap();
        reopened.recover(&mut lease, &paths).unwrap();
        assert_eq!(fs::read_to_string(project.join("a")).unwrap(), "a0");
        assert_eq!(fs::read_to_string(project.join("b")).unwrap(), "b0");
    }
    #[test]
    fn interrupted_creation_is_visible_and_discardable() {
        let temp = TempDir::new().unwrap();
        let store = RealmStore::open(&temp.path().join("control")).unwrap();
        let record = store.create(None).unwrap();
        let mut lease = store.lease(&record.realm_id).unwrap();
        lease.record.status = "creating".into();
        store.save(&lease.record).unwrap();
        assert_eq!(store.list().unwrap()[0].status, "creating");
        assert!(store.recover(&mut lease, &[]).is_err());
        store.destroy(&lease).unwrap();
        assert!(store.list().unwrap().is_empty());
    }
}
