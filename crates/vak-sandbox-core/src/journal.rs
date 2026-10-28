//! Promotion journal for crash-safe transactions

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub id: String,
    pub timestamp: u64,
    pub operation: JournalOp,
    pub status: JournalStatus,
    pub workspace_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum JournalOp {
    Begin {
        realm_id: String,
        base_path: PathBuf,
    },
    Backup {
        file: PathBuf,
        backup_path: PathBuf,
    },
    Change {
        file: PathBuf,
        action: ChangeAction,
    },
    Apply {
        file: PathBuf,
    },
    Rollback {
        file: PathBuf,
    },
    Commit,
    Abort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ChangeAction {
    Create { content_hash: String },
    Modify { old_hash: String, new_hash: String },
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JournalStatus {
    Pending,
    Applied,
    Committed,
    RolledBack,
    Failed,
}

#[derive(Debug)]
pub struct PromotionJournal {
    journal_dir: PathBuf,
    entries: Vec<JournalEntry>,
    current_id: Option<String>,
    current_workspace: Option<PathBuf>,
    _lock: File,
}

impl PromotionJournal {
    /// # Errors
    /// Returns directory creation, confinement or exclusive journal-lock errors.
    pub fn new(journal_dir: impl AsRef<Path>) -> Result<Self> {
        let journal_dir = journal_dir.as_ref().to_path_buf();
        fs::create_dir_all(&journal_dir)?;
        let journal_dir = journal_dir.canonicalize()?;
        let lock_path = crate::path::confined(&journal_dir, ".lock")?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.try_lock()
            .map_err(|e| Error::Journal(format!("Journal is busy: {e}")))?;
        Ok(Self {
            journal_dir,
            entries: Vec::new(),
            current_id: None,
            current_workspace: None,
            _lock: lock,
        })
    }

    /// # Errors
    /// Rejects invalid IDs, an already active transaction, clock errors or journal persistence failures.
    pub fn begin(&mut self, realm_id: &str, base_path: &Path) -> Result<String> {
        validate_id(realm_id)?;
        if self.current_id.is_some() {
            return Err(Error::Journal("A transaction is already active".into()));
        }
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Journal(e.to_string()))?
            .as_nanos();
        let id = format!("promo-{realm_id}-{}-{nanos}-{sequence}", std::process::id());
        self.current_id = Some(id.clone());
        self.current_workspace = Some(base_path.to_path_buf());
        let entry = JournalEntry {
            id: id.clone(),
            timestamp: timestamp(),
            operation: JournalOp::Begin {
                realm_id: realm_id.to_string(),
                base_path: base_path.to_path_buf(),
            },
            status: JournalStatus::Pending,
            workspace_root: Some(base_path.to_path_buf()),
        };
        self.append_entry(&entry)?;
        self.entries.push(entry);
        Ok(id)
    }

    /// # Errors
    /// Requires an active transaction and a valid, writable durable journal.
    pub fn backup(&mut self, file: &Path, backup_path: &Path) -> Result<()> {
        let entry = JournalEntry {
            id: self
                .current_id
                .clone()
                .ok_or_else(|| Error::Journal("No active journal".into()))?,
            timestamp: timestamp(),
            operation: JournalOp::Backup {
                file: file.to_path_buf(),
                backup_path: backup_path.to_path_buf(),
            },
            status: JournalStatus::Pending,
            workspace_root: self.current_workspace.clone(),
        };
        self.append_entry(&entry)?;
        self.entries.push(entry);
        Ok(())
    }

    /// # Errors
    /// Requires an active transaction and a valid, writable durable journal.
    pub fn change(&mut self, file: &Path, action: ChangeAction) -> Result<()> {
        let entry = JournalEntry {
            id: self
                .current_id
                .clone()
                .ok_or_else(|| Error::Journal("No active journal".into()))?,
            timestamp: timestamp(),
            operation: JournalOp::Change {
                file: file.to_path_buf(),
                action,
            },
            status: JournalStatus::Pending,
            workspace_root: self.current_workspace.clone(),
        };
        self.append_entry(&entry)?;
        self.entries.push(entry);
        Ok(())
    }

    /// # Errors
    /// Requires an active transaction and successful durable journal append.
    pub fn commit(&mut self) -> Result<()> {
        let entry = JournalEntry {
            id: self
                .current_id
                .clone()
                .ok_or_else(|| Error::Journal("No active journal".into()))?,
            timestamp: timestamp(),
            operation: JournalOp::Commit,
            status: JournalStatus::Pending,
            workspace_root: self.current_workspace.clone(),
        };
        self.append_entry(&entry)?;
        self.entries.push(entry);
        self.current_id = None;
        self.current_workspace = None;
        Ok(())
    }

    /// # Errors
    /// Requires an active transaction and successful durable journal append.
    pub fn abort(&mut self) -> Result<()> {
        let entry = JournalEntry {
            id: self
                .current_id
                .clone()
                .ok_or_else(|| Error::Journal("No active journal".into()))?,
            timestamp: timestamp(),
            operation: JournalOp::Abort,
            status: JournalStatus::Pending,
            workspace_root: self.current_workspace.clone(),
        };
        self.append_entry(&entry)?;
        self.entries.push(entry);
        self.current_id = None;
        self.current_workspace = None;
        Ok(())
    }

    fn append_entry(&self, entry: &JournalEntry) -> Result<()> {
        validate_id(&entry.id)?;
        let journal_file =
            crate::path::confined(&self.journal_dir, &format!("{}.jsonl", entry.id))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_file)?;
        let line = serde_json::to_string(entry)?;
        writeln!(file, "{line}")?;
        file.sync_all()?;
        File::open(&self.journal_dir)?.sync_all()?;
        Ok(())
    }

    /// # Errors
    /// Rejects invalid IDs, symlinks, oversized/corrupt records and ownership mismatches.
    pub fn load_journal(&self, journal_id: &str) -> Result<Vec<JournalEntry>> {
        validate_id(journal_id)?;
        let journal_file =
            crate::path::confined(&self.journal_dir, &format!("{journal_id}.jsonl"))?;
        let metadata = fs::symlink_metadata(&journal_file)?;
        if !metadata.is_file() || metadata.len() > 32 * 1024 * 1024 {
            return Err(Error::Journal("Invalid journal file".into()));
        }
        let mut file = File::open(&journal_file)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let mut entries = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: JournalEntry = serde_json::from_str(line)?;
            if entry.id != journal_id {
                return Err(Error::Journal("Journal ownership mismatch".into()));
            }
            entries.push(entry);
        }
        Ok(entries)
    }

    /// # Errors
    /// Returns directory, journal-integrity or journal-read errors; corrupt history is never skipped.
    pub fn list_incomplete(&self) -> Result<Vec<String>> {
        let mut incomplete = Vec::new();
        if !self.journal_dir.exists() {
            return Ok(incomplete);
        }
        for entry in fs::read_dir(&self.journal_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
                let id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                if id.is_empty() {
                    continue;
                }
                let entries = self.load_journal(&id)?;
                if entries.is_empty() {
                    continue;
                }
                let finished = entries
                    .iter()
                    .any(|e| matches!(e.operation, JournalOp::Commit | JournalOp::Abort));
                if !finished {
                    incomplete.push(id);
                }
            }
        }
        Ok(incomplete)
    }
}

fn validate_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    {
        return Err(Error::Journal("Invalid journal identifier".into()));
    }
    Ok(())
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn journal_begin_commit() {
        let td = TempDir::new().unwrap();
        let mut journal = PromotionJournal::new(td.path()).unwrap();
        let id = journal.begin("realm1", Path::new("/tmp/base")).unwrap();
        assert!(!id.is_empty());
        journal.commit().unwrap();
        let entries = journal.load_journal(&id).unwrap();
        assert!(
            entries
                .iter()
                .any(|e| matches!(e.operation, JournalOp::Commit))
        );
    }
    #[test]
    fn invalid_ids_and_corrupt_history_fail_closed() {
        let temp = TempDir::new().unwrap();
        let mut journal = PromotionJournal::new(temp.path()).unwrap();
        assert!(journal.begin("../outside", temp.path()).is_err());
        assert!(journal.load_journal("/absolute").is_err());
        let id = journal.begin("realm", temp.path()).unwrap();
        assert!(journal.begin("second", temp.path()).is_err());
        journal.commit().unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(temp.path().join(format!("{id}.jsonl")))
            .unwrap();
        writeln!(file, "corrupt").unwrap();
        file.sync_all().unwrap();
        assert!(journal.load_journal(&id).is_err());
        assert!(journal.list_incomplete().is_err());
    }
}
