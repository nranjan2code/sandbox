//! Promotion journal for crash-safe transactions

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    Begin { realm_id: String, base_path: PathBuf },
    Backup { file: PathBuf, backup_path: PathBuf },
    Change { file: PathBuf, action: ChangeAction },
    Apply { file: PathBuf },
    Rollback { file: PathBuf },
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
}

impl PromotionJournal {
    pub fn new(journal_dir: impl AsRef<Path>) -> Result<Self> {
        let journal_dir = journal_dir.as_ref().to_path_buf();
        fs::create_dir_all(&journal_dir)?;
        Ok(Self {
            journal_dir,
            entries: Vec::new(),
            current_id: None,
            current_workspace: None,
        })
    }

    pub fn begin(&mut self, realm_id: &str, base_path: &Path) -> Result<String> {
        let id = format!("promo-{}-{}", realm_id, timestamp());
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

    pub fn backup(&mut self, file: &Path, backup_path: &Path) -> Result<()> {
        let entry = JournalEntry {
            id: self.current_id.clone().ok_or_else(|| Error::Journal("No active journal".into()))?,
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

    pub fn change(&mut self, file: &Path, action: ChangeAction) -> Result<()> {
        let entry = JournalEntry {
            id: self.current_id.clone().ok_or_else(|| Error::Journal("No active journal".into()))?,
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

    pub fn commit(&mut self) -> Result<()> {
        let entry = JournalEntry {
            id: self.current_id.clone().ok_or_else(|| Error::Journal("No active journal".into()))?,
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

    pub fn abort(&mut self) -> Result<()> {
        let entry = JournalEntry {
            id: self.current_id.clone().ok_or_else(|| Error::Journal("No active journal".into()))?,
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
        let journal_file = self.journal_dir.join(format!("{}.jsonl", entry.id));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&journal_file)?;
        let line = serde_json::to_string(entry)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    pub fn load_journal(&self, journal_id: &str) -> Result<Vec<JournalEntry>> {
        let journal_file = self.journal_dir.join(format!("{}.jsonl", journal_id));
        let mut file = File::open(&journal_file)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let mut entries = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() { continue; }
            if let Ok(entry) = serde_json::from_str::<JournalEntry>(line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    pub fn list_incomplete(&self) -> Result<Vec<String>> {
        let mut incomplete = Vec::new();
        if !self.journal_dir.exists() { return Ok(incomplete); }
        for entry in fs::read_dir(&self.journal_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
                let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
                if id.is_empty() { continue; }
                let entries = self.load_journal(&id)?;
                if entries.is_empty() { continue; }
                let finished = entries.iter().any(|e| matches!(e.operation, JournalOp::Commit | JournalOp::Abort));
                if !finished {
                    incomplete.push(id);
                }
            }
        }
        Ok(incomplete)
    }
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
        assert!(entries.iter().any(|e| matches!(e.operation, JournalOp::Commit)));
    }
}
