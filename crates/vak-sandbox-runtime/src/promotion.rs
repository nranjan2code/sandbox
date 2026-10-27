//! Crash-safe promotion workflow

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs as async_fs;
use vak_sandbox_core::journal::{ChangeAction, PromotionJournal};
use vak_sandbox_env::sha256_file;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("promotion error: {0}")]
    Promotion(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct PromotionPlan {
    pub realm_root: PathBuf,
    pub base_path: PathBuf,
    pub changes: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PromotionReceipt {
    pub journal_id: String,
    pub promoted_files: Vec<PathBuf>,
    pub backed_up: Vec<PathBuf>,
}

pub struct Promoter {
    journal_dir: PathBuf,
    backup_dir: PathBuf,
}

impl Promoter {
    pub fn new(state_dir: impl AsRef<Path>) -> Result<Self> {
        let state_dir = state_dir.as_ref();
        let journal_dir = state_dir.join("journals");
        let backup_dir = state_dir.join("backups");
        fs::create_dir_all(&journal_dir)?;
        fs::create_dir_all(&backup_dir)?;
        Ok(Self { journal_dir, backup_dir })
    }

    pub async fn promote(&self, plan: PromotionPlan) -> Result<PromotionReceipt> {
        let mut journal = PromotionJournal::new(&self.journal_dir)
            .map_err(|e| Error::Promotion(e.to_string()))?;
        let realm_id = plan.realm_root.file_name().and_then(|n| n.to_str()).unwrap_or("unknown");
        let journal_id = journal.begin(realm_id, &plan.base_path)
            .map_err(|e| Error::Promotion(e.to_string()))?;

        let mut promoted = Vec::new();
        let mut backed_up = Vec::new();

        for change in &plan.changes {
            let rel = change.strip_prefix(&plan.realm_root)
                .map_err(|_| Error::Promotion("Invalid change path".into()))?;
            let target = plan.base_path.join(rel);

            // Backup existing file if it exists
            if target.exists() {
                let backup_path = self.backup_dir.join(format!("{}-{}", journal_id, backup_name(&target)));
                async_fs::copy(&target, &backup_path).await?;
                journal.backup(&target, &backup_path)
                    .map_err(|e| Error::Promotion(e.to_string()))?;
                backed_up.push(backup_path);
            }

            // Ensure parent exists
            if let Some(parent) = target.parent() {
                async_fs::create_dir_all(parent).await?;
            }

            // Copy from realm to target
            if change.is_dir() {
                // For directories, create
                async_fs::create_dir_all(&target).await?;
            } else {
                async_fs::copy(change, &target).await?;
                // Record change
                let new_hash = sha256_file(&target).unwrap_or_default();
                journal.change(&target, ChangeAction::Modify { old_hash: String::new(), new_hash })
                    .map_err(|e| Error::Promotion(e.to_string()))?;
            }
            promoted.push(target);
        }

        journal.commit().map_err(|e| Error::Promotion(e.to_string()))?;
        Ok(PromotionReceipt { journal_id, promoted_files: promoted, backed_up })
    }

    pub fn rollback(&self, journal_id: &str) -> Result<()> {
        let journal = PromotionJournal::new(&self.journal_dir)
            .map_err(|e| Error::Promotion(e.to_string()))?;
        let entries = journal.load_journal(journal_id)
            .map_err(|e| Error::Promotion(e.to_string()))?;
        
        // Rollback in reverse order
        for entry in entries.iter().rev() {
            if let vak_sandbox_core::journal::JournalOp::Backup { file, backup_path } = &entry.operation {
                if backup_path.exists() {
                    fs::copy(backup_path, file)?;
                }
            }
        }
        Ok(())
    }
}

fn backup_name(p: &Path) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{}", p.file_name().and_then(|n| n.to_str()).unwrap_or("file"), ts)
}
