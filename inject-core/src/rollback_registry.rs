//! Rollback registry — track injection operations with rollback state so
//! failed or unwanted injections can be cleanly reverted.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A single rollback entry describing one reversible operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackEntry {
    pub id: String,
    pub target_id: String,
    pub target_path: PathBuf,
    pub operation: RollbackOperation,
    pub applied_at: DateTime<Utc>,
    pub state: RollbackState,
    pub committed_at: Option<DateTime<Utc>>,
    pub rolled_back_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RollbackOperation {
    /// Restore a file from a backup.
    FileRestore { backup_path: PathBuf },
    /// Delete inserted rows by their row IDs.
    RowDelete { table: String, row_ids: Vec<i64> },
    /// Revert a specific SQL statement.
    SqlRevert { statement: String },
    /// Restore a registry key.
    RegistryRestore { key: String, value: String },
    /// Remove a file that was created.
    FileRemove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RollbackState {
    Pending,
    Committed,
    RolledBack,
    Failed,
}

/// Rollback registry.
pub struct RollbackRegistry {
    entries: HashMap<String, RollbackEntry>,
    history_limit: usize,
}

impl RollbackRegistry {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            history_limit: 10_000,
        }
    }

    /// Add a new pending entry.
    pub fn add(&mut self, entry: RollbackEntry) {
        self.entries.insert(entry.id.clone(), entry);
        self.enforce_history_limit();
    }

    fn enforce_history_limit(&mut self) {
        if self.entries.len() > self.history_limit {
            // Remove the oldest committed entries first.
            let committed_ids: Vec<(String, DateTime<Utc>)> = self.entries.iter()
                .filter(|(_, e)| e.state == RollbackState::Committed)
                .map(|(id, e)| (id.clone(), e.committed_at.unwrap_or(e.applied_at)))
                .collect();
            let mut sorted = committed_ids;
            sorted.sort_by_key(|(_, t)| *t);
            let excess = self.entries.len() - self.history_limit;
            for (id, _) in sorted.into_iter().take(excess) {
                self.entries.remove(&id);
            }
        }
    }

    /// Mark an entry as committed.
    pub fn commit(&mut self, id: &str) -> bool {
        if let Some(e) = self.entries.get_mut(id) {
            e.state = RollbackState::Committed;
            e.committed_at = Some(Utc::now());
            true
        } else {
            false
        }
    }

    /// Mark an entry as rolled back.
    pub fn mark_rolled_back(&mut self, id: &str) -> bool {
        if let Some(e) = self.entries.get_mut(id) {
            e.state = RollbackState::RolledBack;
            e.rolled_back_at = Some(Utc::now());
            true
        } else {
            false
        }
    }

    /// Mark an entry as failed.
    pub fn mark_failed(&mut self, id: &str, error: &str) -> bool {
        if let Some(e) = self.entries.get_mut(id) {
            e.state = RollbackState::Failed;
            e.error = Some(error.into());
            true
        } else {
            false
        }
    }

    /// Get an entry.
    pub fn get(&self, id: &str) -> Option<&RollbackEntry> {
        self.entries.get(id)
    }

    /// All pending entries.
    pub fn pending(&self) -> Vec<&RollbackEntry> {
        self.entries.values()
            .filter(|e| e.state == RollbackState::Pending).collect()
    }

    /// All committed entries (these are candidates for rollback).
    pub fn committed(&self) -> Vec<&RollbackEntry> {
        self.entries.values()
            .filter(|e| e.state == RollbackState::Committed).collect()
    }

    /// All rolled back entries.
    pub fn rolled_back(&self) -> Vec<&RollbackEntry> {
        self.entries.values()
            .filter(|e| e.state == RollbackState::RolledBack).collect()
    }

    /// Entries for a specific target.
    pub fn for_target(&self, target_id: &str) -> Vec<&RollbackEntry> {
        self.entries.values()
            .filter(|e| e.target_id == target_id).collect()
    }

    /// Failed entries.
    pub fn failed(&self) -> Vec<&RollbackEntry> {
        self.entries.values()
            .filter(|e| e.state == RollbackState::Failed).collect()
    }

    /// Recent entries within the last N seconds.
    pub fn recent(&self, secs: i64) -> Vec<&RollbackEntry> {
        let cutoff = Utc::now() - chrono::Duration::seconds(secs);
        self.entries.values()
            .filter(|e| e.applied_at > cutoff).collect()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for RollbackRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, target: &str, op: RollbackOperation) -> RollbackEntry {
        RollbackEntry {
            id: id.into(),
            target_id: target.into(),
            target_path: PathBuf::from("/target"),
            operation: op,
            applied_at: Utc::now(),
            state: RollbackState::Pending,
            committed_at: None,
            rolled_back_at: None,
            error: None,
        }
    }

    #[test]
    fn test_add_and_get() {
        let mut r = RollbackRegistry::new();
        r.add(entry("e1", "firefox", RollbackOperation::FileRemove));
        assert!(r.get("e1").is_some());
    }

    #[test]
    fn test_commit() {
        let mut r = RollbackRegistry::new();
        r.add(entry("e1", "firefox", RollbackOperation::FileRemove));
        assert!(r.commit("e1"));
        assert_eq!(r.get("e1").unwrap().state, RollbackState::Committed);
    }

    #[test]
    fn test_rollback() {
        let mut r = RollbackRegistry::new();
        r.add(entry("e1", "firefox", RollbackOperation::FileRemove));
        r.commit("e1");
        assert!(r.mark_rolled_back("e1"));
        assert_eq!(r.get("e1").unwrap().state, RollbackState::RolledBack);
    }

    #[test]
    fn test_mark_failed() {
        let mut r = RollbackRegistry::new();
        r.add(entry("e1", "firefox", RollbackOperation::FileRemove));
        assert!(r.mark_failed("e1", "db locked"));
        assert_eq!(r.get("e1").unwrap().state, RollbackState::Failed);
        assert_eq!(r.get("e1").unwrap().error.as_deref(), Some("db locked"));
    }

    #[test]
    fn test_pending_list() {
        let mut r = RollbackRegistry::new();
        r.add(entry("e1", "a", RollbackOperation::FileRemove));
        r.add(entry("e2", "b", RollbackOperation::FileRemove));
        r.commit("e1");
        assert_eq!(r.pending().len(), 1);
        assert_eq!(r.committed().len(), 1);
    }

    #[test]
    fn test_for_target() {
        let mut r = RollbackRegistry::new();
        r.add(entry("e1", "firefox", RollbackOperation::FileRemove));
        r.add(entry("e2", "firefox", RollbackOperation::FileRemove));
        r.add(entry("e3", "chrome", RollbackOperation::FileRemove));
        assert_eq!(r.for_target("firefox").len(), 2);
    }

    #[test]
    fn test_recent() {
        let mut r = RollbackRegistry::new();
        r.add(entry("e1", "a", RollbackOperation::FileRemove));
        assert_eq!(r.recent(3600).len(), 1);
    }

    #[test]
    fn test_sql_revert_operation() {
        let mut r = RollbackRegistry::new();
        r.add(entry("e1", "firefox",
            RollbackOperation::SqlRevert { statement: "DELETE FROM moz_places WHERE id=1".into() }));
        assert!(r.get("e1").is_some());
    }

    #[test]
    fn test_row_delete_operation() {
        let mut r = RollbackRegistry::new();
        r.add(entry("e1", "firefox",
            RollbackOperation::RowDelete { table: "moz_places".into(), row_ids: vec![1, 2, 3] }));
        match &r.get("e1").unwrap().operation {
            RollbackOperation::RowDelete { row_ids, .. } => assert_eq!(row_ids.len(), 3),
            _ => panic!("wrong operation"),
        }
    }
}
