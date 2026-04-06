//! Snapshot store — preserve target state before injection for safe rollback.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A snapshot of target state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub target_id: String,
    pub source_path: PathBuf,
    pub backup_path: PathBuf,
    pub size_bytes: u64,
    pub hash_hex: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
    pub state: SnapshotState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotState {
    Active,
    Restored,
    Discarded,
    Corrupted,
}

impl Snapshot {
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
    }

    pub fn age_secs(&self) -> i64 {
        (Utc::now() - self.created_at).num_seconds()
    }
}

/// Snapshot store.
pub struct SnapshotStore {
    snapshots: HashMap<String, Snapshot>,
    by_target: HashMap<String, Vec<String>>,
    total_bytes: u64,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
            by_target: HashMap::new(),
            total_bytes: 0,
        }
    }

    /// Add a snapshot.
    pub fn add(&mut self, snapshot: Snapshot) {
        let id = snapshot.id.clone();
        let target = snapshot.target_id.clone();
        self.total_bytes += snapshot.size_bytes;
        self.by_target.entry(target).or_default().push(id.clone());
        self.snapshots.insert(id, snapshot);
    }

    /// Remove a snapshot.
    pub fn remove(&mut self, id: &str) -> Option<Snapshot> {
        let snapshot = self.snapshots.remove(id)?;
        self.total_bytes = self.total_bytes.saturating_sub(snapshot.size_bytes);
        if let Some(ids) = self.by_target.get_mut(&snapshot.target_id) {
            ids.retain(|i| i != id);
        }
        Some(snapshot)
    }

    /// Mark a snapshot as restored.
    pub fn mark_restored(&mut self, id: &str) -> bool {
        if let Some(s) = self.snapshots.get_mut(id) {
            s.state = SnapshotState::Restored;
            return true;
        }
        false
    }

    /// Discard a snapshot (logically — caller deletes the backup file).
    pub fn discard(&mut self, id: &str) -> bool {
        if let Some(s) = self.snapshots.get_mut(id) {
            s.state = SnapshotState::Discarded;
            return true;
        }
        false
    }

    /// Get a snapshot.
    pub fn get(&self, id: &str) -> Option<&Snapshot> {
        self.snapshots.get(id)
    }

    /// All snapshots for a target.
    pub fn for_target(&self, target_id: &str) -> Vec<&Snapshot> {
        self.by_target.get(target_id)
            .map(|ids| ids.iter().filter_map(|id| self.snapshots.get(id)).collect())
            .unwrap_or_default()
    }

    /// Most recent snapshot for a target.
    pub fn latest_for(&self, target_id: &str) -> Option<&Snapshot> {
        let mut snaps = self.for_target(target_id);
        snaps.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        snaps.into_iter().next()
    }

    /// Active snapshots.
    pub fn active(&self) -> Vec<&Snapshot> {
        self.snapshots.values().filter(|s| s.state == SnapshotState::Active).collect()
    }

    /// Expired snapshots.
    pub fn expired(&self) -> Vec<&Snapshot> {
        self.snapshots.values().filter(|s| s.is_expired()).collect()
    }

    /// Total bytes used by snapshots.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Snapshots older than N seconds.
    pub fn older_than(&self, secs: i64) -> Vec<&Snapshot> {
        self.snapshots.values().filter(|s| s.age_secs() > secs).collect()
    }
}

impl Default for SnapshotStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(id: &str, target: &str, size: u64) -> Snapshot {
        Snapshot {
            id: id.into(),
            target_id: target.into(),
            source_path: PathBuf::from(format!("/source/{}", id)),
            backup_path: PathBuf::from(format!("/backup/{}", id)),
            size_bytes: size,
            hash_hex: format!("hash-{}", id),
            created_at: Utc::now(),
            expires_at: None,
            metadata: HashMap::new(),
            state: SnapshotState::Active,
        }
    }

    #[test]
    fn test_add_and_count() {
        let mut s = SnapshotStore::new();
        s.add(snap("s1", "firefox", 1000));
        assert_eq!(s.snapshot_count(), 1);
        assert_eq!(s.total_bytes(), 1000);
    }

    #[test]
    fn test_for_target() {
        let mut s = SnapshotStore::new();
        s.add(snap("s1", "firefox", 100));
        s.add(snap("s2", "firefox", 200));
        s.add(snap("s3", "chrome", 100));
        assert_eq!(s.for_target("firefox").len(), 2);
    }

    #[test]
    fn test_remove() {
        let mut s = SnapshotStore::new();
        s.add(snap("s1", "firefox", 1000));
        let removed = s.remove("s1");
        assert!(removed.is_some());
        assert_eq!(s.snapshot_count(), 0);
        assert_eq!(s.total_bytes(), 0);
    }

    #[test]
    fn test_mark_restored() {
        let mut s = SnapshotStore::new();
        s.add(snap("s1", "firefox", 1000));
        s.mark_restored("s1");
        assert_eq!(s.get("s1").unwrap().state, SnapshotState::Restored);
    }

    #[test]
    fn test_discard() {
        let mut s = SnapshotStore::new();
        s.add(snap("s1", "firefox", 1000));
        s.discard("s1");
        assert_eq!(s.get("s1").unwrap().state, SnapshotState::Discarded);
    }

    #[test]
    fn test_latest_for() {
        let mut s = SnapshotStore::new();
        let mut old = snap("old", "firefox", 100);
        old.created_at = Utc::now() - chrono::Duration::days(1);
        let new = snap("new", "firefox", 100);
        s.add(old);
        s.add(new);
        assert_eq!(s.latest_for("firefox").unwrap().id, "new");
    }

    #[test]
    fn test_active() {
        let mut s = SnapshotStore::new();
        s.add(snap("s1", "firefox", 100));
        s.add(snap("s2", "firefox", 100));
        s.discard("s1");
        assert_eq!(s.active().len(), 1);
    }

    #[test]
    fn test_expired() {
        let mut s = SnapshotStore::new();
        let mut old = snap("expired", "firefox", 100);
        old.expires_at = Some(Utc::now() - chrono::Duration::days(1));
        s.add(old);
        assert_eq!(s.expired().len(), 1);
    }

    #[test]
    fn test_older_than() {
        let mut s = SnapshotStore::new();
        let mut old = snap("old", "firefox", 100);
        old.created_at = Utc::now() - chrono::Duration::seconds(100);
        s.add(old);
        s.add(snap("new", "firefox", 100));
        assert_eq!(s.older_than(50).len(), 1);
    }
}
