//! macOS FSEvents log injection.
//!
//! FSEvents is macOS's file system change notification mechanism.  The kernel
//! writes compressed event records to `/.fseventsd/` (one file per batch),
//! each containing an event ID, affected path, flag bitmask (indicating
//! created / modified / removed / renamed), and a timestamp.
//!
//! This module serializes synthetic FSEvents records as JSON files in an
//! output directory, mimicking the structure that macOS writes to
//! `/.fseventsd/`.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{
    InjectionResult, InjectionStrategy, InjectionStrategy::DirectInjection, Injector, Target,
    VerificationStatus,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Artifact schema (deserialized from engine output)
// ---------------------------------------------------------------------------

/// FSEvents flag bitmask values matching the macOS `FSEventStreamEventFlags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsEventFlag {
    /// A file or directory was created.
    Created,
    /// A file or directory was modified.
    Modified,
    /// A file or directory was removed.
    Removed,
    /// A file or directory was renamed.
    Renamed,
    /// Ownership or permissions changed.
    OwnerChange,
    /// Extended attributes changed.
    XattrModified,
}

impl FsEventFlag {
    /// Map to the raw macOS FSEventStreamEventFlags bitmask value.
    pub fn raw_flag(self) -> u32 {
        match self {
            Self::Created => 0x0100,       // kFSEventStreamEventFlagItemCreated
            Self::Modified => 0x1000,      // kFSEventStreamEventFlagItemModified
            Self::Removed => 0x0200,       // kFSEventStreamEventFlagItemRemoved
            Self::Renamed => 0x0800,       // kFSEventStreamEventFlagItemRenamed
            Self::OwnerChange => 0x4000,   // kFSEventStreamEventFlagItemChangeOwner
            Self::XattrModified => 0x8000, // kFSEventStreamEventFlagItemXattrMod
        }
    }
}

/// A single FSEvents record produced by plausiden-engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEventRecord {
    /// Monotonically increasing event ID.
    pub event_id: u64,
    /// Path affected by the event.
    pub path: String,
    /// Flags describing what happened.
    pub flags: Vec<FsEventFlag>,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
}

impl FsEventRecord {
    /// Compute the combined raw flag bitmask.
    pub fn combined_flags(&self) -> u32 {
        self.flags.iter().fold(0u32, |acc, f| acc | f.raw_flag())
    }
}

/// Internal stored representation with the combined bitmask.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FsEventStoredRecord {
    event_id: u64,
    path: String,
    flags: Vec<FsEventFlag>,
    raw_flags: u32,
    timestamp: DateTime<Utc>,
}

impl FsEventStoredRecord {
    fn from_record(record: &FsEventRecord) -> Self {
        Self {
            event_id: record.event_id,
            path: record.path.clone(),
            flags: record.flags.clone(),
            raw_flags: record.combined_flags(),
            timestamp: record.timestamp,
        }
    }
}

// ---------------------------------------------------------------------------
// Injector implementation
// ---------------------------------------------------------------------------

/// FSEvents log injector for macOS systems.
///
/// Writes synthetic FSEvents-style JSON records into an output directory.
/// Each injection run creates a single JSON file containing all event
/// records with computed raw flag bitmasks.
pub struct FsEventsInjector {
    /// Override output directory for testing.
    output_dir_override: Option<PathBuf>,
}

impl FsEventsInjector {
    /// Create a new injector that will auto-discover the FSEvents store.
    pub fn new() -> Self {
        Self {
            output_dir_override: None,
        }
    }

    /// Create an injector targeting a specific output directory.
    pub fn with_output_dir(output_dir: PathBuf) -> Self {
        Self {
            output_dir_override: Some(output_dir),
        }
    }

    /// Resolve the output directory from the `Target` or override.
    fn resolve_output_dir(&self, target: &Target) -> Result<PathBuf> {
        if let Some(dir) = &self.output_dir_override {
            return Ok(dir.clone());
        }
        match target {
            Target::MacosFsEvents { log_path } => Ok(log_path.clone()),
            other => Err(InjectError::UnsupportedTarget {
                description: format!("FsEventsInjector does not handle {other}"),
            }),
        }
    }

    /// Write FSEvents records to the output directory as a JSON file.
    fn inject_records(
        &self,
        records: &[FsEventRecord],
        output_dir: &Path,
    ) -> Result<InjectionResult> {
        fs::create_dir_all(output_dir)?;

        let run_id = Uuid::new_v4();
        let output_file = output_dir.join(format!("fsevents-{run_id}.json"));

        // Back up if the file already exists.
        let backup_path = if output_file.exists() {
            Some(backup_file(&output_file)?)
        } else {
            None
        };

        // Convert to stored format (includes raw_flags).
        let stored: Vec<FsEventStoredRecord> = records
            .iter()
            .map(FsEventStoredRecord::from_record)
            .collect();

        let json = serde_json::to_string_pretty(&stored).map_err(|e| {
            InjectError::Serialization(format!("failed to serialize FSEvents records: {e}"))
        })?;
        fs::write(&output_file, &json)?;

        let injected_ids: Vec<String> = records
            .iter()
            .map(|r| format!("{}::{}", output_file.display(), r.event_id))
            .collect();

        tracing::info!(
            output = %output_file.display(),
            records = records.len(),
            "fsevents injection complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::MacosFsEvents {
                log_path: output_dir.to_path_buf(),
            },
            strategy: DirectInjection,
            records_injected: records.len(),
            backup_path,
            timestamp: Utc::now(),
            injected_ids,
        })
    }
}

impl Default for FsEventsInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for FsEventsInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        target: &Target,
        strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        if strategy != DirectInjection {
            return Err(InjectError::UnsupportedStrategy {
                strategy: strategy.to_string(),
                target: target.to_string(),
            });
        }

        let output_dir = self.resolve_output_dir(target)?;
        let records: Vec<FsEventRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }
        self.inject_records(&records, &output_dir)
    }

    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        if result.injected_ids.is_empty() {
            return Ok(VerificationStatus::AllPresent { checked: 0 });
        }

        let mut present = 0usize;
        let mut missing_ids = Vec::new();

        for id in &result.injected_ids {
            // ID format: "filepath::event_id"
            let file_path = id.split("::").next().unwrap_or(id);
            let path = PathBuf::from(file_path);
            if path.exists() {
                present += 1;
            } else {
                missing_ids.push(id.clone());
            }
        }

        let total = result.injected_ids.len();
        if present == total {
            Ok(VerificationStatus::AllPresent { checked: total })
        } else if present == 0 {
            Ok(VerificationStatus::NonePresent { expected: total })
        } else {
            Ok(VerificationStatus::PartiallyPresent {
                present,
                missing: total - present,
                missing_ids,
            })
        }
    }

    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        let mut files_to_remove = std::collections::HashSet::new();
        for id in &result.injected_ids {
            let file_path = id.split("::").next().unwrap_or(id);
            files_to_remove.insert(PathBuf::from(file_path));
        }

        for file_path in &files_to_remove {
            if file_path.exists() {
                fs::remove_file(file_path).map_err(|e| InjectError::RollbackFailed {
                    reason: format!("failed to remove {}: {e}", file_path.display()),
                })?;
                tracing::debug!(path = %file_path.display(), "fsevents file removed during rollback");
            }
        }

        tracing::info!(
            target = %result.target,
            removed = files_to_remove.len(),
            "fsevents rollback complete"
        );

        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();

        if let Some(dir) = &self.output_dir_override {
            targets.push(Target::MacosFsEvents {
                log_path: dir.clone(),
            });
        } else {
            // Standard macOS FSEvents store location.
            let fseventsd = PathBuf::from("/.fseventsd");
            targets.push(Target::MacosFsEvents {
                log_path: fseventsd,
            });
        }

        targets
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        vec![DirectInjection]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a timestamped backup of a file.
fn backup_file(file_path: &Path) -> Result<PathBuf> {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let backup_name = format!("{file_name}.plausiden-backup.{timestamp}");
    let backup_path = file_path.with_file_name(backup_name);

    fs::copy(file_path, &backup_path).map_err(|e| InjectError::BackupFailed {
        path: file_path.to_path_buf(),
        reason: e.to_string(),
    })?;

    tracing::debug!(
        src = %file_path.display(),
        dst = %backup_path.display(),
        "file backed up"
    );

    Ok(backup_path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_records() -> Vec<FsEventRecord> {
        vec![
            FsEventRecord {
                event_id: 1001,
                path: "/Users/test/Documents/report.pdf".to_string(),
                flags: vec![FsEventFlag::Created],
                timestamp: "2026-03-15T14:30:00Z".parse().unwrap(),
            },
            FsEventRecord {
                event_id: 1002,
                path: "/Users/test/Documents/report.pdf".to_string(),
                flags: vec![FsEventFlag::Modified, FsEventFlag::XattrModified],
                timestamp: "2026-03-15T15:00:00Z".parse().unwrap(),
            },
            FsEventRecord {
                event_id: 1003,
                path: "/Users/test/Desktop/old_notes.txt".to_string(),
                flags: vec![FsEventFlag::Removed],
                timestamp: "2026-04-01T09:15:00Z".parse().unwrap(),
            },
        ]
    }

    fn to_artifact(records: &[FsEventRecord]) -> Vec<u8> {
        serde_json::to_vec(records).unwrap()
    }

    #[test]
    fn flag_raw_values() {
        assert_eq!(FsEventFlag::Created.raw_flag(), 0x0100);
        assert_eq!(FsEventFlag::Modified.raw_flag(), 0x1000);
        assert_eq!(FsEventFlag::Removed.raw_flag(), 0x0200);
        assert_eq!(FsEventFlag::Renamed.raw_flag(), 0x0800);
        assert_eq!(FsEventFlag::OwnerChange.raw_flag(), 0x4000);
        assert_eq!(FsEventFlag::XattrModified.raw_flag(), 0x8000);
    }

    #[test]
    fn combined_flags_bitmask() {
        let record = FsEventRecord {
            event_id: 1,
            path: "/test".to_string(),
            flags: vec![FsEventFlag::Created, FsEventFlag::Modified],
            timestamp: "2026-01-01T00:00:00Z".parse().unwrap(),
        };
        // Created (0x0100) | Modified (0x1000) = 0x1100
        assert_eq!(record.combined_flags(), 0x1100);
    }

    #[test]
    fn inject_creates_fsevents_json() {
        let tmp = TempDir::new().unwrap();
        let injector = FsEventsInjector::with_output_dir(tmp.path().to_path_buf());
        let records = sample_records();
        let artifact = to_artifact(&records);
        let target = Target::MacosFsEvents {
            log_path: tmp.path().to_path_buf(),
        };

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        assert_eq!(result.records_injected, 3);
        assert_eq!(result.injected_ids.len(), 3);

        // Verify the JSON file was created with raw_flags.
        let file_path = result.injected_ids[0].split("::").next().unwrap();
        let contents = fs::read_to_string(file_path).unwrap();
        let parsed: Vec<FsEventStoredRecord> = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].event_id, 1001);
        assert_eq!(parsed[0].raw_flags, FsEventFlag::Created.raw_flag());
        // Second record has Modified|XattrModified
        assert_eq!(
            parsed[1].raw_flags,
            FsEventFlag::Modified.raw_flag() | FsEventFlag::XattrModified.raw_flag()
        );
    }

    #[test]
    fn verify_after_injection() {
        let tmp = TempDir::new().unwrap();
        let injector = FsEventsInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::MacosFsEvents {
            log_path: tmp.path().to_path_buf(),
        };

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::AllPresent { checked: 3 });
    }

    #[test]
    fn verify_detects_missing_file() {
        let tmp = TempDir::new().unwrap();
        let injector = FsEventsInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::MacosFsEvents {
            log_path: tmp.path().to_path_buf(),
        };

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        // Remove the file manually.
        let file_path = result.injected_ids[0].split("::").next().unwrap();
        fs::remove_file(file_path).unwrap();

        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::NonePresent { expected: 3 });
    }

    #[test]
    fn rollback_removes_injected_file() {
        let tmp = TempDir::new().unwrap();
        let injector = FsEventsInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::MacosFsEvents {
            log_path: tmp.path().to_path_buf(),
        };

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        let file_path = result.injected_ids[0].split("::").next().unwrap();
        assert!(PathBuf::from(file_path).exists());

        injector.rollback(&result).unwrap();
        assert!(!PathBuf::from(file_path).exists());
    }

    #[test]
    fn reject_unsupported_strategy() {
        let tmp = TempDir::new().unwrap();
        let injector = FsEventsInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::MacosFsEvents {
            log_path: tmp.path().to_path_buf(),
        };

        let err = injector
            .inject(
                &artifact,
                &target,
                InjectionStrategy::TranslatorInterposition,
            )
            .unwrap_err();
        assert!(matches!(err, InjectError::UnsupportedStrategy { .. }));
    }

    #[test]
    fn reject_empty_artifact() {
        let tmp = TempDir::new().unwrap();
        let injector = FsEventsInjector::with_output_dir(tmp.path().to_path_buf());
        let empty: Vec<FsEventRecord> = vec![];
        let artifact = to_artifact(&empty);
        let target = Target::MacosFsEvents {
            log_path: tmp.path().to_path_buf(),
        };

        let err = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap_err();
        assert!(matches!(err, InjectError::EmptyArtifact));
    }

    #[test]
    fn reject_wrong_target() {
        let injector = FsEventsInjector::new();
        let artifact = to_artifact(&sample_records());
        let target = Target::Filesystem {
            path: PathBuf::from("/tmp"),
        };

        let err = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap_err();
        assert!(matches!(err, InjectError::UnsupportedTarget { .. }));
    }

    #[test]
    fn record_serialization_roundtrip() {
        let records = sample_records();
        let json = serde_json::to_string(&records).unwrap();
        let parsed: Vec<FsEventRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), records.len());
        assert_eq!(parsed[0].event_id, 1001);
        assert_eq!(parsed[2].flags, vec![FsEventFlag::Removed]);
    }

    #[test]
    fn supported_strategies_returns_direct() {
        let injector = FsEventsInjector::new();
        let strategies = injector.supported_strategies();
        assert_eq!(strategies, vec![DirectInjection]);
    }
}
