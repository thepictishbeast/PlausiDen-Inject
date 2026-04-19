//! macOS filesystem artifact injection (HFS+/APFS metadata).
//!
//! macOS filesystems (HFS+ and APFS) support rich per-file metadata beyond
//! standard POSIX attributes:
//!
//! - **Extended attributes (xattr)**: arbitrary key-value pairs stored on
//!   files, commonly used for Spotlight comments (`com.apple.metadata:kMDItemFinderComment`),
//!   quarantine info (`com.apple.quarantine`), and download origin
//!   (`com.apple.metadata:kMDItemWhereFroms`).
//!
//! - **Resource forks**: legacy HFS+ mechanism for storing structured data
//!   alongside a file.  APFS stores them as extended attributes under the
//!   `com.apple.ResourceFork` key.
//!
//! - **Spotlight comments**: `kMDItemFinderComment` stored as an xattr.
//!
//! This module serializes synthetic macOS filesystem records as JSON files,
//! including path, extended attributes, resource fork data, and Spotlight
//! comments.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{
    InjectionResult, InjectionStrategy, InjectionStrategy::DirectInjection, Injector, Target,
    VerificationStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Artifact schema (deserialized from engine output)
// ---------------------------------------------------------------------------

/// A single macOS filesystem record produced by plausiden-engine.
///
/// Represents a file with its HFS+/APFS metadata attributes including
/// extended attributes, resource fork, and Spotlight comments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosFileRecord {
    /// Full path to the file.
    pub path: String,
    /// File display name.
    pub filename: String,
    /// File size in bytes.
    pub file_size: u64,
    /// Extended attributes (xattr key-value pairs).
    ///
    /// Common keys:
    /// - `com.apple.quarantine` -- download quarantine flag
    /// - `com.apple.metadata:kMDItemWhereFroms` -- download origin URLs
    /// - `com.apple.metadata:kMDItemFinderComment` -- Finder comment
    /// - `com.apple.FinderInfo` -- Finder display hints
    #[serde(default)]
    pub xattrs: HashMap<String, String>,
    /// Resource fork data (Base64-encoded if binary).
    /// On APFS this is stored as the `com.apple.ResourceFork` xattr.
    #[serde(default)]
    pub resource_fork: Option<String>,
    /// Spotlight / Finder comment (kMDItemFinderComment).
    #[serde(default)]
    pub spotlight_comment: Option<String>,
    /// Creation timestamp (APFS stores creation time separately from ctime).
    pub created: Option<DateTime<Utc>>,
    /// Last modification timestamp.
    pub modified: Option<DateTime<Utc>>,
    /// Last accessed timestamp.
    pub accessed: Option<DateTime<Utc>>,
}

/// Internal stored representation with all metadata resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MacosFileStoredRecord {
    path: String,
    filename: String,
    file_size: u64,
    xattrs: HashMap<String, String>,
    resource_fork: Option<String>,
    spotlight_comment: Option<String>,
    created: Option<DateTime<Utc>>,
    modified: Option<DateTime<Utc>>,
    accessed: Option<DateTime<Utc>>,
}

impl MacosFileStoredRecord {
    fn from_record(record: &MacosFileRecord) -> Self {
        let mut xattrs = record.xattrs.clone();

        // If a resource fork is provided, store it as the standard xattr.
        if let Some(ref rfork) = record.resource_fork {
            xattrs
                .entry("com.apple.ResourceFork".to_string())
                .or_insert_with(|| rfork.clone());
        }

        // If a Spotlight comment is provided, store it as the standard xattr.
        if let Some(ref comment) = record.spotlight_comment {
            xattrs
                .entry("com.apple.metadata:kMDItemFinderComment".to_string())
                .or_insert_with(|| comment.clone());
        }

        Self {
            path: record.path.clone(),
            filename: record.filename.clone(),
            file_size: record.file_size,
            xattrs,
            resource_fork: record.resource_fork.clone(),
            spotlight_comment: record.spotlight_comment.clone(),
            created: record.created,
            modified: record.modified,
            accessed: record.accessed,
        }
    }
}

// ---------------------------------------------------------------------------
// Injector implementation
// ---------------------------------------------------------------------------

/// macOS filesystem injector for HFS+/APFS metadata.
///
/// Writes synthetic filesystem records including extended attributes,
/// resource forks, and Spotlight comments as JSON files in an output
/// directory.
pub struct MacosFilesystemInjector {
    /// Override output directory for testing.
    output_dir_override: Option<PathBuf>,
}

impl MacosFilesystemInjector {
    /// Create a new injector.
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
            Target::Filesystem { path } => Ok(path.clone()),
            other => Err(InjectError::UnsupportedTarget {
                description: format!("MacosFilesystemInjector does not handle {other}"),
            }),
        }
    }

    /// Write macOS filesystem records to the output directory as a JSON file.
    fn inject_records(
        &self,
        records: &[MacosFileRecord],
        output_dir: &Path,
    ) -> Result<InjectionResult> {
        fs::create_dir_all(output_dir)?;

        let run_id = Uuid::new_v4();
        let output_file = output_dir.join(format!("macos-fs-{run_id}.json"));

        // Back up if the file already exists.
        let backup_path = if output_file.exists() {
            Some(backup_file(&output_file)?)
        } else {
            None
        };

        // Convert to stored format (resolves xattr merging).
        let stored: Vec<MacosFileStoredRecord> = records
            .iter()
            .map(MacosFileStoredRecord::from_record)
            .collect();

        let json = serde_json::to_string_pretty(&stored).map_err(|e| {
            InjectError::Serialization(format!("failed to serialize macOS filesystem records: {e}"))
        })?;
        fs::write(&output_file, &json)?;

        let injected_ids: Vec<String> = records
            .iter()
            .enumerate()
            .map(|(i, _r)| format!("{}::{}", output_file.display(), i))
            .collect();

        tracing::info!(
            output = %output_file.display(),
            records = records.len(),
            "macos filesystem injection complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::Filesystem {
                path: output_dir.to_path_buf(),
            },
            strategy: DirectInjection,
            records_injected: records.len(),
            backup_path,
            timestamp: Utc::now(),
            injected_ids,
        })
    }
}

impl Default for MacosFilesystemInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for MacosFilesystemInjector {
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
        let records: Vec<MacosFileRecord> = serde_json::from_slice(artifact_bytes)?;
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
            // ID format: "filepath::index"
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
                tracing::debug!(path = %file_path.display(), "macos-fs file removed during rollback");
            }
        }

        tracing::info!(
            target = %result.target,
            removed = files_to_remove.len(),
            "macos filesystem rollback complete"
        );

        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();

        if let Some(dir) = &self.output_dir_override {
            targets.push(Target::Filesystem { path: dir.clone() });
        } else if let Ok(home) = std::env::var("HOME") {
            let documents = PathBuf::from(&home).join("Documents");
            targets.push(Target::Filesystem { path: documents });

            let downloads = PathBuf::from(&home).join("Downloads");
            targets.push(Target::Filesystem { path: downloads });

            let desktop = PathBuf::from(&home).join("Desktop");
            targets.push(Target::Filesystem { path: desktop });
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

    fn sample_records() -> Vec<MacosFileRecord> {
        let mut xattrs1 = HashMap::new();
        xattrs1.insert(
            "com.apple.quarantine".to_string(),
            "0083;5f1234ab;Safari;".to_string(),
        );
        xattrs1.insert(
            "com.apple.metadata:kMDItemWhereFroms".to_string(),
            "https://example.com/report.pdf".to_string(),
        );

        vec![
            MacosFileRecord {
                path: "/Users/test/Downloads/report.pdf".to_string(),
                filename: "report.pdf".to_string(),
                file_size: 524288,
                xattrs: xattrs1,
                resource_fork: None,
                spotlight_comment: Some("Q4 financial report".to_string()),
                created: Some("2026-03-15T14:30:00Z".parse().unwrap()),
                modified: Some("2026-03-15T14:30:00Z".parse().unwrap()),
                accessed: Some("2026-04-01T09:15:00Z".parse().unwrap()),
            },
            MacosFileRecord {
                path: "/Users/test/Documents/photo.jpg".to_string(),
                filename: "photo.jpg".to_string(),
                file_size: 2097152,
                xattrs: HashMap::new(),
                resource_fork: Some("AAAAAABBBBBB".to_string()),
                spotlight_comment: None,
                created: Some("2026-01-10T08:00:00Z".parse().unwrap()),
                modified: Some("2026-02-20T12:00:00Z".parse().unwrap()),
                accessed: None,
            },
        ]
    }

    fn to_artifact(records: &[MacosFileRecord]) -> Vec<u8> {
        serde_json::to_vec(records).unwrap()
    }

    #[test]
    fn inject_creates_macos_fs_json() {
        let tmp = TempDir::new().unwrap();
        let injector = MacosFilesystemInjector::with_output_dir(tmp.path().to_path_buf());
        let records = sample_records();
        let artifact = to_artifact(&records);
        let target = Target::Filesystem {
            path: tmp.path().to_path_buf(),
        };

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        assert_eq!(result.records_injected, 2);
        assert_eq!(result.injected_ids.len(), 2);

        // Verify the JSON file was created.
        let file_path = result.injected_ids[0].split("::").next().unwrap();
        let contents = fs::read_to_string(file_path).unwrap();
        let parsed: Vec<MacosFileStoredRecord> = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].filename, "report.pdf");
        assert_eq!(parsed[1].filename, "photo.jpg");
    }

    #[test]
    fn stored_record_merges_resource_fork_xattr() {
        let records = sample_records();
        let stored = MacosFileStoredRecord::from_record(&records[1]);

        // photo.jpg has a resource fork; it should appear as an xattr.
        assert!(stored.xattrs.contains_key("com.apple.ResourceFork"));
        assert_eq!(stored.xattrs["com.apple.ResourceFork"], "AAAAAABBBBBB");
    }

    #[test]
    fn stored_record_merges_spotlight_comment_xattr() {
        let records = sample_records();
        let stored = MacosFileStoredRecord::from_record(&records[0]);

        // report.pdf has a Spotlight comment; it should appear as an xattr.
        assert!(
            stored
                .xattrs
                .contains_key("com.apple.metadata:kMDItemFinderComment")
        );
        assert_eq!(
            stored.xattrs["com.apple.metadata:kMDItemFinderComment"],
            "Q4 financial report"
        );
    }

    #[test]
    fn verify_after_injection() {
        let tmp = TempDir::new().unwrap();
        let injector = MacosFilesystemInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::Filesystem {
            path: tmp.path().to_path_buf(),
        };

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::AllPresent { checked: 2 });
    }

    #[test]
    fn verify_detects_missing_file() {
        let tmp = TempDir::new().unwrap();
        let injector = MacosFilesystemInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::Filesystem {
            path: tmp.path().to_path_buf(),
        };

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        let file_path = result.injected_ids[0].split("::").next().unwrap();
        fs::remove_file(file_path).unwrap();

        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::NonePresent { expected: 2 });
    }

    #[test]
    fn rollback_removes_injected_file() {
        let tmp = TempDir::new().unwrap();
        let injector = MacosFilesystemInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::Filesystem {
            path: tmp.path().to_path_buf(),
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
        let injector = MacosFilesystemInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::Filesystem {
            path: tmp.path().to_path_buf(),
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
        let injector = MacosFilesystemInjector::with_output_dir(tmp.path().to_path_buf());
        let empty: Vec<MacosFileRecord> = vec![];
        let artifact = to_artifact(&empty);
        let target = Target::Filesystem {
            path: tmp.path().to_path_buf(),
        };

        let err = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap_err();
        assert!(matches!(err, InjectError::EmptyArtifact));
    }

    #[test]
    fn reject_wrong_target() {
        let injector = MacosFilesystemInjector::new();
        let artifact = to_artifact(&sample_records());
        let target = Target::MacosFsEvents {
            log_path: PathBuf::from("/tmp"),
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
        let parsed: Vec<MacosFileRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), records.len());
        assert_eq!(parsed[0].path, records[0].path);
        assert_eq!(parsed[1].resource_fork, records[1].resource_fork);
    }

    #[test]
    fn supported_strategies_returns_direct() {
        let injector = MacosFilesystemInjector::new();
        let strategies = injector.supported_strategies();
        assert_eq!(strategies, vec![DirectInjection]);
    }

    #[test]
    fn xattrs_preserved_when_no_resource_fork() {
        let mut xattrs = HashMap::new();
        xattrs.insert("com.apple.quarantine".to_string(), "test-value".to_string());

        let record = MacosFileRecord {
            path: "/test/file.txt".to_string(),
            filename: "file.txt".to_string(),
            file_size: 100,
            xattrs,
            resource_fork: None,
            spotlight_comment: None,
            created: None,
            modified: None,
            accessed: None,
        };

        let stored = MacosFileStoredRecord::from_record(&record);
        assert_eq!(stored.xattrs.len(), 1);
        assert_eq!(stored.xattrs["com.apple.quarantine"], "test-value");
        // No ResourceFork xattr should be added.
        assert!(!stored.xattrs.contains_key("com.apple.ResourceFork"));
    }
}
