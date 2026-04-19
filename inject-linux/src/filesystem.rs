//! Filesystem artifact injection (timestamps, file content, metadata).
//!
//! Writes generated files to disk with controlled timestamps, ownership,
//! and extended attributes to match plausiden-engine output.

use chrono::{DateTime, Utc};
use filetime::FileTime;
use inject_core::error::{InjectError, Result};
use inject_core::{
    InjectionResult, InjectionStrategy, InjectionStrategy::DirectInjection, Injector, Target,
    VerificationStatus,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Artifact schema (deserialized from engine output)
// ---------------------------------------------------------------------------

/// A filesystem artifact record produced by plausiden-engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileArtifact {
    pub filename: String,
    pub path: String,
    #[serde(default)]
    pub mime_type: String,
    pub file_size: u64,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Injector implementation
// ---------------------------------------------------------------------------

/// Linux filesystem injector.
pub struct FilesystemInjector;

impl FilesystemInjector {
    /// Create a new filesystem injector.
    pub fn new() -> Self {
        Self
    }

    /// Inject a single file artifact to disk.
    fn inject_file(&self, artifact: &FileArtifact) -> Result<PathBuf> {
        let file_path = PathBuf::from(&artifact.path);

        // Create parent directories if they don't exist.
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Generate random content of the specified size.
        let mut rng = rand::thread_rng();
        let mut content = vec![0u8; artifact.file_size as usize];
        rng.fill(content.as_mut_slice());

        std::fs::write(&file_path, &content)?;

        // Set timestamps using filetime.
        let mtime = artifact
            .modified
            .map(|dt| FileTime::from_unix_time(dt.timestamp(), dt.timestamp_subsec_nanos()))
            .unwrap_or_else(|| FileTime::now());

        let atime = artifact
            .accessed
            .map(|dt| FileTime::from_unix_time(dt.timestamp(), dt.timestamp_subsec_nanos()))
            .unwrap_or_else(|| FileTime::now());

        filetime::set_file_times(&file_path, atime, mtime)?;

        tracing::debug!(
            path = %file_path.display(),
            size = artifact.file_size,
            "file artifact written"
        );

        Ok(file_path)
    }
}

impl Default for FilesystemInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for FilesystemInjector {
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

        match target {
            Target::Filesystem { .. } => {}
            other => {
                return Err(InjectError::UnsupportedTarget {
                    description: format!("FilesystemInjector does not handle {other}"),
                });
            }
        }

        let artifacts: Vec<FileArtifact> = serde_json::from_slice(artifact_bytes)?;
        if artifacts.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::with_capacity(artifacts.len());

        // Back up any existing files before overwriting.
        for artifact in &artifacts {
            let file_path = PathBuf::from(&artifact.path);
            if file_path.exists() {
                backup_file(&file_path)?;
            }
        }

        for artifact in &artifacts {
            let created_path = self.inject_file(artifact)?;
            injected_ids.push(created_path.to_string_lossy().into_owned());
        }

        tracing::info!(records = artifacts.len(), "filesystem injection complete");

        Ok(InjectionResult {
            run_id,
            target: target.clone(),
            strategy: DirectInjection,
            records_injected: artifacts.len(),
            backup_path: None,
            timestamp: Utc::now(),
            injected_ids,
        })
    }

    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        if result.injected_ids.is_empty() {
            return Ok(VerificationStatus::AllPresent { checked: 0 });
        }

        let mut present = 0usize;
        let mut missing_ids = Vec::new();

        for id in &result.injected_ids {
            let file_path = PathBuf::from(id);
            if file_path.exists() {
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
        for id in &result.injected_ids {
            let file_path = PathBuf::from(id);
            if file_path.exists() {
                std::fs::remove_file(&file_path).map_err(|e| InjectError::RollbackFailed {
                    reason: format!("failed to remove {}: {e}", file_path.display()),
                })?;
                tracing::debug!(path = %file_path.display(), "file removed during rollback");
            }
        }

        tracing::info!(
            target = %result.target,
            removed = result.injected_ids.len(),
            "filesystem rollback complete"
        );

        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        // The filesystem injector can target any writable directory.
        // Return a sensible default based on the user's home directory.
        let mut targets = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            let docs = PathBuf::from(&home).join("Documents");
            targets.push(Target::Filesystem { path: docs });

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

/// Create a backup copy of an existing file before overwriting.
fn backup_file(file_path: &Path) -> Result<PathBuf> {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let backup_name = format!("{file_name}.plausiden-backup.{timestamp}");
    let backup_path = file_path.with_file_name(backup_name);

    std::fs::copy(file_path, &backup_path).map_err(|e| InjectError::BackupFailed {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a JSON artifact payload for a single file.
    fn make_artifact_json(dir: &Path, filename: &str, size: u64) -> Vec<u8> {
        let path = dir.join(filename);
        let artifacts = vec![FileArtifact {
            filename: filename.to_string(),
            path: path.to_string_lossy().into_owned(),
            mime_type: "application/octet-stream".to_string(),
            file_size: size,
            created: Some("2026-01-15T10:30:00Z".parse().unwrap()),
            modified: Some("2026-03-20T14:22:00Z".parse().unwrap()),
            accessed: Some("2026-04-05T09:00:00Z".parse().unwrap()),
        }];
        serde_json::to_vec(&artifacts).unwrap()
    }

    fn make_target(dir: &Path) -> Target {
        Target::Filesystem {
            path: dir.to_path_buf(),
        }
    }

    #[test]
    fn inject_creates_file_with_correct_size() {
        let tmp = TempDir::new().unwrap();
        let injector = FilesystemInjector::new();
        let artifact = make_artifact_json(tmp.path(), "test_doc.txt", 4096);
        let target = make_target(tmp.path());

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        assert_eq!(result.records_injected, 1);
        let created = PathBuf::from(&result.injected_ids[0]);
        assert!(created.exists());
        let meta = std::fs::metadata(&created).unwrap();
        assert_eq!(meta.len(), 4096);
    }

    #[test]
    fn inject_sets_timestamps_correctly() {
        let tmp = TempDir::new().unwrap();
        let injector = FilesystemInjector::new();
        let artifact = make_artifact_json(tmp.path(), "timestamped.bin", 128);
        let target = make_target(tmp.path());

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        let created = PathBuf::from(&result.injected_ids[0]);
        let mtime = FileTime::from_last_modification_time(&std::fs::metadata(&created).unwrap());

        let expected_mtime: DateTime<Utc> = "2026-03-20T14:22:00Z".parse().unwrap();
        let expected_ft = FileTime::from_unix_time(
            expected_mtime.timestamp(),
            expected_mtime.timestamp_subsec_nanos(),
        );

        assert_eq!(
            mtime.unix_seconds(),
            expected_ft.unix_seconds(),
            "mtime should match the artifact's modified timestamp"
        );
    }

    #[test]
    fn inject_creates_parent_directories() {
        let tmp = TempDir::new().unwrap();
        let injector = FilesystemInjector::new();

        // Target a file nested several directories deep.
        let nested_dir = tmp.path().join("a").join("b").join("c");
        let nested_path = nested_dir.join("deep_file.dat");
        let artifacts = vec![FileArtifact {
            filename: "deep_file.dat".to_string(),
            path: nested_path.to_string_lossy().into_owned(),
            mime_type: "application/octet-stream".to_string(),
            file_size: 64,
            created: None,
            modified: None,
            accessed: None,
        }];
        let payload = serde_json::to_vec(&artifacts).unwrap();
        let target = make_target(tmp.path());

        let result = injector.inject(&payload, &target, DirectInjection).unwrap();

        let created = PathBuf::from(&result.injected_ids[0]);
        assert!(created.exists());
        assert!(nested_dir.exists());
    }

    #[test]
    fn rollback_deletes_injected_file() {
        let tmp = TempDir::new().unwrap();
        let injector = FilesystemInjector::new();
        let artifact = make_artifact_json(tmp.path(), "to_rollback.txt", 256);
        let target = make_target(tmp.path());

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        let created = PathBuf::from(&result.injected_ids[0]);
        assert!(created.exists(), "file should exist before rollback");

        injector.rollback(&result).unwrap();
        assert!(!created.exists(), "file should be gone after rollback");
    }

    #[test]
    fn verify_confirms_file_exists() {
        let tmp = TempDir::new().unwrap();
        let injector = FilesystemInjector::new();
        let artifact = make_artifact_json(tmp.path(), "verify_me.txt", 512);
        let target = make_target(tmp.path());

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::AllPresent { checked: 1 });
    }

    #[test]
    fn verify_detects_missing_file() {
        let tmp = TempDir::new().unwrap();
        let injector = FilesystemInjector::new();
        let artifact = make_artifact_json(tmp.path(), "will_vanish.txt", 128);
        let target = make_target(tmp.path());

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        // Delete the file manually.
        let created = PathBuf::from(&result.injected_ids[0]);
        std::fs::remove_file(&created).unwrap();

        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::NonePresent { expected: 1 });
    }

    #[test]
    fn reject_unsupported_strategy() {
        let tmp = TempDir::new().unwrap();
        let injector = FilesystemInjector::new();
        let artifact = make_artifact_json(tmp.path(), "nope.txt", 32);
        let target = make_target(tmp.path());

        let err = injector
            .inject(
                &artifact,
                &target,
                InjectionStrategy::TranslatorInterposition,
            )
            .unwrap_err();

        assert!(
            matches!(err, InjectError::UnsupportedStrategy { .. }),
            "should reject non-DirectInjection strategy"
        );
    }

    #[test]
    fn reject_empty_artifact() {
        let injector = FilesystemInjector::new();
        let payload = serde_json::to_vec(&Vec::<FileArtifact>::new()).unwrap();
        let target = Target::Filesystem {
            path: PathBuf::from("/tmp"),
        };

        let err = injector
            .inject(&payload, &target, DirectInjection)
            .unwrap_err();

        assert!(
            matches!(err, InjectError::EmptyArtifact),
            "should reject empty artifact list"
        );
    }

    #[test]
    fn backup_existing_file_before_overwrite() {
        let tmp = TempDir::new().unwrap();
        let injector = FilesystemInjector::new();
        let file_path = tmp.path().join("existing.txt");

        // Create a pre-existing file.
        std::fs::write(&file_path, b"original content").unwrap();

        let artifact = make_artifact_json(tmp.path(), "existing.txt", 100);
        let target = make_target(tmp.path());

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        // The original file should now be backed up.
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("plausiden-backup"))
            .collect();
        assert!(
            !entries.is_empty(),
            "backup file should exist for pre-existing file"
        );

        // The injected file should have the new size.
        let created = PathBuf::from(&result.injected_ids[0]);
        let meta = std::fs::metadata(&created).unwrap();
        assert_eq!(meta.len(), 100);
    }
}
