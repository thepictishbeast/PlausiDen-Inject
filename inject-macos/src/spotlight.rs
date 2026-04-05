//! macOS Spotlight metadata injection.
//!
//! Spotlight indexes file metadata in `.Spotlight-V100` stores.  Each indexed
//! file gets a record containing the file path, content type (UTI), display
//! name, last-used date, and a content hash.
//!
//! This module serializes synthetic Spotlight index records as JSON files in
//! an output directory, mimicking the structure that macOS maintains in
//! `/.Spotlight-V100/` and per-volume stores.

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

/// A single Spotlight metadata record produced by plausiden-engine.
///
/// Models the key attributes that Spotlight stores for indexed files:
/// `kMDItemPath`, `kMDItemContentType`, `kMDItemDisplayName`,
/// `kMDItemLastUsedDate`, and `kMDItemContentHash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpotlightRecord {
    /// Full path to the indexed file (kMDItemPath).
    pub file_path: String,
    /// Uniform Type Identifier (kMDItemContentType), e.g. `"public.plain-text"`.
    pub content_type: String,
    /// Display name shown in Spotlight results (kMDItemDisplayName).
    pub display_name: String,
    /// Last time the file was opened/used (kMDItemLastUsedDate).
    pub last_used: DateTime<Utc>,
    /// SHA-256 content hash for integrity (kMDItemContentHash).
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// Injector implementation
// ---------------------------------------------------------------------------

/// Spotlight metadata injector for macOS systems.
///
/// Writes synthetic `.spotlight-V100`-style JSON index records into an
/// output directory.  Each injection run creates a single JSON file
/// containing all injected records.
pub struct SpotlightInjector {
    /// Override output directory for testing; if `None`, auto-discover.
    output_dir_override: Option<PathBuf>,
}

impl SpotlightInjector {
    /// Create a new injector that will auto-discover the Spotlight store.
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

    /// Resolve the output directory from the `Target` variant or
    /// the configured override.
    fn resolve_output_dir(&self, target: &Target) -> Result<PathBuf> {
        if let Some(dir) = &self.output_dir_override {
            return Ok(dir.clone());
        }
        match target {
            Target::MacosSpotlight { store_path } => Ok(store_path.clone()),
            other => Err(InjectError::UnsupportedTarget {
                description: format!("SpotlightInjector does not handle {other}"),
            }),
        }
    }

    /// Write Spotlight records to the output directory as a JSON file.
    fn inject_records(
        &self,
        records: &[SpotlightRecord],
        output_dir: &Path,
    ) -> Result<InjectionResult> {
        fs::create_dir_all(output_dir)?;

        let run_id = Uuid::new_v4();
        let output_file = output_dir.join(format!("spotlight-{run_id}.json"));

        // Back up if the file already exists.
        let backup_path = if output_file.exists() {
            Some(backup_file(&output_file)?)
        } else {
            None
        };

        let json = serde_json::to_string_pretty(records).map_err(|e| {
            InjectError::Serialization(format!("failed to serialize Spotlight records: {e}"))
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
            "spotlight metadata injection complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::MacosSpotlight {
                store_path: output_dir.to_path_buf(),
            },
            strategy: DirectInjection,
            records_injected: records.len(),
            backup_path,
            timestamp: Utc::now(),
            injected_ids,
        })
    }
}

impl Default for SpotlightInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for SpotlightInjector {
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
        let records: Vec<SpotlightRecord> = serde_json::from_slice(artifact_bytes)?;
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
        // Collect unique file paths from injected_ids.
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
                tracing::debug!(path = %file_path.display(), "spotlight file removed during rollback");
            }
        }

        // Restore backup if available.
        if let Some(backup) = &result.backup_path {
            if backup.exists() {
                if let Target::MacosSpotlight { store_path } = &result.target {
                    // The backup corresponds to the output file; restore it.
                    let original_name = backup
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .split(".plausiden-backup.")
                        .next()
                        .unwrap_or("spotlight.json");
                    let dest = store_path.join(original_name);
                    fs::copy(backup, &dest).map_err(|e| InjectError::RollbackFailed {
                        reason: format!(
                            "failed to restore backup {} -> {}: {e}",
                            backup.display(),
                            dest.display()
                        ),
                    })?;
                }
            }
        }

        tracing::info!(
            target = %result.target,
            removed = files_to_remove.len(),
            "spotlight rollback complete"
        );

        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();

        if let Some(dir) = &self.output_dir_override {
            targets.push(Target::MacosSpotlight {
                store_path: dir.clone(),
            });
        } else if let Ok(home) = std::env::var("HOME") {
            // Standard macOS Spotlight store location.
            let spotlight_dir = PathBuf::from(&home)
                .join("Library")
                .join(".Spotlight-V100");
            targets.push(Target::MacosSpotlight {
                store_path: spotlight_dir,
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

    fn sample_records() -> Vec<SpotlightRecord> {
        vec![
            SpotlightRecord {
                file_path: "/Users/test/Documents/report.pdf".to_string(),
                content_type: "com.adobe.pdf".to_string(),
                display_name: "report.pdf".to_string(),
                last_used: "2026-03-15T14:30:00Z".parse().unwrap(),
                content_hash: "a1b2c3d4e5f6".to_string(),
            },
            SpotlightRecord {
                file_path: "/Users/test/Desktop/notes.txt".to_string(),
                content_type: "public.plain-text".to_string(),
                display_name: "notes.txt".to_string(),
                last_used: "2026-04-01T09:15:00Z".parse().unwrap(),
                content_hash: "f6e5d4c3b2a1".to_string(),
            },
        ]
    }

    fn to_artifact(records: &[SpotlightRecord]) -> Vec<u8> {
        serde_json::to_vec(records).unwrap()
    }

    #[test]
    fn inject_creates_spotlight_json() {
        let tmp = TempDir::new().unwrap();
        let injector = SpotlightInjector::with_output_dir(tmp.path().to_path_buf());
        let records = sample_records();
        let artifact = to_artifact(&records);
        let target = Target::MacosSpotlight {
            store_path: tmp.path().to_path_buf(),
        };

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        assert_eq!(result.records_injected, 2);
        assert_eq!(result.injected_ids.len(), 2);

        // Verify the JSON file was created.
        let file_path = result.injected_ids[0].split("::").next().unwrap();
        let contents = fs::read_to_string(file_path).unwrap();
        let parsed: Vec<SpotlightRecord> = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].display_name, "report.pdf");
        assert_eq!(parsed[1].content_type, "public.plain-text");
    }

    #[test]
    fn verify_after_injection() {
        let tmp = TempDir::new().unwrap();
        let injector = SpotlightInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::MacosSpotlight {
            store_path: tmp.path().to_path_buf(),
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
        let injector = SpotlightInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::MacosSpotlight {
            store_path: tmp.path().to_path_buf(),
        };

        let result = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap();

        // Remove the file manually.
        let file_path = result.injected_ids[0].split("::").next().unwrap();
        fs::remove_file(file_path).unwrap();

        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::NonePresent { expected: 2 });
    }

    #[test]
    fn rollback_removes_injected_file() {
        let tmp = TempDir::new().unwrap();
        let injector = SpotlightInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::MacosSpotlight {
            store_path: tmp.path().to_path_buf(),
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
        let injector = SpotlightInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::MacosSpotlight {
            store_path: tmp.path().to_path_buf(),
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
        let injector = SpotlightInjector::with_output_dir(tmp.path().to_path_buf());
        let empty: Vec<SpotlightRecord> = vec![];
        let artifact = to_artifact(&empty);
        let target = Target::MacosSpotlight {
            store_path: tmp.path().to_path_buf(),
        };

        let err = injector
            .inject(&artifact, &target, DirectInjection)
            .unwrap_err();
        assert!(matches!(err, InjectError::EmptyArtifact));
    }

    #[test]
    fn reject_wrong_target() {
        let injector = SpotlightInjector::new();
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
        let parsed: Vec<SpotlightRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), records.len());
        assert_eq!(parsed[0].file_path, records[0].file_path);
        assert_eq!(parsed[1].content_hash, records[1].content_hash);
    }

    #[test]
    fn supported_strategies_returns_direct() {
        let injector = SpotlightInjector::new();
        let strategies = injector.supported_strategies();
        assert_eq!(strategies, vec![DirectInjection]);
    }
}
