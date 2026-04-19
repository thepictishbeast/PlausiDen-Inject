//! CoreData persistent store injection.
//!
//! macOS CoreData (NSPersistentStore) backs many first-party apps (Notes,
//! Reminders, Photos, etc.).  Each managed object has an entity name,
//! attribute dictionary, relationship references, and timestamps stored as
//! seconds since the **CoreData reference date**: 2001-01-01 00:00:00 UTC.
//!
//! This module serializes synthetic CoreData-style records as JSON files in
//! an output directory, mimicking the structure of `NSManagedObject` graphs
//! that a real CoreData SQLite store would contain.

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
// Constants
// ---------------------------------------------------------------------------

/// Seconds between the Unix epoch (1970-01-01) and the CoreData reference
/// date (2001-01-01 00:00:00 UTC).
const COREDATA_EPOCH_OFFSET: i64 = 978_307_200;

// ---------------------------------------------------------------------------
// Timestamp conversion
// ---------------------------------------------------------------------------

/// Convert a Unix timestamp (seconds since 1970-01-01) to a CoreData
/// timestamp (seconds since 2001-01-01).
pub fn unix_to_coredata(unix_secs: i64) -> f64 {
    (unix_secs - COREDATA_EPOCH_OFFSET) as f64
}

/// Convert a CoreData timestamp back to a Unix timestamp.
pub fn coredata_to_unix(coredata_secs: f64) -> i64 {
    coredata_secs as i64 + COREDATA_EPOCH_OFFSET
}

// ---------------------------------------------------------------------------
// Artifact schema (deserialized from engine output)
// ---------------------------------------------------------------------------

/// A single CoreData managed-object record produced by plausiden-engine.
///
/// Models the core attributes of an `NSManagedObject`:
/// - Entity name (the CoreData entity/class, e.g. `"ZNOTE"`, `"ZREMINDER"`)
/// - Attribute values as a string-keyed map
/// - Relationships as entity name + object ID references
/// - Creation and modification timestamps (CoreData epoch)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreDataRecord {
    /// CoreData entity name (e.g. `"ZNOTE"`, `"ZREMINDER"`).
    pub entity_name: String,
    /// Primary key / object ID within the entity table.
    #[serde(default = "default_object_id")]
    pub object_id: u64,
    /// Attribute name-value pairs.
    pub attributes: HashMap<String, serde_json::Value>,
    /// Relationships: maps relationship name to a list of referenced object
    /// IDs in the target entity.
    #[serde(default)]
    pub relationships: HashMap<String, Vec<u64>>,
    /// Unix timestamp for creation (converted to CoreData epoch on write).
    pub created_at: DateTime<Utc>,
    /// Unix timestamp for last modification.
    pub modified_at: DateTime<Utc>,
}

fn default_object_id() -> u64 {
    1
}

/// Internal representation written to JSON, with timestamps already
/// converted to CoreData epoch seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoreDataStoredRecord {
    entity_name: String,
    object_id: u64,
    attributes: HashMap<String, serde_json::Value>,
    relationships: HashMap<String, Vec<u64>>,
    /// Seconds since 2001-01-01 00:00:00 UTC.
    z_creation_date: f64,
    /// Seconds since 2001-01-01 00:00:00 UTC.
    z_modification_date: f64,
}

impl CoreDataStoredRecord {
    fn from_record(record: &CoreDataRecord) -> Self {
        Self {
            entity_name: record.entity_name.clone(),
            object_id: record.object_id,
            attributes: record.attributes.clone(),
            relationships: record.relationships.clone(),
            z_creation_date: unix_to_coredata(record.created_at.timestamp()),
            z_modification_date: unix_to_coredata(record.modified_at.timestamp()),
        }
    }
}

// ---------------------------------------------------------------------------
// Injector implementation
// ---------------------------------------------------------------------------

/// CoreData persistent store injector for macOS systems.
///
/// Writes synthetic NSManagedObject-style JSON records into an output
/// directory.  Each injection run creates a single JSON file containing
/// all injected records with timestamps converted to the CoreData epoch.
pub struct CoreDataInjector {
    /// Override output directory for testing.
    output_dir_override: Option<PathBuf>,
}

impl CoreDataInjector {
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
                description: format!("CoreDataInjector does not handle {other}"),
            }),
        }
    }

    /// Write CoreData records to the output directory as a JSON file.
    fn inject_records(
        &self,
        records: &[CoreDataRecord],
        output_dir: &Path,
    ) -> Result<InjectionResult> {
        fs::create_dir_all(output_dir)?;

        let run_id = Uuid::new_v4();
        let output_file = output_dir.join(format!("coredata-{run_id}.json"));

        // Back up if the file already exists.
        let backup_path = if output_file.exists() {
            Some(backup_file(&output_file)?)
        } else {
            None
        };

        // Convert to stored format (CoreData epoch timestamps).
        let stored: Vec<CoreDataStoredRecord> = records
            .iter()
            .map(CoreDataStoredRecord::from_record)
            .collect();

        let json = serde_json::to_string_pretty(&stored).map_err(|e| {
            InjectError::Serialization(format!("failed to serialize CoreData records: {e}"))
        })?;
        fs::write(&output_file, &json)?;

        let injected_ids: Vec<String> = records
            .iter()
            .map(|r| {
                format!(
                    "{}::{}::{}",
                    output_file.display(),
                    r.entity_name,
                    r.object_id
                )
            })
            .collect();

        tracing::info!(
            output = %output_file.display(),
            records = records.len(),
            "coredata injection complete"
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

impl Default for CoreDataInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for CoreDataInjector {
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
        let records: Vec<CoreDataRecord> = serde_json::from_slice(artifact_bytes)?;
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
            // ID format: "filepath::entity_name::object_id"
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
                tracing::debug!(path = %file_path.display(), "coredata file removed during rollback");
            }
        }

        tracing::info!(
            target = %result.target,
            removed = files_to_remove.len(),
            "coredata rollback complete"
        );

        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();

        if let Some(dir) = &self.output_dir_override {
            targets.push(Target::Filesystem { path: dir.clone() });
        } else if let Ok(home) = std::env::var("HOME") {
            // Common CoreData store locations on macOS.
            let containers = PathBuf::from(&home).join("Library").join("Containers");
            targets.push(Target::Filesystem { path: containers });
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

    fn sample_records() -> Vec<CoreDataRecord> {
        let mut attrs1 = HashMap::new();
        attrs1.insert(
            "ZTITLE".to_string(),
            serde_json::Value::String("Shopping List".to_string()),
        );
        attrs1.insert(
            "ZBODY".to_string(),
            serde_json::Value::String("Eggs, milk, bread".to_string()),
        );

        let mut rels1 = HashMap::new();
        rels1.insert("ZFOLDER".to_string(), vec![1]);

        let mut attrs2 = HashMap::new();
        attrs2.insert(
            "ZTITLE".to_string(),
            serde_json::Value::String("Meeting Notes".to_string()),
        );
        attrs2.insert(
            "ZPRIORITY".to_string(),
            serde_json::Value::Number(serde_json::Number::from(2)),
        );

        vec![
            CoreDataRecord {
                entity_name: "ZNOTE".to_string(),
                object_id: 42,
                attributes: attrs1,
                relationships: rels1,
                created_at: "2026-01-10T08:00:00Z".parse().unwrap(),
                modified_at: "2026-03-15T14:30:00Z".parse().unwrap(),
            },
            CoreDataRecord {
                entity_name: "ZREMINDER".to_string(),
                object_id: 99,
                attributes: attrs2,
                relationships: HashMap::new(),
                created_at: "2026-02-20T12:00:00Z".parse().unwrap(),
                modified_at: "2026-04-01T09:15:00Z".parse().unwrap(),
            },
        ]
    }

    fn to_artifact(records: &[CoreDataRecord]) -> Vec<u8> {
        serde_json::to_vec(records).unwrap()
    }

    #[test]
    fn unix_to_coredata_known_value() {
        // 2001-01-01 00:00:00 UTC in Unix time is 978307200.
        // That should map to CoreData 0.0.
        assert!((unix_to_coredata(978_307_200) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn coredata_to_unix_roundtrip() {
        let unix_ts: i64 = 1_700_000_000;
        let cd = unix_to_coredata(unix_ts);
        let back = coredata_to_unix(cd);
        assert_eq!(back, unix_ts);
    }

    #[test]
    fn inject_creates_coredata_json() {
        let tmp = TempDir::new().unwrap();
        let injector = CoreDataInjector::with_output_dir(tmp.path().to_path_buf());
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

        // Verify the JSON file was created and has CoreData timestamps.
        let file_path = result.injected_ids[0].split("::").next().unwrap();
        let contents = fs::read_to_string(file_path).unwrap();
        let parsed: Vec<CoreDataStoredRecord> = serde_json::from_str(&contents).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].entity_name, "ZNOTE");
        assert_eq!(parsed[0].object_id, 42);
        // Verify CoreData timestamp conversion.
        let expected_creation = unix_to_coredata(
            "2026-01-10T08:00:00Z"
                .parse::<DateTime<Utc>>()
                .unwrap()
                .timestamp(),
        );
        assert!((parsed[0].z_creation_date - expected_creation).abs() < f64::EPSILON);
    }

    #[test]
    fn stored_record_has_coredata_timestamps() {
        let records = sample_records();
        let stored = CoreDataStoredRecord::from_record(&records[0]);

        // z_creation_date should be seconds since 2001-01-01
        let unix_created = records[0].created_at.timestamp();
        let expected = (unix_created - COREDATA_EPOCH_OFFSET) as f64;
        assert!((stored.z_creation_date - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn verify_after_injection() {
        let tmp = TempDir::new().unwrap();
        let injector = CoreDataInjector::with_output_dir(tmp.path().to_path_buf());
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
        let injector = CoreDataInjector::with_output_dir(tmp.path().to_path_buf());
        let artifact = to_artifact(&sample_records());
        let target = Target::Filesystem {
            path: tmp.path().to_path_buf(),
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
        let injector = CoreDataInjector::with_output_dir(tmp.path().to_path_buf());
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
        let injector = CoreDataInjector::with_output_dir(tmp.path().to_path_buf());
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
        let injector = CoreDataInjector::with_output_dir(tmp.path().to_path_buf());
        let empty: Vec<CoreDataRecord> = vec![];
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
    fn record_serialization_roundtrip() {
        let records = sample_records();
        let json = serde_json::to_string(&records).unwrap();
        let parsed: Vec<CoreDataRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), records.len());
        assert_eq!(parsed[0].entity_name, "ZNOTE");
        assert_eq!(parsed[1].entity_name, "ZREMINDER");
        assert_eq!(parsed[0].object_id, 42);
    }

    #[test]
    fn supported_strategies_returns_direct() {
        let injector = CoreDataInjector::new();
        let strategies = injector.supported_strategies();
        assert_eq!(strategies, vec![DirectInjection]);
    }
}
