//! iOS app sandbox file creation.
//!
//! Each iOS app has an isolated sandbox directory containing Documents,
//! Library, and tmp subdirectories.  This injector writes JSON manifests
//! describing files to be placed within a specific app's sandbox,
//! enabling downstream tooling to populate extracted backup images.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Sandbox subdirectory within an iOS app container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SandboxLocation {
    Documents,
    Library,
    LibraryCaches,
    LibraryPreferences,
    Tmp,
}

/// A file to be placed in an iOS app sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosSandboxRecord {
    /// Bundle identifier of the app (e.g. `com.example.myapp`).
    pub bundle_id: String,
    /// Which sandbox subdirectory the file belongs in.
    pub location: SandboxLocation,
    /// Filename (relative to the sandbox subdirectory).
    pub filename: String,
    /// MIME type.
    pub mime_type: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// File creation time.
    pub created: DateTime<Utc>,
    /// File modification time.
    pub modified: DateTime<Utc>,
}

impl IosSandboxRecord {
    /// Derive a JSON manifest filename.
    pub fn manifest_filename(&self) -> String {
        let safe_bundle = self.bundle_id.replace('.', "_");
        let safe_file = self.filename.replace(' ', "_").replace('/', "_");
        format!("ios_sandbox_{safe_bundle}_{safe_file}.json")
    }
}

pub struct SandboxInjector {
    output_dir: PathBuf,
}

impl SandboxInjector {
    pub fn new(output_dir: PathBuf) -> Self { Self { output_dir } }
}

impl Injector for SandboxInjector {
    fn inject(&self, artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        let records: Vec<IosSandboxRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() { return Err(InjectError::EmptyArtifact); }

        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::new();

        for record in &records {
            let path = self.output_dir.join(record.manifest_filename());
            let data = serde_json::to_vec_pretty(record).map_err(|e| InjectError::Other(e.to_string()))?;
            std::fs::write(&path, &data).map_err(InjectError::Io)?;
            injected_ids.push(path.to_string_lossy().to_string());
        }

        Ok(InjectionResult {
            run_id,
            target: Target::Filesystem { path: self.output_dir.clone() },
            strategy: InjectionStrategy::DirectInjection,
            records_injected: records.len(),
            backup_path: None,
            timestamp: Utc::now(),
            injected_ids,
        })
    }

    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        let mut present = 0;
        for path in &result.injected_ids {
            if std::path::Path::new(path).exists() { present += 1; }
        }
        if present == result.injected_ids.len() {
            Ok(VerificationStatus::AllPresent { checked: present })
        } else if present > 0 {
            Ok(VerificationStatus::PartiallyPresent { present, missing: result.injected_ids.len() - present, missing_ids: vec![] })
        } else {
            Ok(VerificationStatus::NonePresent { expected: result.injected_ids.len() })
        }
    }

    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        for path in &result.injected_ids {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        vec![Target::Filesystem { path: self.output_dir.clone() }]
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        vec![InjectionStrategy::DirectInjection]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_records() -> Vec<IosSandboxRecord> {
        vec![IosSandboxRecord {
            bundle_id: "com.example.notes".into(),
            location: SandboxLocation::Documents,
            filename: "user_data.sqlite".into(),
            mime_type: "application/x-sqlite3".into(),
            size_bytes: 48_000,
            created: Utc::now(),
            modified: Utc::now(),
        }]
    }

    #[test]
    fn test_inject_and_verify_sandbox() {
        let dir = TempDir::new().unwrap();
        let injector = SandboxInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        assert_eq!(result.records_injected, 1);
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::AllPresent { .. }));
    }

    #[test]
    fn test_rollback_sandbox() {
        let dir = TempDir::new().unwrap();
        let injector = SandboxInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        injector.rollback(&result).unwrap();
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::NonePresent { .. }));
    }
}
