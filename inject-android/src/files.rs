//! Android file creation with metadata.
//!
//! Creates files in the Android filesystem (external storage, app data
//! directories) with realistic metadata.  Files are written as JSON
//! manifests paired with content stubs so that downstream tooling can
//! place them at the correct paths on a device image.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Describes a file to be placed on an Android filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidFileRecord {
    /// Full path on the device (e.g. `/sdcard/Download/report.pdf`).
    pub device_path: String,
    /// Display filename.
    pub filename: String,
    /// MIME type.
    pub mime_type: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// File creation time.
    pub created: DateTime<Utc>,
    /// Last modification time.
    pub modified: DateTime<Utc>,
    /// Owner package (empty string for user-created files).
    pub owner_package: String,
}

impl AndroidFileRecord {
    /// Output filename for the manifest.
    pub fn manifest_filename(&self) -> String {
        let safe = self.filename.replace(' ', "_").replace('/', "_");
        format!("android_file_{safe}.json")
    }
}

pub struct AndroidFileInjector {
    output_dir: PathBuf,
}

impl AndroidFileInjector {
    pub fn new(output_dir: PathBuf) -> Self { Self { output_dir } }
}

impl Injector for AndroidFileInjector {
    fn inject(&self, artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        let records: Vec<AndroidFileRecord> = serde_json::from_slice(artifact_bytes)?;
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

    fn sample_records() -> Vec<AndroidFileRecord> {
        vec![AndroidFileRecord {
            device_path: "/sdcard/Download/meeting_notes.pdf".into(),
            filename: "meeting_notes.pdf".into(),
            mime_type: "application/pdf".into(),
            size_bytes: 125_000,
            created: Utc::now(),
            modified: Utc::now(),
            owner_package: String::new(),
        }]
    }

    #[test]
    fn test_inject_and_verify_files() {
        let dir = TempDir::new().unwrap();
        let injector = AndroidFileInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        assert_eq!(result.records_injected, 1);
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::AllPresent { .. }));
    }

    #[test]
    fn test_rollback_files() {
        let dir = TempDir::new().unwrap();
        let injector = AndroidFileInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        injector.rollback(&result).unwrap();
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::NonePresent { .. }));
    }
}
