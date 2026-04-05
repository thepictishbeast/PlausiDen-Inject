//! Android MediaStore entry injection.
//!
//! The MediaStore is Android's indexed catalog of media files (photos,
//! videos, audio).  This injector writes JSON representations of
//! MediaStore rows that can be replayed into an extracted
//! `external.db` / `internal.db` or used to generate matching file
//! stubs on the filesystem.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Type of media tracked by the MediaStore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MediaType {
    Image,
    Video,
    Audio,
}

/// A single MediaStore catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaStoreRecord {
    /// Relative path on the device (e.g. `DCIM/Camera/IMG_20240101.jpg`).
    pub relative_path: String,
    /// Display name of the media file.
    pub display_name: String,
    /// MIME type (e.g. `image/jpeg`).
    pub mime_type: String,
    /// Media type category.
    pub media_type: MediaType,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Date the media was taken / recorded.
    pub date_taken: DateTime<Utc>,
    /// Date added to the MediaStore.
    pub date_added: DateTime<Utc>,
    /// Image/video width in pixels (0 for audio).
    pub width: u32,
    /// Image/video height in pixels (0 for audio).
    pub height: u32,
}

impl MediaStoreRecord {
    /// Derive a JSON filename for this record.
    pub fn filename(&self) -> String {
        let safe = self.display_name.replace(' ', "_");
        format!("mediastore_{safe}.json")
    }
}

pub struct MediaStoreInjector {
    output_dir: PathBuf,
}

impl MediaStoreInjector {
    pub fn new(output_dir: PathBuf) -> Self { Self { output_dir } }
}

impl Injector for MediaStoreInjector {
    fn inject(&self, artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        let records: Vec<MediaStoreRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() { return Err(InjectError::EmptyArtifact); }

        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::new();

        for record in &records {
            let path = self.output_dir.join(record.filename());
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

    fn sample_records() -> Vec<MediaStoreRecord> {
        vec![MediaStoreRecord {
            relative_path: "DCIM/Camera/IMG_20240101_120000.jpg".into(),
            display_name: "IMG_20240101_120000.jpg".into(),
            mime_type: "image/jpeg".into(),
            media_type: MediaType::Image,
            size_bytes: 3_500_000,
            date_taken: Utc::now(),
            date_added: Utc::now(),
            width: 4032,
            height: 3024,
        }]
    }

    #[test]
    fn test_inject_and_verify_media_store() {
        let dir = TempDir::new().unwrap();
        let injector = MediaStoreInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        assert_eq!(result.records_injected, 1);
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::AllPresent { .. }));
    }

    #[test]
    fn test_rollback_media_store() {
        let dir = TempDir::new().unwrap();
        let injector = MediaStoreInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        injector.rollback(&result).unwrap();
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::NonePresent { .. }));
    }
}
