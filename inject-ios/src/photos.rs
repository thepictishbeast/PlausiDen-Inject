//! iOS Photos library injection.
//!
//! iOS stores photo metadata in `Photos.sqlite` under the
//! `com.apple.Photos` container (Camera Roll, albums, moments).
//! This injector writes JSON representations of Photos.sqlite rows
//! that can be replayed into an extracted database.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// A single iOS Photos library asset record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosPhotoRecord {
    /// Asset filename (e.g. `IMG_0001.HEIC`).
    pub filename: String,
    /// Directory within the photo library (e.g. `DCIM/100APPLE`).
    pub directory: String,
    /// Uniform type identifier (e.g. `public.heic`).
    pub uniform_type_id: String,
    /// Image width in pixels.
    pub pixel_width: u32,
    /// Image height in pixels.
    pub pixel_height: u32,
    /// File size in bytes.
    pub file_size: u64,
    /// Date the photo was taken (from EXIF or file creation).
    pub date_created: DateTime<Utc>,
    /// Date the asset was added to the library.
    pub date_added: DateTime<Utc>,
    /// Whether the asset is marked as favorite.
    pub favorite: bool,
    /// Whether the asset is hidden.
    pub hidden: bool,
}

impl IosPhotoRecord {
    /// Derive a JSON filename for this record.
    pub fn manifest_filename(&self) -> String {
        let stem = self.filename.rsplit('.').last().unwrap_or(&self.filename);
        format!("ios_photo_{stem}.json")
    }
}

pub struct PhotosInjector {
    output_dir: PathBuf,
}

impl PhotosInjector {
    pub fn new(output_dir: PathBuf) -> Self { Self { output_dir } }
}

impl Injector for PhotosInjector {
    fn inject(&self, artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        let records: Vec<IosPhotoRecord> = serde_json::from_slice(artifact_bytes)?;
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

    fn sample_records() -> Vec<IosPhotoRecord> {
        vec![IosPhotoRecord {
            filename: "IMG_0042.HEIC".into(),
            directory: "DCIM/100APPLE".into(),
            uniform_type_id: "public.heic".into(),
            pixel_width: 4032,
            pixel_height: 3024,
            file_size: 2_800_000,
            date_created: Utc::now(),
            date_added: Utc::now(),
            favorite: false,
            hidden: false,
        }]
    }

    #[test]
    fn test_inject_and_verify_photos() {
        let dir = TempDir::new().unwrap();
        let injector = PhotosInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        assert_eq!(result.records_injected, 1);
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::AllPresent { .. }));
    }

    #[test]
    fn test_rollback_photos() {
        let dir = TempDir::new().unwrap();
        let injector = PhotosInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        injector.rollback(&result).unwrap();
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::NonePresent { .. }));
    }
}
