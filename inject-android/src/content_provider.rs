//! Android ContentProvider-style record injection.
//!
//! ContentProviders are the standard Android IPC mechanism for structured
//! data (contacts, media, settings).  This injector writes JSON files that
//! mirror the schema of common ContentProvider URIs so that downstream
//! tooling can replay them into an Android image or emulator.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// A single ContentProvider record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentProviderRecord {
    /// Authority URI, e.g. `content://com.android.contacts/contacts`.
    pub uri: String,
    /// Display name shown in the provider listing.
    pub display_name: String,
    /// MIME type of the record.
    pub mime_type: String,
    /// Arbitrary key/value columns mirroring the provider schema.
    pub columns: std::collections::HashMap<String, String>,
    /// Timestamp the record was last modified.
    pub last_modified: DateTime<Utc>,
}

impl ContentProviderRecord {
    /// Derive a stable filename from the URI and display name.
    pub fn filename(&self) -> String {
        let authority = self.uri.replace("content://", "").replace('/', "_");
        let safe_name = self.display_name.replace(' ', "_");
        format!("{authority}_{safe_name}.json")
    }
}

pub struct ContentProviderInjector {
    output_dir: PathBuf,
}

impl ContentProviderInjector {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }
}

impl Injector for ContentProviderInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<ContentProviderRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }

        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::new();

        for record in &records {
            let path = self.output_dir.join(record.filename());
            let data =
                serde_json::to_vec_pretty(record).map_err(|e| InjectError::Other(e.to_string()))?;
            std::fs::write(&path, &data).map_err(InjectError::Io)?;
            injected_ids.push(path.to_string_lossy().to_string());
        }

        Ok(InjectionResult {
            run_id,
            target: Target::Filesystem {
                path: self.output_dir.clone(),
            },
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
            if std::path::Path::new(path).exists() {
                present += 1;
            }
        }
        if present == result.injected_ids.len() {
            Ok(VerificationStatus::AllPresent { checked: present })
        } else if present > 0 {
            Ok(VerificationStatus::PartiallyPresent {
                present,
                missing: result.injected_ids.len() - present,
                missing_ids: vec![],
            })
        } else {
            Ok(VerificationStatus::NonePresent {
                expected: result.injected_ids.len(),
            })
        }
    }

    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        for path in &result.injected_ids {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        vec![Target::Filesystem {
            path: self.output_dir.clone(),
        }]
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        vec![InjectionStrategy::DirectInjection]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_records() -> Vec<ContentProviderRecord> {
        let mut cols = std::collections::HashMap::new();
        cols.insert("phone".into(), "+1-555-0100".into());
        cols.insert("email".into(), "alice@example.com".into());
        vec![ContentProviderRecord {
            uri: "content://com.android.contacts/contacts".into(),
            display_name: "Alice Smith".into(),
            mime_type: "vnd.android.cursor.item/contact".into(),
            columns: cols,
            last_modified: Utc::now(),
        }]
    }

    #[test]
    fn test_inject_and_verify_content_provider() {
        let dir = TempDir::new().unwrap();
        let injector = ContentProviderInjector::new(dir.path().to_path_buf());
        let records = sample_records();
        let bytes = serde_json::to_vec(&records).unwrap();
        let result = injector
            .inject(
                &bytes,
                &Target::Filesystem {
                    path: dir.path().into(),
                },
                InjectionStrategy::DirectInjection,
            )
            .unwrap();
        assert_eq!(result.records_injected, 1);
        assert!(matches!(
            injector.verify(&result).unwrap(),
            VerificationStatus::AllPresent { .. }
        ));
    }

    #[test]
    fn test_rollback_content_provider() {
        let dir = TempDir::new().unwrap();
        let injector = ContentProviderInjector::new(dir.path().to_path_buf());
        let records = sample_records();
        let bytes = serde_json::to_vec(&records).unwrap();
        let result = injector
            .inject(
                &bytes,
                &Target::Filesystem {
                    path: dir.path().into(),
                },
                InjectionStrategy::DirectInjection,
            )
            .unwrap();
        injector.rollback(&result).unwrap();
        assert!(matches!(
            injector.verify(&result).unwrap(),
            VerificationStatus::NonePresent { .. }
        ));
    }
}
