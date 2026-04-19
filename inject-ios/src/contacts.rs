//! iOS Contacts (AddressBook) injection.
//!
//! iOS stores contacts in `AddressBook.sqlitedb` under the
//! `com.apple.AddressBook` container.  This injector writes JSON
//! representations of contact records that can be replayed into an
//! extracted database or used by downstream tooling to populate a
//! device backup.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// A single iOS contact record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosContactRecord {
    /// First name.
    pub first_name: String,
    /// Last name.
    pub last_name: String,
    /// Phone numbers.
    pub phone_numbers: Vec<String>,
    /// Email addresses.
    pub emails: Vec<String>,
    /// Organization / company.
    pub organization: String,
    /// Date the contact was created.
    pub creation_date: DateTime<Utc>,
    /// Date the contact was last modified.
    pub modification_date: DateTime<Utc>,
}

impl IosContactRecord {
    /// Derive a stable filename for this contact.
    pub fn filename(&self) -> String {
        let safe = format!("{}_{}", self.first_name, self.last_name).replace(' ', "_");
        format!("ios_contact_{safe}.json")
    }
}

pub struct ContactsInjector {
    output_dir: PathBuf,
}

impl ContactsInjector {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }
}

impl Injector for ContactsInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<IosContactRecord> = serde_json::from_slice(artifact_bytes)?;
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

    fn sample_records() -> Vec<IosContactRecord> {
        vec![IosContactRecord {
            first_name: "Jane".into(),
            last_name: "Doe".into(),
            phone_numbers: vec!["+1-555-0199".into()],
            emails: vec!["jane.doe@example.com".into()],
            organization: "Example Corp".into(),
            creation_date: Utc::now(),
            modification_date: Utc::now(),
        }]
    }

    #[test]
    fn test_inject_and_verify_contacts() {
        let dir = TempDir::new().unwrap();
        let injector = ContactsInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
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
    fn test_rollback_contacts() {
        let dir = TempDir::new().unwrap();
        let injector = ContactsInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
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
