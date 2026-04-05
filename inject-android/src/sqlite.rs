//! Generic Android SQLite database injection.
//!
//! Android apps store private data in SQLite databases under
//! `/data/data/<package>/databases/`.  This injector writes JSON
//! representations of database rows so that downstream tooling can
//! replay them into extracted database files.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// A generic Android SQLite row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidSqliteRecord {
    /// Package name owning the database (e.g. `com.whatsapp`).
    pub package_name: String,
    /// Database filename (e.g. `msgstore.db`).
    pub database_name: String,
    /// Table within the database.
    pub table_name: String,
    /// Column name/value pairs for the row.
    pub row_data: std::collections::HashMap<String, String>,
    /// When this row was created.
    pub created_at: DateTime<Utc>,
}

impl AndroidSqliteRecord {
    /// Derive a stable filename for this record.
    pub fn filename(&self, index: usize) -> String {
        format!("{}_{}_{}_{index}.json", self.package_name, self.database_name, self.table_name)
    }
}

pub struct AndroidSqliteInjector {
    output_dir: PathBuf,
}

impl AndroidSqliteInjector {
    pub fn new(output_dir: PathBuf) -> Self { Self { output_dir } }
}

impl Injector for AndroidSqliteInjector {
    fn inject(&self, artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        let records: Vec<AndroidSqliteRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() { return Err(InjectError::EmptyArtifact); }

        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::new();

        for (i, record) in records.iter().enumerate() {
            let path = self.output_dir.join(record.filename(i));
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

    fn sample_records() -> Vec<AndroidSqliteRecord> {
        let mut row = std::collections::HashMap::new();
        row.insert("_id".into(), "1".into());
        row.insert("body".into(), "Hello from PlausiDen".into());
        row.insert("address".into(), "+15550100".into());
        vec![AndroidSqliteRecord {
            package_name: "com.android.providers.telephony".into(),
            database_name: "mmssms.db".into(),
            table_name: "sms".into(),
            row_data: row,
            created_at: Utc::now(),
        }]
    }

    #[test]
    fn test_inject_and_verify_sqlite() {
        let dir = TempDir::new().unwrap();
        let injector = AndroidSqliteInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        assert_eq!(result.records_injected, 1);
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::AllPresent { .. }));
    }

    #[test]
    fn test_rollback_sqlite() {
        let dir = TempDir::new().unwrap();
        let injector = AndroidSqliteInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        injector.rollback(&result).unwrap();
        assert!(matches!(injector.verify(&result).unwrap(), VerificationStatus::NonePresent { .. }));
    }
}
