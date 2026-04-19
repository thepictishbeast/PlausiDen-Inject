//! Windows Recycle Bin metadata generation ($I files).

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecycleBinRecord {
    pub original_path: String,
    pub file_size: u64,
    pub deleted_at: DateTime<Utc>,
}

pub struct RecycleBinInjector {
    output_dir: PathBuf,
}
impl RecycleBinInjector {
    pub fn new(dir: PathBuf) -> Self {
        Self { output_dir: dir }
    }
}

impl Injector for RecycleBinInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<RecycleBinRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }
        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;
        let run_id = Uuid::new_v4();
        let mut ids = Vec::new();
        for (i, record) in records.iter().enumerate() {
            let path = self.output_dir.join(format!("$I{:06}.json", i));
            std::fs::write(
                &path,
                serde_json::to_vec_pretty(record).map_err(|e| InjectError::Other(e.to_string()))?,
            )
            .map_err(InjectError::Io)?;
            ids.push(path.to_string_lossy().to_string());
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
            injected_ids: ids,
        })
    }
    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        let p = result
            .injected_ids
            .iter()
            .filter(|p| std::path::Path::new(p).exists())
            .count();
        if p == result.injected_ids.len() {
            Ok(VerificationStatus::AllPresent { checked: p })
        } else {
            Ok(VerificationStatus::NonePresent {
                expected: result.injected_ids.len(),
            })
        }
    }
    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        for p in &result.injected_ids {
            let _ = std::fs::remove_file(p);
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

    #[test]
    fn test_recycle_bin_inject() {
        let dir = TempDir::new().unwrap();
        let injector = RecycleBinInjector::new(dir.path().into());
        let records = vec![RecycleBinRecord {
            original_path: "C:\\Users\\user\\Documents\\secret.docx".into(),
            file_size: 50000,
            deleted_at: Utc::now(),
        }];
        let result = injector
            .inject(
                &serde_json::to_vec(&records).unwrap(),
                &Target::Filesystem {
                    path: dir.path().into(),
                },
                InjectionStrategy::DirectInjection,
            )
            .unwrap();
        assert_eq!(result.records_injected, 1);
        assert!(dir.path().join("$I000000.json").exists());
    }
}
