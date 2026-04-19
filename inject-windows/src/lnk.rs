//! Windows LNK shortcut file generation.
//!
//! LNK files record recently opened files, applications, and directories.
//! Forensic analysts extract target paths, timestamps, and volume serial numbers.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LnkRecord {
    pub target_path: String,
    pub working_dir: String,
    pub description: String,
    pub icon_location: Option<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
    pub target_size: u64,
    pub show_command: ShowCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShowCommand {
    Normal,
    Minimized,
    Maximized,
}

pub struct LnkInjector {
    output_dir: PathBuf,
}

impl LnkInjector {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }
}

impl Injector for LnkInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<LnkRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }
        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;
        let run_id = Uuid::new_v4();
        let mut ids = Vec::new();
        for record in &records {
            let name = std::path::Path::new(&record.target_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("shortcut");
            let path = self.output_dir.join(format!("{name}.lnk.json"));
            let data =
                serde_json::to_vec_pretty(record).map_err(|e| InjectError::Other(e.to_string()))?;
            std::fs::write(&path, &data).map_err(InjectError::Io)?;
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
        let present = result
            .injected_ids
            .iter()
            .filter(|p| std::path::Path::new(p).exists())
            .count();
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
    fn test_inject_lnk() {
        let dir = TempDir::new().unwrap();
        let injector = LnkInjector::new(dir.path().into());
        let records = vec![LnkRecord {
            target_path: "C:\\Program Files\\app.exe".into(),
            working_dir: "C:\\Program Files".into(),
            description: "Application".into(),
            icon_location: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            accessed_at: Utc::now(),
            target_size: 1024,
            show_command: ShowCommand::Normal,
        }];
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
    }

    #[test]
    fn test_verify_and_rollback() {
        let dir = TempDir::new().unwrap();
        let injector = LnkInjector::new(dir.path().into());
        let records = vec![LnkRecord {
            target_path: "C:\\test.txt".into(),
            working_dir: "C:\\".into(),
            description: "Test".into(),
            icon_location: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
            accessed_at: Utc::now(),
            target_size: 100,
            show_command: ShowCommand::Normal,
        }];
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
        assert!(matches!(
            injector.verify(&result).unwrap(),
            VerificationStatus::AllPresent { .. }
        ));
        injector.rollback(&result).unwrap();
    }
}
