//! Windows Prefetch file generation.
//!
//! Prefetch files (.pf) are stored in C:\Windows\Prefetch\ and record
//! which applications were run, when, and what files they accessed.
//! Forensic analysts use these to build execution timelines.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// A Windows Prefetch record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchRecord {
    pub executable_name: String,
    pub prefetch_hash: String,
    pub run_count: u32,
    pub last_run_times: Vec<DateTime<Utc>>,
    pub files_accessed: Vec<String>,
}

/// Generates Prefetch filename: EXECUTABLE-HASH.pf
impl PrefetchRecord {
    pub fn filename(&self) -> String {
        format!(
            "{}-{}.pf",
            self.executable_name.to_uppercase(),
            self.prefetch_hash
        )
    }

    /// Generate a simple hash from the executable path (simplified version of Windows hash).
    pub fn compute_hash(exe_path: &str) -> String {
        let hash = blake3::hash(exe_path.as_bytes());
        format!(
            "{:08X}",
            u32::from_le_bytes(hash.as_bytes()[..4].try_into().unwrap())
        ) // SAFETY: blake3::hash returns a 32-byte Hash; slicing [..4] and try_into::<[u8;4]> is always Ok
    }
}

pub struct PrefetchInjector {
    output_dir: PathBuf,
}

impl PrefetchInjector {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }
}

impl Injector for PrefetchInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<PrefetchRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }

        std::fs::create_dir_all(&self.output_dir).map_err(|e| InjectError::Io(e))?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::new();

        for record in &records {
            let filename = record.filename();
            let path = self.output_dir.join(&filename);
            // Write a simplified prefetch file (JSON representation)
            let data =
                serde_json::to_vec_pretty(record).map_err(|e| InjectError::Other(e.to_string()))?;
            std::fs::write(&path, &data).map_err(|e| InjectError::Io(e))?;
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

    #[test]
    fn test_prefetch_filename() {
        let record = PrefetchRecord {
            executable_name: "CHROME.EXE".into(),
            prefetch_hash: "A1B2C3D4".into(),
            run_count: 5,
            last_run_times: vec![Utc::now()],
            files_accessed: vec!["C:\\Windows\\System32\\ntdll.dll".into()],
        };
        assert_eq!(record.filename(), "CHROME.EXE-A1B2C3D4.pf");
    }

    #[test]
    fn test_inject_prefetch() {
        let dir = TempDir::new().unwrap();
        let injector = PrefetchInjector::new(dir.path().to_path_buf());
        let records = vec![PrefetchRecord {
            executable_name: "NOTEPAD.EXE".into(),
            prefetch_hash: PrefetchRecord::compute_hash("C:\\Windows\\notepad.exe"),
            run_count: 3,
            last_run_times: vec![Utc::now()],
            files_accessed: vec!["C:\\Windows\\System32\\kernel32.dll".into()],
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
        assert!(dir.path().join(records[0].filename()).exists());
    }

    #[test]
    fn test_verify_prefetch() {
        let dir = TempDir::new().unwrap();
        let injector = PrefetchInjector::new(dir.path().to_path_buf());
        let records = vec![PrefetchRecord {
            executable_name: "CMD.EXE".into(),
            prefetch_hash: "11223344".into(),
            run_count: 10,
            last_run_times: vec![Utc::now()],
            files_accessed: vec![],
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
    }

    #[test]
    fn test_rollback_prefetch() {
        let dir = TempDir::new().unwrap();
        let injector = PrefetchInjector::new(dir.path().to_path_buf());
        let records = vec![PrefetchRecord {
            executable_name: "TEST.EXE".into(),
            prefetch_hash: "AABBCCDD".into(),
            run_count: 1,
            last_run_times: vec![Utc::now()],
            files_accessed: vec![],
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
        injector.rollback(&result).unwrap();
        assert!(!dir.path().join("TEST.EXE-AABBCCDD.pf").exists());
    }
}
