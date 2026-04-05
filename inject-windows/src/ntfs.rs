//! NTFS metadata generation — $MFT entries, $UsnJrnl records.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// NTFS MFT (Master File Table) record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftRecord {
    pub record_number: u64,
    pub file_path: String,
    pub parent_record: u64,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
    pub mft_modified_at: DateTime<Utc>,
    pub file_size: u64,
    pub is_directory: bool,
    pub is_deleted: bool,
}

/// USN Journal change record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsnRecord {
    pub usn: u64,
    pub file_name: String,
    pub reason: UsnReason,
    pub timestamp: DateTime<Utc>,
    pub file_ref: u64,
    pub parent_ref: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UsnReason { FileCreate, FileDelete, DataOverwrite, RenameOldName, RenameNewName, Close }

pub struct NtfsInjector { output_dir: PathBuf }
impl NtfsInjector { pub fn new(dir: PathBuf) -> Self { Self { output_dir: dir } } }

impl Injector for NtfsInjector {
    fn inject(&self, artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        let records: Vec<MftRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() { return Err(InjectError::EmptyArtifact); }
        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;
        let run_id = Uuid::new_v4();
        let mut ids = Vec::new();
        for record in &records {
            let path = self.output_dir.join(format!("mft_{}.json", record.record_number));
            std::fs::write(&path, serde_json::to_vec_pretty(record).map_err(|e| InjectError::Other(e.to_string()))?).map_err(InjectError::Io)?;
            ids.push(path.to_string_lossy().to_string());
        }
        Ok(InjectionResult { run_id, target: Target::Filesystem { path: self.output_dir.clone() }, strategy: InjectionStrategy::DirectInjection, records_injected: records.len(), backup_path: None, timestamp: Utc::now(), injected_ids: ids })
    }
    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        let p = result.injected_ids.iter().filter(|p| std::path::Path::new(p).exists()).count();
        if p == result.injected_ids.len() { Ok(VerificationStatus::AllPresent { checked: p }) } else { Ok(VerificationStatus::NonePresent { expected: result.injected_ids.len() }) }
    }
    fn rollback(&self, result: &InjectionResult) -> Result<()> { for p in &result.injected_ids { let _ = std::fs::remove_file(p); } Ok(()) }
    fn available_targets(&self) -> Vec<Target> { vec![Target::Filesystem { path: self.output_dir.clone() }] }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> { vec![InjectionStrategy::DirectInjection] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_mft_inject() {
        let dir = TempDir::new().unwrap();
        let injector = NtfsInjector::new(dir.path().into());
        let records = vec![MftRecord {
            record_number: 12345, file_path: "C:\\Users\\user\\doc.txt".into(), parent_record: 100,
            created_at: Utc::now(), modified_at: Utc::now(), accessed_at: Utc::now(), mft_modified_at: Utc::now(),
            file_size: 4096, is_directory: false, is_deleted: false,
        }];
        let result = injector.inject(&serde_json::to_vec(&records).unwrap(), &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        assert_eq!(result.records_injected, 1);
    }

    #[test]
    fn test_deleted_file_record() {
        let record = MftRecord {
            record_number: 99999, file_path: "C:\\secret.txt".into(), parent_record: 5,
            created_at: Utc::now(), modified_at: Utc::now(), accessed_at: Utc::now(), mft_modified_at: Utc::now(),
            file_size: 0, is_directory: false, is_deleted: true,
        };
        assert!(record.is_deleted);
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"is_deleted\":true"));
    }
}
