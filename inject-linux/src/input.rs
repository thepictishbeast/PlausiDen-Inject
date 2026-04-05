//! Linux input event injection.

use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputRecord { pub data: serde_json::Value, pub timestamp: String }

pub struct InputInjector { output_dir: PathBuf }
impl InputInjector { pub fn new(dir: PathBuf) -> Self { Self { output_dir: dir } } }

impl Injector for InputInjector {
    fn inject(&self, artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        let records: Vec<InputRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() { return Err(InjectError::EmptyArtifact); }
        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;
        let run_id = Uuid::new_v4();
        let mut ids = Vec::new();
        for (i, r) in records.iter().enumerate() {
            let p = self.output_dir.join(format!("input_{i:06}.json"));
            std::fs::write(&p, serde_json::to_vec_pretty(r).map_err(|e| InjectError::Other(e.to_string()))?).map_err(InjectError::Io)?;
            ids.push(p.to_string_lossy().to_string());
        }
        Ok(InjectionResult { run_id, target: Target::Filesystem { path: self.output_dir.clone() }, strategy: InjectionStrategy::DirectInjection, records_injected: records.len(), backup_path: None, timestamp: Utc::now(), injected_ids: ids })
    }
    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> { let p = result.injected_ids.iter().filter(|x| std::path::Path::new(x).exists()).count(); if p == result.injected_ids.len() { Ok(VerificationStatus::AllPresent { checked: p }) } else { Ok(VerificationStatus::NonePresent { expected: result.injected_ids.len() }) } }
    fn rollback(&self, result: &InjectionResult) -> Result<()> { for p in &result.injected_ids { let _ = std::fs::remove_file(p); } Ok(()) }
    fn available_targets(&self) -> Vec<Target> { vec![Target::Filesystem { path: self.output_dir.clone() }] }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> { vec![InjectionStrategy::DirectInjection] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    #[test]
    fn test_input_inject() {
        let dir = TempDir::new().unwrap();
        let inj = InputInjector::new(dir.path().into());
        let records = vec![InputRecord { data: serde_json::json!({"key": "a"}), timestamp: Utc::now().to_rfc3339() }];
        let result = inj.inject(&serde_json::to_vec(&records).unwrap(), &Target::Filesystem { path: dir.path().into() }, InjectionStrategy::DirectInjection).unwrap();
        assert_eq!(result.records_injected, 1);
    }
}
