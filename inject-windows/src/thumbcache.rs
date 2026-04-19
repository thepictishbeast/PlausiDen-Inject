//! Windows thumbnail cache metadata generation.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThumbcacheRecord {
    pub original_path: String,
    pub thumbnail_size: ThumbSize,
    pub image_hash: String,
    pub cached_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThumbSize {
    Small,
    Medium,
    Large,
    ExtraLarge,
}

pub struct ThumbcacheInjector {
    output_dir: PathBuf,
}
impl ThumbcacheInjector {
    pub fn new(dir: PathBuf) -> Self {
        Self { output_dir: dir }
    }
}

impl Injector for ThumbcacheInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<ThumbcacheRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }
        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;
        let run_id = Uuid::new_v4();
        let mut ids = Vec::new();
        for (i, record) in records.iter().enumerate() {
            let path = self.output_dir.join(format!("thumb_{:04}.json", i));
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
    fn test_thumbcache_inject() {
        let dir = TempDir::new().unwrap();
        let injector = ThumbcacheInjector::new(dir.path().into());
        let records = vec![ThumbcacheRecord {
            original_path: "C:\\Users\\user\\Pictures\\photo.jpg".into(),
            thumbnail_size: ThumbSize::Medium,
            image_hash: "abc123".into(),
            cached_at: Utc::now(),
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
    }
}
