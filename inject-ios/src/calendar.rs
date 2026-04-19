//! iOS Calendar injection.
//!
//! iOS persists calendar events in `Calendar.sqlitedb` under the
//! `com.apple.CalendarDatabase` container.  This injector writes JSON
//! representations of calendar events that can be replayed into an
//! extracted database or device backup.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// A single iOS calendar event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosCalendarRecord {
    /// Event title / summary.
    pub title: String,
    /// Calendar name (e.g. "Home", "Work").
    pub calendar_name: String,
    /// Event location (may be empty).
    pub location: String,
    /// Event notes / description.
    pub notes: String,
    /// Start time.
    pub start_date: DateTime<Utc>,
    /// End time.
    pub end_date: DateTime<Utc>,
    /// Whether the event is all-day.
    pub all_day: bool,
    /// Date the event was created.
    pub creation_date: DateTime<Utc>,
}

impl IosCalendarRecord {
    /// Derive a stable filename for this event.
    pub fn filename(&self) -> String {
        let safe = self.title.replace(' ', "_").replace('/', "_");
        let ts = self.start_date.format("%Y%m%dT%H%M%S");
        format!("ios_calendar_{safe}_{ts}.json")
    }
}

pub struct CalendarInjector {
    output_dir: PathBuf,
}

impl CalendarInjector {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }
}

impl Injector for CalendarInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<IosCalendarRecord> = serde_json::from_slice(artifact_bytes)?;
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

    fn sample_records() -> Vec<IosCalendarRecord> {
        let now = Utc::now();
        vec![IosCalendarRecord {
            title: "Team Standup".into(),
            calendar_name: "Work".into(),
            location: "Conference Room B".into(),
            notes: "Weekly sync".into(),
            start_date: now,
            end_date: now + chrono::Duration::hours(1),
            all_day: false,
            creation_date: now,
        }]
    }

    #[test]
    fn test_inject_and_verify_calendar() {
        let dir = TempDir::new().unwrap();
        let injector = CalendarInjector::new(dir.path().to_path_buf());
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
    fn test_rollback_calendar() {
        let dir = TempDir::new().unwrap();
        let injector = CalendarInjector::new(dir.path().to_path_buf());
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
