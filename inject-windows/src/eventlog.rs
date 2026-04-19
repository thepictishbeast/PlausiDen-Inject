//! Windows Event Log generation — EVTX-format XML entries.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogRecord {
    pub event_id: u32,
    pub level: EventLevel,
    pub source: String,
    pub channel: String,
    pub computer: String,
    pub timestamp: DateTime<Utc>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventLevel {
    Information,
    Warning,
    Error,
    Critical,
    Audit,
}

impl EventLogRecord {
    /// Render as EVTX XML format.
    pub fn to_xml(&self) -> String {
        format!(
            r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{source}"/>
    <EventID>{event_id}</EventID>
    <Level>{level}</Level>
    <TimeCreated SystemTime="{timestamp}"/>
    <Channel>{channel}</Channel>
    <Computer>{computer}</Computer>
  </System>
  <EventData><Data>{message}</Data></EventData>
</Event>"#,
            source = self.source,
            event_id = self.event_id,
            level = match self.level {
                EventLevel::Information => 4,
                EventLevel::Warning => 3,
                EventLevel::Error => 2,
                EventLevel::Critical => 1,
                EventLevel::Audit => 0,
            },
            timestamp = self.timestamp.to_rfc3339(),
            channel = self.channel,
            computer = self.computer,
            message = self.message,
        )
    }
}

pub struct EventLogInjector {
    output_dir: PathBuf,
}
impl EventLogInjector {
    pub fn new(dir: PathBuf) -> Self {
        Self { output_dir: dir }
    }
}

impl Injector for EventLogInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<EventLogRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }
        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;
        let run_id = Uuid::new_v4();
        let mut ids = Vec::new();
        for (i, record) in records.iter().enumerate() {
            let path = self.output_dir.join(format!("event_{:06}.xml", i));
            std::fs::write(&path, record.to_xml()).map_err(InjectError::Io)?;
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
    fn test_eventlog_xml_format() {
        let record = EventLogRecord {
            event_id: 4624,
            level: EventLevel::Information,
            source: "Microsoft-Windows-Security-Auditing".into(),
            channel: "Security".into(),
            computer: "WORKSTATION".into(),
            timestamp: Utc::now(),
            message: "An account was successfully logged on.".into(),
        };
        let xml = record.to_xml();
        assert!(xml.contains("EventID>4624"));
        assert!(xml.contains("Security"));
    }

    #[test]
    fn test_inject_eventlog() {
        let dir = TempDir::new().unwrap();
        let injector = EventLogInjector::new(dir.path().into());
        let records = vec![
            EventLogRecord {
                event_id: 4624,
                level: EventLevel::Information,
                source: "Security".into(),
                channel: "Security".into(),
                computer: "PC".into(),
                timestamp: Utc::now(),
                message: "Logon success".into(),
            },
            EventLogRecord {
                event_id: 7045,
                level: EventLevel::Information,
                source: "Service Control Manager".into(),
                channel: "System".into(),
                computer: "PC".into(),
                timestamp: Utc::now(),
                message: "Service installed".into(),
            },
        ];
        let result = injector
            .inject(
                &serde_json::to_vec(&records).unwrap(),
                &Target::Filesystem {
                    path: dir.path().into(),
                },
                InjectionStrategy::DirectInjection,
            )
            .unwrap();
        assert_eq!(result.records_injected, 2);
        let xml = std::fs::read_to_string(dir.path().join("event_000000.xml")).unwrap();
        assert!(xml.contains("4624"));
    }
}
