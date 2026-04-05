//! System log injection — writes syslog-format entries to log files.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub timestamp: DateTime<Utc>,
    pub facility: String,
    pub severity: String,
    pub source: String,
    pub pid: u32,
    pub message: String,
}

impl LogRecord {
    /// Format as syslog line: `Apr 05 10:30:00 hostname source[pid]: message`
    pub fn to_syslog_line(&self, hostname: &str) -> String {
        let ts = self.timestamp.format("%b %d %H:%M:%S");
        format!("{ts} {hostname} {}[{}]: {}", self.source, self.pid, self.message)
    }
}

pub struct LogInjector {
    hostname: String,
    log_dir: PathBuf,
}

impl LogInjector {
    pub fn new() -> Self {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "localhost".to_string());
        Self { hostname, log_dir: PathBuf::from("/var/log") }
    }

    pub fn with_log_dir(log_dir: PathBuf) -> Self {
        Self { hostname: "testhost".to_string(), log_dir }
    }

    fn log_file_for_facility(&self, facility: &str) -> PathBuf {
        match facility {
            "auth" => self.log_dir.join("auth.log"),
            "kern" => self.log_dir.join("kern.log"),
            "daemon" => self.log_dir.join("daemon.log"),
            "cron" => self.log_dir.join("cron.log"),
            _ => self.log_dir.join("syslog"),
        }
    }
}

impl Default for LogInjector {
    fn default() -> Self { Self::new() }
}

impl Injector for LogInjector {
    fn inject(&self, artifact_bytes: &[u8], target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        let records: Vec<LogRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::new();

        for record in &records {
            let log_file = self.log_file_for_facility(&record.facility);

            // Create parent dir if needed
            if let Some(parent) = log_file.parent() {
                fs::create_dir_all(parent).map_err(|e| InjectError::Io(e))?;
            }

            // Backup before first write
            if log_file.exists() && !injected_ids.contains(&log_file.to_string_lossy().to_string()) {
                let backup = log_file.with_extension("log.bak");
                fs::copy(&log_file, &backup).map_err(|e| InjectError::Io(e))?;
            }

            // Append syslog line
            let line = record.to_syslog_line(&self.hostname);
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file)
                .map_err(|e| InjectError::Io(e))?;

            writeln!(file, "{line}").map_err(|e| InjectError::Io(e))?;
            injected_ids.push(log_file.to_string_lossy().to_string());
        }

        Ok(InjectionResult {
            run_id,
            target: target.clone(),
            strategy: InjectionStrategy::DirectInjection,
            records_injected: records.len(),
            backup_path: None,
            timestamp: Utc::now(),
            injected_ids,
        })
    }

    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        for path_str in &result.injected_ids {
            if !Path::new(path_str).exists() {
                return Ok(VerificationStatus::NonePresent { expected: result.injected_ids.len() });
            }
        }
        Ok(VerificationStatus::AllPresent { checked: result.injected_ids.len() })
    }

    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        for path_str in &result.injected_ids {
            let path = Path::new(path_str);
            let backup = path.with_extension("log.bak");
            if backup.exists() {
                fs::copy(&backup, path).map_err(|e| InjectError::Io(e))?;
                fs::remove_file(&backup).map_err(|e| InjectError::Io(e))?;
            }
        }
        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        vec![Target::Filesystem { path: self.log_dir.clone() }]
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        vec![InjectionStrategy::DirectInjection]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_records() -> Vec<LogRecord> {
        vec![
            LogRecord {
                timestamp: Utc::now(),
                facility: "auth".into(),
                severity: "Info".into(),
                source: "sshd".into(),
                pid: 1234,
                message: "Accepted publickey for user from 192.168.1.100".into(),
            },
            LogRecord {
                timestamp: Utc::now(),
                facility: "daemon".into(),
                severity: "Info".into(),
                source: "systemd".into(),
                pid: 1,
                message: "Started Network Manager".into(),
            },
        ]
    }

    #[test]
    fn test_syslog_format() {
        let record = LogRecord {
            timestamp: Utc::now(),
            facility: "auth".into(),
            severity: "Info".into(),
            source: "sshd".into(),
            pid: 850,
            message: "session opened".into(),
        };
        let line = record.to_syslog_line("myhost");
        assert!(line.contains("myhost"));
        assert!(line.contains("sshd[850]"));
        assert!(line.contains("session opened"));
    }

    #[test]
    fn test_inject_creates_log_files() {
        let dir = TempDir::new().unwrap();
        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());
        let records = make_records();
        let bytes = serde_json::to_vec(&records).unwrap();

        let result = injector.inject(
            &bytes,
            &Target::Filesystem { path: dir.path().to_path_buf() },
            InjectionStrategy::DirectInjection,
        ).unwrap();

        assert_eq!(result.records_injected, 2);
        assert!(dir.path().join("auth.log").exists());
        assert!(dir.path().join("daemon.log").exists());
    }

    #[test]
    fn test_inject_appends_content() {
        let dir = TempDir::new().unwrap();
        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());
        let records = vec![LogRecord {
            timestamp: Utc::now(), facility: "auth".into(), severity: "Info".into(),
            source: "sudo".into(), pid: 5000, message: "user ran apt update".into(),
        }];
        let bytes = serde_json::to_vec(&records).unwrap();

        injector.inject(&bytes, &Target::Filesystem { path: dir.path().to_path_buf() }, InjectionStrategy::DirectInjection).unwrap();

        let content = fs::read_to_string(dir.path().join("auth.log")).unwrap();
        assert!(content.contains("sudo[5000]"));
        assert!(content.contains("apt update"));
    }

    #[test]
    fn test_verify_confirms_files() {
        let dir = TempDir::new().unwrap();
        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&make_records()).unwrap();

        let result = injector.inject(&bytes, &Target::Filesystem { path: dir.path().to_path_buf() }, InjectionStrategy::DirectInjection).unwrap();
        let status = injector.verify(&result).unwrap();
        assert!(matches!(status, VerificationStatus::AllPresent { .. }));
    }

    #[test]
    fn test_empty_records_rejected() {
        let dir = TempDir::new().unwrap();
        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());
        let bytes = b"[]";
        let result = injector.inject(bytes, &Target::Filesystem { path: dir.path().to_path_buf() }, InjectionStrategy::DirectInjection);
        assert!(result.is_err());
    }

    #[test]
    fn test_facility_routing() {
        let dir = TempDir::new().unwrap();
        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());

        let records = vec![
            LogRecord { timestamp: Utc::now(), facility: "kern".into(), severity: "Warning".into(), source: "kernel".into(), pid: 0, message: "test kern".into() },
            LogRecord { timestamp: Utc::now(), facility: "cron".into(), severity: "Info".into(), source: "CRON".into(), pid: 999, message: "test cron".into() },
        ];
        let bytes = serde_json::to_vec(&records).unwrap();

        injector.inject(&bytes, &Target::Filesystem { path: dir.path().to_path_buf() }, InjectionStrategy::DirectInjection).unwrap();

        assert!(dir.path().join("kern.log").exists());
        assert!(dir.path().join("cron.log").exists());
    }
}
