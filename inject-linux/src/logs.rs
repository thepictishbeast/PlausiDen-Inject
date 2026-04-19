//! System and application log injection on Linux.
//!
//! Injects synthetic log entries into system log files with correct syslog
//! formatting and timestamps.  Two injection methods are supported:
//!
//! 1. **Direct file append** (`DirectInjection`): opens the target log file
//!    and appends formatted syslog lines.  Requires write permission on the
//!    log file.  Gives precise timestamp control and creates a backup for
//!    rollback.
//!
//! 2. **Logger command** (`Hybrid`): shells out to the `logger(1)` utility,
//!    which speaks the syslog protocol.  Safest approach -- works without
//!    root on systems running rsyslog / syslog-ng, but timestamps are
//!    determined by the syslog daemon and no backup is created.
//!
//! The artifact JSON consumed by this module is produced by
//! `engine-system::logs::LogGenerator`.

use chrono::{DateTime, Utc};
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Artifact schema
// ---------------------------------------------------------------------------

/// A single log record deserialized from engine output.
///
/// The engine's `LogEntry` includes a `meta` field from `ArtifactMetadata`
/// which is silently ignored here (serde default: skip unknown fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    /// Timestamp for the log line.
    pub timestamp: DateTime<Utc>,
    /// Syslog facility (e.g. `"auth"`, `"kern"`, `"daemon"`, `"cron"`).
    pub facility: String,
    /// Severity level.
    pub severity: LogSeverity,
    /// Process or service name that produced the log.
    pub source: String,
    /// PID of the originating process.
    pub pid: u32,
    /// Human-readable log message.
    pub message: String,
}

/// Syslog severity levels (RFC 5424 subset used by the engine).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogSeverity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
}

impl LogSeverity {
    /// Map to the numeric syslog severity code (RFC 5424 Section 6.2.1).
    fn code(&self) -> u8 {
        match self {
            Self::Debug => 7,
            Self::Info => 6,
            Self::Notice => 5,
            Self::Warning => 4,
            Self::Error => 3,
            Self::Critical => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// Syslog facility codes
// ---------------------------------------------------------------------------

/// Map a facility name to its numeric code (RFC 5424 Section 6.2.1).
fn facility_code(facility: &str) -> u8 {
    match facility {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => 1, // default to "user"
    }
}

/// Compute the syslog priority value: `facility * 8 + severity`.
fn syslog_priority(facility: &str, severity: &LogSeverity) -> u16 {
    (facility_code(facility) as u16) * 8 + (severity.code() as u16)
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Format a log record as a BSD-style syslog line (RFC 3164) with the
/// priority prefix.
///
/// Format: `<priority>Mon DD HH:MM:SS hostname source[pid]: message`
pub fn format_syslog_line(record: &LogRecord, hostname: &str) -> String {
    let pri = syslog_priority(&record.facility, &record.severity);
    let ts = record.timestamp.format("%b %e %H:%M:%S");
    format!(
        "<{pri}>{ts} {hostname} {source}[{pid}]: {msg}",
        source = record.source,
        pid = record.pid,
        msg = record.message,
    )
}

/// Format without the `<priority>` prefix -- the form that appears in log
/// files after rsyslog processes the message.
fn format_file_line(record: &LogRecord, hostname: &str) -> String {
    let ts = record.timestamp.format("%b %e %H:%M:%S");
    format!(
        "{ts} {hostname} {source}[{pid}]: {msg}",
        source = record.source,
        pid = record.pid,
        msg = record.message,
    )
}

// ---------------------------------------------------------------------------
// LogInjector
// ---------------------------------------------------------------------------

/// Linux log-file injector.
///
/// Supports two injection strategies:
/// - `DirectInjection` -- direct file append (backup + precise timestamps)
/// - `Hybrid` -- use the `logger(1)` command (syslog protocol, no backup)
pub struct LogInjector {
    /// Hostname to embed in log lines.
    hostname: String,
    /// Base directory for log files.  Defaults to `/var/log`.
    log_dir: PathBuf,
}

impl LogInjector {
    /// Create a new injector that uses the system hostname and `/var/log`.
    pub fn new() -> Self {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "localhost".to_string());
        Self {
            hostname,
            log_dir: PathBuf::from("/var/log"),
        }
    }

    /// Create an injector targeting a custom log directory (useful for
    /// testing without writing to system paths).
    pub fn with_log_dir(log_dir: PathBuf) -> Self {
        Self {
            hostname: "testhost".to_string(),
            log_dir,
        }
    }

    /// Create an injector with explicit hostname and log directory.
    pub fn with_hostname_and_dir(hostname: impl Into<String>, log_dir: PathBuf) -> Self {
        Self {
            hostname: hostname.into(),
            log_dir,
        }
    }

    /// Determine which log file a facility maps to.
    fn log_file_for_facility(&self, facility: &str) -> PathBuf {
        match facility {
            "auth" | "authpriv" => self.log_dir.join("auth.log"),
            _ => self.log_dir.join("syslog"),
        }
    }

    // -- Direct file append ------------------------------------------------

    /// Inject records by appending formatted lines directly to log files.
    /// Groups records by facility so each target file gets a single backup.
    fn inject_direct(&self, records: &[LogRecord], target: &Target) -> Result<InjectionResult> {
        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::with_capacity(records.len());
        let mut first_backup: Option<PathBuf> = None;
        let mut backed_up_files = std::collections::HashSet::new();

        // If the caller gave us a LogFile target, use that single file
        // for all records; otherwise route by facility.
        let explicit_path = match target {
            Target::LogFile { path } => Some(path.clone()),
            _ => None,
        };

        for record in records {
            let log_path = explicit_path
                .clone()
                .unwrap_or_else(|| self.log_file_for_facility(&record.facility));

            // Ensure parent directory exists.
            if let Some(parent) = log_path.parent() {
                fs::create_dir_all(parent).map_err(InjectError::Io)?;
            }

            // Backup each unique log file once before first write.
            if !backed_up_files.contains(&log_path) {
                let backup = backup_log_file(&log_path)?;
                if first_backup.is_none() {
                    first_backup = Some(backup);
                }
                backed_up_files.insert(log_path.clone());
            }

            // Append the formatted line.
            let line = format_file_line(record, &self.hostname);
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .map_err(InjectError::Io)?;
            writeln!(file, "{line}").map_err(InjectError::Io)?;

            injected_ids.push(make_record_id(record));
        }

        // Determine the canonical target path for the result.
        let result_path = explicit_path.unwrap_or_else(|| {
            records
                .first()
                .map(|r| self.log_file_for_facility(&r.facility))
                .unwrap_or_else(|| self.log_dir.join("syslog"))
        });

        tracing::info!(
            path = %result_path.display(),
            records = records.len(),
            "log injection (direct append) complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::LogFile { path: result_path },
            strategy: InjectionStrategy::DirectInjection,
            records_injected: records.len(),
            backup_path: first_backup,
            timestamp: Utc::now(),
            injected_ids,
        })
    }

    // -- Logger command ----------------------------------------------------

    /// Inject records via the `logger(1)` command.
    fn inject_via_logger(&self, records: &[LogRecord]) -> Result<InjectionResult> {
        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::with_capacity(records.len());

        for record in records {
            let pri = syslog_priority(&record.facility, &record.severity);
            let tag = format!("{}[{}]", record.source, record.pid);

            let status = std::process::Command::new("logger")
                .arg("--priority")
                .arg(pri.to_string())
                .arg("--tag")
                .arg(&tag)
                .arg("--")
                .arg(&record.message)
                .status()
                .map_err(|e| InjectError::Other(format!("failed to run logger: {e}")))?;

            if !status.success() {
                return Err(InjectError::Other(format!(
                    "logger exited with status {status}"
                )));
            }

            injected_ids.push(make_record_id(record));
        }

        let target_path = records
            .first()
            .map(|r| self.log_file_for_facility(&r.facility))
            .unwrap_or_else(|| self.log_dir.join("syslog"));

        tracing::info!(
            records = records.len(),
            "log injection (logger command) complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::LogFile { path: target_path },
            strategy: InjectionStrategy::Hybrid,
            records_injected: records.len(),
            backup_path: None,
            timestamp: Utc::now(),
            injected_ids,
        })
    }

    // -- Verification ------------------------------------------------------

    /// Check that injected log entries appear in the target file by
    /// searching for each record's signature string.
    fn verify_log_file(
        &self,
        log_path: &Path,
        injected_ids: &[String],
    ) -> Result<VerificationStatus> {
        if injected_ids.is_empty() {
            return Ok(VerificationStatus::AllPresent { checked: 0 });
        }

        let contents = fs::read_to_string(log_path).map_err(InjectError::Io)?;

        let mut present = 0usize;
        let mut missing_ids = Vec::new();

        for id in injected_ids {
            if contents.contains(id.as_str()) {
                present += 1;
            } else {
                missing_ids.push(id.clone());
            }
        }

        let total = injected_ids.len();
        if present == total {
            Ok(VerificationStatus::AllPresent { checked: total })
        } else if present == 0 {
            Ok(VerificationStatus::NonePresent { expected: total })
        } else {
            Ok(VerificationStatus::PartiallyPresent {
                present,
                missing: total - present,
                missing_ids,
            })
        }
    }
}

impl Default for LogInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for LogInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        target: &Target,
        strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<LogRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }

        match strategy {
            InjectionStrategy::DirectInjection => self.inject_direct(&records, target),
            InjectionStrategy::Hybrid => self.inject_via_logger(&records),
            InjectionStrategy::TranslatorInterposition => Err(InjectError::UnsupportedStrategy {
                strategy: strategy.to_string(),
                target: target.to_string(),
            }),
        }
    }

    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        match &result.target {
            Target::LogFile { path } => self.verify_log_file(path, &result.injected_ids),
            other => Err(InjectError::UnsupportedTarget {
                description: format!("LogInjector cannot verify {other}"),
            }),
        }
    }

    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        if let Some(backup) = &result.backup_path {
            let dest = match &result.target {
                Target::LogFile { path } => path,
                other => {
                    return Err(InjectError::UnsupportedTarget {
                        description: format!("LogInjector cannot roll back {other}"),
                    });
                }
            };

            fs::copy(backup, dest).map_err(|e| InjectError::RollbackFailed {
                reason: format!(
                    "failed to restore backup {} -> {}: {e}",
                    backup.display(),
                    dest.display()
                ),
            })?;

            tracing::info!(
                backup = %backup.display(),
                dest = %dest.display(),
                "log file restored from backup"
            );

            return Ok(());
        }

        Err(InjectError::RollbackFailed {
            reason: "no backup available; cannot undo logger-based injection".into(),
        })
    }

    fn available_targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();
        for name in ["syslog", "auth.log"] {
            let p = self.log_dir.join(name);
            if p.exists() {
                targets.push(Target::LogFile { path: p });
            }
        }
        targets
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        vec![
            InjectionStrategy::DirectInjection,
            InjectionStrategy::Hybrid,
        ]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a deterministic ID string from a log record.  Used for
/// verification -- we search the log file for this exact substring.
fn make_record_id(record: &LogRecord) -> String {
    format!(
        "{source}[{pid}]: {msg}",
        source = record.source,
        pid = record.pid,
        msg = record.message,
    )
}

/// Create a timestamped backup of a log file before injection.
fn backup_log_file(path: &Path) -> Result<PathBuf> {
    let backup_path = backup_path_for(path);

    if !path.exists() {
        // Nothing to back up -- create an empty placeholder so rollback
        // can restore the "no file" state.
        fs::write(&backup_path, b"").map_err(|e| InjectError::BackupFailed {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        return Ok(backup_path);
    }

    fs::copy(path, &backup_path).map_err(|e| InjectError::BackupFailed {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })?;

    tracing::debug!(
        src = %path.display(),
        dst = %backup_path.display(),
        "log file backed up"
    );

    Ok(backup_path)
}

/// Compute a backup path: `<original>.plausiden-backup.<timestamp>`.
fn backup_path_for(path: &Path) -> PathBuf {
    let ts = Utc::now().format("%Y%m%d%H%M%S");
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("logfile");
    let backup_name = format!("{name}.plausiden-backup.{ts}");
    path.with_file_name(backup_name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: build a `LogRecord` for testing.
    fn sample_record(facility: &str, source: &str, message: &str) -> LogRecord {
        LogRecord {
            timestamp: "2026-04-05T10:30:00Z".parse().unwrap(),
            facility: facility.to_string(),
            severity: LogSeverity::Info,
            source: source.to_string(),
            pid: 850,
            message: message.to_string(),
        }
    }

    /// Serialize records to JSON bytes (simulating engine output).
    fn to_artifact(records: &[LogRecord]) -> Vec<u8> {
        serde_json::to_vec(records).unwrap()
    }

    // -- Formatting -------------------------------------------------------

    #[test]
    fn test_syslog_priority_calculation() {
        // auth(4) * 8 + info(6) = 38
        assert_eq!(syslog_priority("auth", &LogSeverity::Info), 38);
        // kern(0) * 8 + critical(2) = 2
        assert_eq!(syslog_priority("kern", &LogSeverity::Critical), 2);
        // daemon(3) * 8 + warning(4) = 28
        assert_eq!(syslog_priority("daemon", &LogSeverity::Warning), 28);
    }

    #[test]
    fn test_format_syslog_line_contains_priority() {
        let rec = sample_record(
            "auth",
            "sshd",
            "Accepted publickey for user from 192.168.1.100 port 52431 ssh2",
        );
        let line = format_syslog_line(&rec, "testhost");
        assert!(line.starts_with("<38>"));
        assert!(line.contains("testhost"));
        assert!(line.contains("sshd[850]:"));
        assert!(line.contains("Accepted publickey"));
    }

    #[test]
    fn test_format_file_line_no_priority() {
        let rec = sample_record("daemon", "systemd", "Started Network Manager.");
        let line = format_file_line(&rec, "mybox");
        assert!(!line.contains('<'));
        assert!(line.contains("mybox"));
        assert!(line.contains("systemd[850]: Started Network Manager."));
    }

    #[test]
    fn test_facility_to_log_path() {
        let inj = LogInjector::with_log_dir(PathBuf::from("/var/log"));
        assert_eq!(
            inj.log_file_for_facility("auth"),
            PathBuf::from("/var/log/auth.log")
        );
        assert_eq!(
            inj.log_file_for_facility("authpriv"),
            PathBuf::from("/var/log/auth.log")
        );
        assert_eq!(
            inj.log_file_for_facility("daemon"),
            PathBuf::from("/var/log/syslog")
        );
        assert_eq!(
            inj.log_file_for_facility("kern"),
            PathBuf::from("/var/log/syslog")
        );
        assert_eq!(
            inj.log_file_for_facility("cron"),
            PathBuf::from("/var/log/syslog")
        );
    }

    #[test]
    fn test_severity_codes() {
        assert_eq!(LogSeverity::Debug.code(), 7);
        assert_eq!(LogSeverity::Info.code(), 6);
        assert_eq!(LogSeverity::Notice.code(), 5);
        assert_eq!(LogSeverity::Warning.code(), 4);
        assert_eq!(LogSeverity::Error.code(), 3);
        assert_eq!(LogSeverity::Critical.code(), 2);
    }

    #[test]
    fn test_make_record_id_deterministic() {
        let rec = sample_record("auth", "sshd", "test message");
        let id1 = make_record_id(&rec);
        let id2 = make_record_id(&rec);
        assert_eq!(id1, id2);
        assert_eq!(id1, "sshd[850]: test message");
    }

    // -- Inject + Verify + Rollback ---------------------------------------

    #[test]
    fn test_inject_direct_appends_to_file() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");
        fs::write(&log_path, "existing line\n").unwrap();

        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());
        let records = vec![
            sample_record("auth", "sshd", "Accepted publickey for testuser"),
            sample_record("daemon", "systemd", "Started Network Manager."),
        ];
        let artifact = to_artifact(&records);

        let target = Target::LogFile {
            path: log_path.clone(),
        };
        let result = injector
            .inject(&artifact, &target, InjectionStrategy::DirectInjection)
            .unwrap();

        assert_eq!(result.records_injected, 2);
        assert!(result.backup_path.is_some());
        assert_eq!(result.injected_ids.len(), 2);

        let contents = fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains("existing line"));
        assert!(contents.contains("sshd[850]: Accepted publickey for testuser"));
        assert!(contents.contains("systemd[850]: Started Network Manager."));
    }

    #[test]
    fn test_inject_creates_facility_routed_files() {
        let dir = TempDir::new().unwrap();
        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());

        let records = vec![
            sample_record("auth", "sshd", "auth facility message"),
            sample_record("daemon", "systemd", "daemon facility message"),
        ];
        let artifact = to_artifact(&records);

        // Use a Filesystem target so facility routing kicks in.
        let target = Target::Filesystem {
            path: dir.path().to_path_buf(),
        };
        let result = injector
            .inject(&artifact, &target, InjectionStrategy::DirectInjection)
            .unwrap();

        assert_eq!(result.records_injected, 2);

        let auth_content = fs::read_to_string(dir.path().join("auth.log")).unwrap();
        assert!(auth_content.contains("sshd[850]: auth facility message"));

        let syslog_content = fs::read_to_string(dir.path().join("syslog")).unwrap();
        assert!(syslog_content.contains("systemd[850]: daemon facility message"));
    }

    #[test]
    fn test_verify_after_injection() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("syslog");
        fs::write(&log_path, "").unwrap();

        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());
        let records = vec![sample_record(
            "daemon",
            "dockerd",
            "Container started: abc123",
        )];
        let artifact = to_artifact(&records);

        let target = Target::LogFile {
            path: log_path.clone(),
        };
        let result = injector
            .inject(&artifact, &target, InjectionStrategy::DirectInjection)
            .unwrap();

        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::AllPresent { checked: 1 });
    }

    #[test]
    fn test_verify_missing_entries() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("syslog");
        fs::write(&log_path, "nothing relevant here\n").unwrap();

        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());

        let result = InjectionResult {
            run_id: Uuid::new_v4(),
            target: Target::LogFile { path: log_path },
            strategy: InjectionStrategy::DirectInjection,
            records_injected: 1,
            backup_path: None,
            timestamp: Utc::now(),
            injected_ids: vec!["sshd[999]: nonexistent message".to_string()],
        };

        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::NonePresent { expected: 1 });
    }

    #[test]
    fn test_rollback_restores_backup() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("auth.log");
        let original = "original log line\n";
        fs::write(&log_path, original).unwrap();

        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());
        let records = vec![
            sample_record("auth", "sshd", "injected entry one"),
            sample_record("auth", "sudo", "injected entry two"),
        ];
        let artifact = to_artifact(&records);

        let target = Target::LogFile {
            path: log_path.clone(),
        };
        let result = injector
            .inject(&artifact, &target, InjectionStrategy::DirectInjection)
            .unwrap();

        // Confirm injection happened.
        let after_inject = fs::read_to_string(&log_path).unwrap();
        assert!(after_inject.contains("injected entry one"));

        // Rollback.
        injector.rollback(&result).unwrap();

        let after_rollback = fs::read_to_string(&log_path).unwrap();
        assert_eq!(after_rollback, original);
        assert!(!after_rollback.contains("injected entry"));
    }

    #[test]
    fn test_empty_artifact_rejected() {
        let dir = TempDir::new().unwrap();
        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());
        let empty: Vec<LogRecord> = vec![];
        let artifact = to_artifact(&empty);
        let target = Target::LogFile {
            path: dir.path().join("fake.log"),
        };

        let err = injector
            .inject(&artifact, &target, InjectionStrategy::DirectInjection)
            .unwrap_err();
        assert!(matches!(err, InjectError::EmptyArtifact));
    }

    #[test]
    fn test_unsupported_strategy_rejected() {
        let dir = TempDir::new().unwrap();
        let injector = LogInjector::with_log_dir(dir.path().to_path_buf());
        let records = vec![sample_record("auth", "sshd", "test")];
        let artifact = to_artifact(&records);
        let target = Target::LogFile {
            path: dir.path().join("fake.log"),
        };

        let err = injector
            .inject(
                &artifact,
                &target,
                InjectionStrategy::TranslatorInterposition,
            )
            .unwrap_err();
        assert!(matches!(err, InjectError::UnsupportedStrategy { .. }));
    }

    #[test]
    fn test_supported_strategies() {
        let injector = LogInjector::with_log_dir(PathBuf::from("/tmp"));
        let strategies = injector.supported_strategies();
        assert!(strategies.contains(&InjectionStrategy::DirectInjection));
        assert!(strategies.contains(&InjectionStrategy::Hybrid));
        assert!(!strategies.contains(&InjectionStrategy::TranslatorInterposition));
    }

    #[test]
    fn test_backup_created_for_existing_file() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("syslog");
        fs::write(&log_path, "pre-existing content\n").unwrap();

        let backup = backup_log_file(&log_path).unwrap();
        assert!(backup.exists());
        assert_eq!(
            fs::read_to_string(&backup).unwrap(),
            "pre-existing content\n"
        );
    }

    #[test]
    fn test_backup_created_for_nonexistent_file() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("does-not-exist.log");

        let backup = backup_log_file(&log_path).unwrap();
        assert!(backup.exists());
        assert!(fs::read_to_string(&backup).unwrap().is_empty());
    }

    #[test]
    fn test_deserialize_engine_artifact_with_meta() {
        // The engine emits a `meta` field; make sure we tolerate it.
        let json = r#"[{
            "meta": {"category": "System", "created": "2026-04-05T10:30:00Z",
                     "modified": "2026-04-05T10:30:00Z", "size_bytes": 200},
            "timestamp": "2026-04-05T10:30:00Z",
            "facility": "auth",
            "severity": "Info",
            "source": "sshd",
            "pid": 850,
            "message": "Accepted publickey for user from 192.168.1.100 port 52431 ssh2"
        }]"#;

        let records: Vec<LogRecord> = serde_json::from_str(json).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].facility, "auth");
        assert_eq!(records[0].source, "sshd");
        assert_eq!(records[0].pid, 850);
    }

    #[test]
    fn test_full_inject_verify_rollback_cycle() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("full-cycle.log");
        fs::write(&log_path, "baseline\n").unwrap();

        let injector = LogInjector::with_hostname_and_dir("cyclehost", dir.path().to_path_buf());
        let records = vec![
            sample_record("auth", "sshd", "session opened for testuser"),
            sample_record("cron", "CRON", "(root) CMD (/usr/bin/apt update)"),
            sample_record("daemon", "systemd", "Started Daily Cleanup."),
        ];
        let artifact = to_artifact(&records);

        let target = Target::LogFile {
            path: log_path.clone(),
        };

        // Inject.
        let result = injector
            .inject(&artifact, &target, InjectionStrategy::DirectInjection)
            .unwrap();
        assert_eq!(result.records_injected, 3);

        // Verify.
        let status = injector.verify(&result).unwrap();
        assert_eq!(status, VerificationStatus::AllPresent { checked: 3 });

        // Rollback.
        injector.rollback(&result).unwrap();
        let restored = fs::read_to_string(&log_path).unwrap();
        assert_eq!(restored, "baseline\n");
    }

    #[test]
    fn test_rollback_without_backup_fails() {
        let injector = LogInjector::with_log_dir(PathBuf::from("/tmp"));
        let result = InjectionResult {
            run_id: Uuid::new_v4(),
            target: Target::LogFile {
                path: PathBuf::from("/tmp/nope.log"),
            },
            strategy: InjectionStrategy::Hybrid,
            records_injected: 1,
            backup_path: None,
            timestamp: Utc::now(),
            injected_ids: vec!["sshd[1]: msg".to_string()],
        };

        let err = injector.rollback(&result).unwrap_err();
        assert!(matches!(err, InjectError::RollbackFailed { .. }));
    }
}
