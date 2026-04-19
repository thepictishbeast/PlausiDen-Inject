//! Safari history injection on macOS.
//!
//! Safari stores browsing history in `History.db` (SQLite) with two principal
//! tables:
//!
//! - `history_items` -- one row per unique URL (domain_expansion, visit_count,
//!   daily_visit_counts, title)
//! - `history_visits` -- one row per visit (history_item FK, visit_time as
//!   CoreData timestamp)
//!
//! CoreData timestamps are seconds since the **CoreData reference date**:
//! 2001-01-01 00:00:00 UTC.  The offset from the Unix epoch is exactly
//! 978_307_200 seconds.
//!
//! This module writes directly into `History.db` using `rusqlite`.

use chrono::Utc;
use inject_core::error::{InjectError, Result};
use inject_core::{
    InjectionResult, InjectionStrategy, InjectionStrategy::DirectInjection, Injector, Target,
    VerificationStatus,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Seconds between the Unix epoch (1970-01-01) and the CoreData reference
/// date (2001-01-01 00:00:00 UTC).
const COREDATA_EPOCH_OFFSET: i64 = 978_307_200;

// ---------------------------------------------------------------------------
// Artifact schemas (deserialized from engine output)
// ---------------------------------------------------------------------------

/// A single Safari browsing-history record produced by plausiden-engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafariHistoryRecord {
    pub url: String,
    pub title: Option<String>,
    /// Unix timestamp in seconds.
    pub visit_time_unix: i64,
    /// Number of visits to attribute to this URL entry.
    #[serde(default = "default_visit_count")]
    pub visit_count: i32,
    /// Safari expands the top-level domain for display (e.g. "example.com").
    /// If omitted, extracted automatically from the URL.
    pub domain_expansion: Option<String>,
}

fn default_visit_count() -> i32 {
    1
}

// ---------------------------------------------------------------------------
// Timestamp conversion
// ---------------------------------------------------------------------------

/// Convert a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) to a
/// CoreData timestamp (seconds since 2001-01-01 00:00:00 UTC).
pub fn unix_to_coredata(unix_secs: i64) -> f64 {
    (unix_secs - COREDATA_EPOCH_OFFSET) as f64
}

/// Convert a CoreData timestamp back to a Unix timestamp.
pub fn coredata_to_unix(coredata_secs: f64) -> i64 {
    coredata_secs as i64 + COREDATA_EPOCH_OFFSET
}

// ---------------------------------------------------------------------------
// Injector implementation
// ---------------------------------------------------------------------------

/// Safari injector for macOS systems.
pub struct SafariInjector {
    /// Override database path for testing; if `None`, auto-discover.
    db_path_override: Option<PathBuf>,
}

impl SafariInjector {
    /// Create a new injector that will auto-discover the Safari History.db.
    pub fn new() -> Self {
        Self {
            db_path_override: None,
        }
    }

    /// Create an injector targeting a specific History.db path.
    pub fn with_db_path(db_path: PathBuf) -> Self {
        Self {
            db_path_override: Some(db_path),
        }
    }

    /// Resolve the target database path from the `Target` variant or
    /// the configured override.
    fn resolve_db_path(&self, target: &Target) -> Result<PathBuf> {
        match target {
            Target::SafariHistory { db_path } => Ok(db_path.clone()),
            other => Err(InjectError::UnsupportedTarget {
                description: format!("SafariInjector does not handle {other}"),
            }),
        }
    }

    /// Inject history records into Safari's `History.db`.
    fn inject_history(
        &self,
        records: &[SafariHistoryRecord],
        db_path: &Path,
    ) -> Result<InjectionResult> {
        if !db_path.exists() {
            return Err(InjectError::DatabaseNotFound {
                path: db_path.to_path_buf(),
            });
        }

        // Back up before mutating.
        let backup_path = backup_database(db_path)?;

        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::with_capacity(records.len());

        let tx = conn.unchecked_transaction()?;

        for record in records {
            let domain = record
                .domain_expansion
                .clone()
                .unwrap_or_else(|| extract_domain(&record.url));

            // Upsert into history_items.
            tx.execute(
                "INSERT OR IGNORE INTO history_items \
                 (url, domain_expansion, visit_count, daily_visit_counts, title) \
                 VALUES (?1, ?2, 0, NULL, ?3)",
                rusqlite::params![record.url, domain, record.title.as_deref().unwrap_or(""),],
            )?;

            // Retrieve the item id (may already exist).
            let item_id: i64 = tx.query_row(
                "SELECT id FROM history_items WHERE url = ?1",
                rusqlite::params![record.url],
                |row| row.get(0),
            )?;

            // Insert visit record with CoreData timestamp.
            let coredata_ts = unix_to_coredata(record.visit_time_unix);
            tx.execute(
                "INSERT INTO history_visits (history_item, visit_time) \
                 VALUES (?1, ?2)",
                rusqlite::params![item_id, coredata_ts],
            )?;

            // Update visit_count on the history_item.
            tx.execute(
                "UPDATE history_items SET visit_count = visit_count + ?1 \
                 WHERE id = ?2",
                rusqlite::params![record.visit_count, item_id],
            )?;

            injected_ids.push(item_id.to_string());
        }

        tx.commit()?;

        tracing::info!(
            db = %db_path.display(),
            records = records.len(),
            "safari history injection complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::SafariHistory {
                db_path: db_path.to_path_buf(),
            },
            strategy: DirectInjection,
            records_injected: records.len(),
            backup_path: Some(backup_path),
            timestamp: Utc::now(),
            injected_ids,
        })
    }
}

impl Default for SafariInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for SafariInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        target: &Target,
        strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        if strategy != DirectInjection {
            return Err(InjectError::UnsupportedStrategy {
                strategy: strategy.to_string(),
                target: target.to_string(),
            });
        }

        let db_path = self.resolve_db_path(target)?;
        let records: Vec<SafariHistoryRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }
        self.inject_history(&records, &db_path)
    }

    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        inject_core::verification::verify_injection(result)
    }

    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        inject_core::rollback::rollback_injection(result)
    }

    fn available_targets(&self) -> Vec<Target> {
        let mut targets = Vec::new();

        let candidate = self
            .db_path_override
            .clone()
            .or_else(inject_core::target::safari_history_db);

        if let Some(path) = candidate {
            if path.exists() {
                targets.push(Target::SafariHistory { db_path: path });
            }
        }

        targets
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        vec![DirectInjection]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the domain from a URL for the `domain_expansion` column.
///
/// Example: `"https://www.example.com/page"` -> `"example.com"`.
fn extract_domain(url: &str) -> String {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    // Strip leading "www." to match Safari's behaviour.
    let domain = host.strip_prefix("www.").unwrap_or(host);
    domain.to_string()
}

/// Create a backup copy of a database file, returning the backup path.
fn backup_database(db_path: &Path) -> Result<PathBuf> {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let file_name = db_path.file_name().and_then(|n| n.to_str()).unwrap_or("db");
    let backup_name = format!("{file_name}.plausiden-backup.{timestamp}");
    let backup_path = db_path.with_file_name(backup_name);

    std::fs::copy(db_path, &backup_path).map_err(|e| InjectError::BackupFailed {
        path: db_path.to_path_buf(),
        reason: e.to_string(),
    })?;

    tracing::debug!(
        src = %db_path.display(),
        dst = %backup_path.display(),
        "database backed up"
    );

    Ok(backup_path)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_to_coredata_known_value() {
        // 2001-01-01 00:00:00 UTC in Unix time is 978307200.
        // That should map to CoreData 0.0.
        assert!((unix_to_coredata(978_307_200) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn coredata_to_unix_roundtrip() {
        let unix_ts: i64 = 1_700_000_000;
        let cd = unix_to_coredata(unix_ts);
        let back = coredata_to_unix(cd);
        assert_eq!(back, unix_ts);
    }

    #[test]
    fn extract_domain_strips_www() {
        assert_eq!(
            extract_domain("https://www.example.com/page"),
            "example.com"
        );
    }

    #[test]
    fn extract_domain_no_www() {
        assert_eq!(extract_domain("https://example.org/path"), "example.org");
    }

    #[test]
    fn extract_domain_with_port() {
        assert_eq!(extract_domain("http://localhost:8080/"), "localhost");
    }

    #[test]
    fn coredata_epoch_offset_correct() {
        // 2001-01-01 00:00:00 UTC via chrono
        use chrono::TimeZone;
        let epoch_2001 = chrono::Utc.with_ymd_and_hms(2001, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(epoch_2001.timestamp(), COREDATA_EPOCH_OFFSET);
    }
}
