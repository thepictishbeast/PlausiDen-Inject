//! Chrome / Chromium history and cookie injection on Linux.
//!
//! Chrome stores browsing history in a SQLite database called `History` with
//! two principal tables:
//!
//! - `urls` -- one row per unique URL (title, visit_count, typed_count, etc.)
//! - `visits` -- one row per visit (url id, visit_time, transition, etc.)
//!
//! Chrome timestamps are microseconds since 1601-01-01 00:00:00 UTC (the
//! Windows FILETIME epoch).  This module handles conversion from Unix
//! timestamps.
//!
//! Cookies live in a separate `Cookies` database with the `cookies` table.

use chrono::Utc;
use inject_core::{
    InjectionResult, InjectionStrategy, InjectionStrategy::DirectInjection, Injector,
    Target, VerificationStatus,
};
use inject_core::error::{InjectError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

mod chrome_crypto;
use chrome_crypto::encrypt_cookie_value;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Microseconds between the Windows FILETIME epoch (1601-01-01) and the
/// Unix epoch (1970-01-01).
const CHROME_EPOCH_OFFSET_US: i64 = 11_644_473_600_000_000;

// ---------------------------------------------------------------------------
// Artifact schemas
// ---------------------------------------------------------------------------

/// A browsing-history record produced by plausiden-engine (Chrome target).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub url: String,
    pub title: Option<String>,
    /// Microseconds since the Unix epoch.
    pub visit_time_us: i64,
    /// Chrome transition type (core mask). 0 = LINK, 1 = TYPED, ...
    #[serde(default)]
    pub transition: i64,
}

/// A cookie record produced by plausiden-engine (Chrome target).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieRecord {
    pub host_key: String,
    pub name: String,
    pub value: String,
    pub path: String,
    /// Seconds since the Unix epoch.
    pub expires_utc: i64,
    #[serde(default)]
    pub is_secure: bool,
    #[serde(default)]
    pub is_httponly: bool,
    #[serde(default = "default_same_site")]
    pub samesite: i32,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_source_scheme")]
    pub source_scheme: i32,
}

fn default_same_site() -> i32 {
    -1 // unspecified
}

fn default_priority() -> i32 {
    1 // MEDIUM
}

fn default_source_scheme() -> i32 {
    2 // HTTPS
}

// ---------------------------------------------------------------------------
// Injector
// ---------------------------------------------------------------------------

/// Chrome / Chromium injector for Linux.
pub struct ChromeInjector {
    /// Override profile paths for testing.
    profile_paths: Vec<PathBuf>,
}

impl ChromeInjector {
    pub fn new() -> Self {
        Self {
            profile_paths: Vec::new(),
        }
    }

    pub fn with_profiles(profiles: Vec<PathBuf>) -> Self {
        Self {
            profile_paths: profiles,
        }
    }

    /// Inject history records into the `History` database.
    fn inject_history(&self, records: &[HistoryRecord], profile: &Path) -> Result<InjectionResult> {
        let db_path = profile.join("History");
        if !db_path.exists() {
            return Err(InjectError::DatabaseNotFound {
                path: db_path.clone(),
            });
        }

        let backup_path = backup_database(&db_path)?;

        let conn = rusqlite::Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::with_capacity(records.len());

        let tx = conn.unchecked_transaction()?;

        for record in records {
            let chrome_time = unix_us_to_chrome(record.visit_time_us);

            // Upsert into `urls`.
            tx.execute(
                "INSERT OR IGNORE INTO urls (url, title, visit_count, typed_count, \
                 last_visit_time, hidden) \
                 VALUES (?1, ?2, 0, 0, ?3, 0)",
                rusqlite::params![
                    record.url,
                    record.title.as_deref().unwrap_or(""),
                    chrome_time,
                ],
            )?;

            let url_id: i64 = tx.query_row(
                "SELECT id FROM urls WHERE url = ?1",
                rusqlite::params![record.url],
                |row| row.get(0),
            )?;

            // Insert into `visits`.
            //
            // Chrome's `transition` column packs the core type in the low
            // bits and qualifier flags in the high bits.  We use the value
            // supplied by the engine (defaulting to 0 = LINK).
            tx.execute(
                "INSERT INTO visits (url, visit_time, from_visit, transition, \
                 segment_id, visit_duration, incremented_omnibox_typed_score, \
                 publicly_routable, originator_cache_guid, \
                 originator_visit_id, originator_from_visit, \
                 originator_opener_visit, is_known_to_sync, \
                 consider_for_ntp_most_visited, \
                 originator_referring_visit) \
                 VALUES (?1, ?2, 0, ?3, 0, 0, 0, 0, '', 0, 0, 0, 0, 0, 0)",
                rusqlite::params![url_id, chrome_time, record.transition],
            )?;

            // Bump the visit count and last_visit_time.
            tx.execute(
                "UPDATE urls SET visit_count = visit_count + 1, \
                 last_visit_time = MAX(COALESCE(last_visit_time, 0), ?1) \
                 WHERE id = ?2",
                rusqlite::params![chrome_time, url_id],
            )?;

            injected_ids.push(url_id.to_string());
        }

        tx.commit()?;

        tracing::info!(
            profile = %profile.display(),
            records = records.len(),
            "chrome history injection complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::ChromeHistory {
                profile_path: profile.to_path_buf(),
            },
            strategy: DirectInjection,
            records_injected: records.len(),
            backup_path: Some(backup_path),
            timestamp: Utc::now(),
            injected_ids,
        })
    }

    /// Inject cookie records into the `Cookies` database.
    fn inject_cookies(&self, records: &[CookieRecord], profile: &Path) -> Result<InjectionResult> {
        let db_path = profile.join("Cookies");
        if !db_path.exists() {
            return Err(InjectError::DatabaseNotFound {
                path: db_path.clone(),
            });
        }

        let backup_path = backup_database(&db_path)?;

        let conn = rusqlite::Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::with_capacity(records.len());

        let tx = conn.unchecked_transaction()?;

        let now_chrome = unix_us_to_chrome(Utc::now().timestamp_micros());

        for record in records {
            let expires_chrome = unix_us_to_chrome(record.expires_utc * 1_000_000);

            // Chrome stores cookies with an empty `value` column and the
            // AES-128-CBC encrypted value in `encrypted_value`.  This makes
            // injected cookies indistinguishable from real ones.
            let encrypted_value = encrypt_cookie_value(&record.value)?;

            tx.execute(
                "INSERT INTO cookies (creation_utc, host_key, name, value, \
                 encrypted_value, path, \
                 expires_utc, is_secure, is_httponly, last_access_utc, \
                 has_expires, is_persistent, priority, samesite, \
                 source_scheme, source_port, last_update_utc) \
                 VALUES (?1, ?2, ?3, '', ?4, ?5, ?6, ?7, ?8, ?9, 1, 1, ?10, ?11, ?12, -1, ?13)",
                rusqlite::params![
                    now_chrome,
                    record.host_key,
                    record.name,
                    encrypted_value,
                    record.path,
                    expires_chrome,
                    record.is_secure as i32,
                    record.is_httponly as i32,
                    now_chrome,
                    record.priority,
                    record.samesite,
                    record.source_scheme,
                    now_chrome,
                ],
            )?;

            injected_ids.push(now_chrome.to_string());
        }

        tx.commit()?;

        tracing::info!(
            profile = %profile.display(),
            records = records.len(),
            "chrome cookie injection complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::ChromeCookies {
                profile_path: profile.to_path_buf(),
            },
            strategy: DirectInjection,
            records_injected: records.len(),
            backup_path: Some(backup_path),
            timestamp: Utc::now(),
            injected_ids,
        })
    }
}

impl Default for ChromeInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for ChromeInjector {
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

        match target {
            Target::ChromeHistory { profile_path } => {
                let records: Vec<HistoryRecord> = serde_json::from_slice(artifact_bytes)?;
                if records.is_empty() {
                    return Err(InjectError::EmptyArtifact);
                }
                self.inject_history(&records, profile_path)
            }
            Target::ChromeCookies { profile_path } => {
                let records: Vec<CookieRecord> = serde_json::from_slice(artifact_bytes)?;
                if records.is_empty() {
                    return Err(InjectError::EmptyArtifact);
                }
                self.inject_cookies(&records, profile_path)
            }
            other => Err(InjectError::UnsupportedTarget {
                description: format!("ChromeInjector does not handle {other}"),
            }),
        }
    }

    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        inject_core::verification::verify_injection(result)
    }

    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        inject_core::rollback::rollback_injection(result)
    }

    fn available_targets(&self) -> Vec<Target> {
        let profiles = if self.profile_paths.is_empty() {
            inject_core::target::discover_chrome_profiles()
        } else {
            self.profile_paths.clone()
        };

        let mut targets = Vec::new();
        for p in &profiles {
            if p.join("History").exists() {
                targets.push(Target::ChromeHistory {
                    profile_path: p.clone(),
                });
            }
            if p.join("Cookies").exists() {
                targets.push(Target::ChromeCookies {
                    profile_path: p.clone(),
                });
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

/// Convert Unix microseconds to Chrome's FILETIME-based microseconds.
fn unix_us_to_chrome(unix_us: i64) -> i64 {
    unix_us + CHROME_EPOCH_OFFSET_US
}

/// Create a timestamped backup of a database file.
fn backup_database(db_path: &Path) -> Result<PathBuf> {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S");
    let file_name = db_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("db");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_epoch_conversion() {
        // 2024-01-01 00:00:00 UTC in Unix microseconds
        let unix_us: i64 = 1_704_067_200_000_000;
        let chrome_us = unix_us_to_chrome(unix_us);
        // Should be positive and larger than the offset.
        assert!(chrome_us > CHROME_EPOCH_OFFSET_US);
        assert_eq!(chrome_us, unix_us + CHROME_EPOCH_OFFSET_US);
    }
}
