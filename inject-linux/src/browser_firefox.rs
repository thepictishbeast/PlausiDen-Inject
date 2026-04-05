//! Firefox history and cookie injection on Linux.
//!
//! Firefox stores browsing history in `places.sqlite` with two principal
//! tables:
//!
//! - `moz_places` -- one row per unique URL (origin, frecency, etc.)
//! - `moz_historyvisits` -- one row per visit (timestamp, place_id, type)
//!
//! Cookies live in a separate `cookies.sqlite` with the `moz_cookies` table.
//!
//! This module writes directly into those databases using `rusqlite`.

use chrono::Utc;
use inject_core::{
    InjectionResult, InjectionStrategy, InjectionStrategy::DirectInjection, Injector,
    Target, VerificationStatus,
};
use inject_core::error::{InjectError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Artifact schemas (deserialized from engine output)
// ---------------------------------------------------------------------------

/// A single browsing-history record produced by plausiden-engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub url: String,
    pub title: Option<String>,
    /// Microseconds since the Unix epoch (Firefox convention).
    pub visit_date_us: i64,
    /// Firefox visit type (1 = TRANSITION_LINK, 2 = TRANSITION_TYPED, ...).
    #[serde(default = "default_visit_type")]
    pub visit_type: i32,
    #[serde(default)]
    pub frecency: i32,
}

fn default_visit_type() -> i32 {
    1 // TRANSITION_LINK
}

/// A single cookie record produced by plausiden-engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieRecord {
    pub name: String,
    pub value: String,
    pub host: String,
    pub path: String,
    /// Seconds since the Unix epoch.
    pub expiry: i64,
    #[serde(default)]
    pub is_secure: bool,
    #[serde(default)]
    pub is_http_only: bool,
    #[serde(default = "default_same_site")]
    pub same_site: i32,
}

fn default_same_site() -> i32 {
    0 // NONE
}

// ---------------------------------------------------------------------------
// Injector implementation
// ---------------------------------------------------------------------------

/// Firefox injector for Linux systems.
pub struct FirefoxInjector {
    /// Override profile paths for testing; if empty, auto-discover.
    profile_paths: Vec<PathBuf>,
}

impl FirefoxInjector {
    /// Create a new injector that will auto-discover Firefox profiles.
    pub fn new() -> Self {
        Self {
            profile_paths: Vec::new(),
        }
    }

    /// Create an injector targeting specific profile directories.
    pub fn with_profiles(profiles: Vec<PathBuf>) -> Self {
        Self {
            profile_paths: profiles,
        }
    }

    /// Inject history records into `places.sqlite`.
    fn inject_history(&self, records: &[HistoryRecord], profile: &Path) -> Result<InjectionResult> {
        let db_path = profile.join("places.sqlite");
        if !db_path.exists() {
            return Err(InjectError::DatabaseNotFound {
                path: db_path.clone(),
            });
        }

        // Back up before mutating.
        let backup_path = backup_database(&db_path)?;

        let conn = rusqlite::Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::with_capacity(records.len());

        let tx = conn.unchecked_transaction()?;

        for record in records {
            // Upsert into moz_places.
            tx.execute(
                "INSERT OR IGNORE INTO moz_places (url, title, rev_host, visit_count, \
                 hidden, typed, frecency, last_visit_date, guid, foreign_count, \
                 url_hash, description, preview_image_url, origin_id) \
                 VALUES (?1, ?2, ?3, 1, 0, 0, ?4, ?5, ?6, 0, \
                 hash(?1), NULL, NULL, NULL)",
                rusqlite::params![
                    record.url,
                    record.title.as_deref().unwrap_or(""),
                    reverse_host(&record.url),
                    record.frecency,
                    record.visit_date_us,
                    generate_guid(),
                ],
            )?;

            // Retrieve the place_id (may already exist).
            let place_id: i64 = tx.query_row(
                "SELECT id FROM moz_places WHERE url = ?1",
                rusqlite::params![record.url],
                |row| row.get(0),
            )?;

            // Insert visit record.
            tx.execute(
                "INSERT INTO moz_historyvisits (from_visit, place_id, visit_date, \
                 visit_type, session) \
                 VALUES (0, ?1, ?2, ?3, 0)",
                rusqlite::params![place_id, record.visit_date_us, record.visit_type],
            )?;

            // Update visit_count and last_visit_date on the place.
            tx.execute(
                "UPDATE moz_places SET visit_count = visit_count + 1, \
                 last_visit_date = MAX(COALESCE(last_visit_date, 0), ?1) \
                 WHERE id = ?2",
                rusqlite::params![record.visit_date_us, place_id],
            )?;

            injected_ids.push(place_id.to_string());
        }

        tx.commit()?;

        tracing::info!(
            profile = %profile.display(),
            records = records.len(),
            "firefox history injection complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::FirefoxHistory {
                profile_path: profile.to_path_buf(),
            },
            strategy: DirectInjection,
            records_injected: records.len(),
            backup_path: Some(backup_path),
            timestamp: Utc::now(),
            injected_ids,
        })
    }

    /// Inject cookie records into `cookies.sqlite`.
    fn inject_cookies(&self, records: &[CookieRecord], profile: &Path) -> Result<InjectionResult> {
        let db_path = profile.join("cookies.sqlite");
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

        let now_us = Utc::now().timestamp_micros();

        for record in records {
            tx.execute(
                "INSERT INTO moz_cookies (name, value, host, path, expiry, \
                 lastAccessed, creationTime, isSecure, isHttpOnly, \
                 inBrowserElement, sameSite, rawSameSite, \
                 schemeMap) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?10, 0)",
                rusqlite::params![
                    record.name,
                    record.value,
                    record.host,
                    record.path,
                    record.expiry,
                    now_us,
                    now_us,
                    record.is_secure as i32,
                    record.is_http_only as i32,
                    record.same_site,
                ],
            )?;

            let row_id = tx.last_insert_rowid();
            injected_ids.push(row_id.to_string());
        }

        tx.commit()?;

        tracing::info!(
            profile = %profile.display(),
            records = records.len(),
            "firefox cookie injection complete"
        );

        Ok(InjectionResult {
            run_id,
            target: Target::FirefoxCookies {
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

impl Default for FirefoxInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for FirefoxInjector {
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
            Target::FirefoxHistory { profile_path } => {
                let records: Vec<HistoryRecord> = serde_json::from_slice(artifact_bytes)?;
                if records.is_empty() {
                    return Err(InjectError::EmptyArtifact);
                }
                self.inject_history(&records, profile_path)
            }
            Target::FirefoxCookies { profile_path } => {
                let records: Vec<CookieRecord> = serde_json::from_slice(artifact_bytes)?;
                if records.is_empty() {
                    return Err(InjectError::EmptyArtifact);
                }
                self.inject_cookies(&records, profile_path)
            }
            other => Err(InjectError::UnsupportedTarget {
                description: format!("FirefoxInjector does not handle {other}"),
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
            inject_core::target::discover_firefox_profiles()
        } else {
            self.profile_paths.clone()
        };

        let mut targets = Vec::new();
        for p in &profiles {
            if p.join("places.sqlite").exists() {
                targets.push(Target::FirefoxHistory {
                    profile_path: p.clone(),
                });
            }
            if p.join("cookies.sqlite").exists() {
                targets.push(Target::FirefoxCookies {
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

/// Reverse a URL's host component for the `rev_host` column that Firefox
/// maintains for efficient suffix matching.
///
/// Example: `"https://example.com/page"` -> `"moc.elpmaxe."`.
fn reverse_host(url: &str) -> String {
    // Extract host from URL.
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

    let mut reversed: String = host.chars().rev().collect();
    reversed.push('.');
    reversed
}

/// Generate a 12-character Base64url GUID matching Firefox's format.
fn generate_guid() -> String {
    let id = Uuid::new_v4();
    let bytes = id.as_bytes();
    // Firefox GUIDs are 12 characters of a restricted alphabet.
    // We take the first 12 characters of a base16 representation for
    // simplicity -- Firefox accepts any unique string.
    let hex = format!("{:032x}", u128::from_be_bytes(*bytes));
    hex[..12].to_string()
}

/// Create a backup copy of a database file, returning the backup path.
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
    fn reverse_host_basic() {
        assert_eq!(reverse_host("https://example.com/page"), "moc.elpmaxe.");
    }

    #[test]
    fn reverse_host_with_port() {
        assert_eq!(reverse_host("http://localhost:8080/"), "tsohlacol.");
    }

    #[test]
    fn guid_length() {
        let guid = generate_guid();
        assert_eq!(guid.len(), 12);
    }
}
