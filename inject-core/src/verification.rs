//! Post-injection verification utilities.
//!
//! After injecting records into a target database, the verification module
//! checks that each record is actually present and readable.

use crate::error::{InjectError, Result};
use crate::traits::{InjectionResult, Target, VerificationStatus};

/// Verify that all injected records exist in a SQLite database by querying
/// for each `injected_id`.
///
/// `id_column` is the column name to match against (e.g. `"id"` or
/// `"place_id"`).  `table` is the table to query.
pub fn verify_sqlite_ids(
    db_path: &std::path::Path,
    table: &str,
    id_column: &str,
    injected_ids: &[String],
) -> Result<VerificationStatus> {
    if injected_ids.is_empty() {
        return Ok(VerificationStatus::AllPresent { checked: 0 });
    }

    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    let mut present = 0usize;
    let mut missing_ids = Vec::new();

    for id in injected_ids {
        let query = format!("SELECT 1 FROM \"{table}\" WHERE \"{id_column}\" = ?1 LIMIT 1");
        let exists: bool = conn
            .query_row(&query, rusqlite::params![id], |_row| Ok(true))
            .unwrap_or(false);

        if exists {
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

/// High-level verification dispatcher that picks the right strategy based on
/// the target type recorded in the `InjectionResult`.
pub fn verify_injection(result: &InjectionResult) -> Result<VerificationStatus> {
    match &result.target {
        Target::FirefoxHistory { profile_path } => {
            let db = profile_path.join("places.sqlite");
            verify_sqlite_ids(&db, "moz_places", "id", &result.injected_ids)
        }
        Target::FirefoxCookies { profile_path } => {
            let db = profile_path.join("cookies.sqlite");
            verify_sqlite_ids(&db, "moz_cookies", "id", &result.injected_ids)
        }
        Target::ChromeHistory { profile_path } => {
            let db = profile_path.join("History");
            verify_sqlite_ids(&db, "urls", "id", &result.injected_ids)
        }
        Target::ChromeCookies { profile_path } => {
            let db = profile_path.join("Cookies");
            verify_sqlite_ids(&db, "cookies", "creation_utc", &result.injected_ids)
        }
        Target::SafariHistory { db_path } => {
            verify_sqlite_ids(db_path, "history_items", "id", &result.injected_ids)
        }
        other => Err(InjectError::UnsupportedTarget {
            description: format!("verification not implemented for {other}"),
        }),
    }
}
