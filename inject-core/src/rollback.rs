//! Rollback (undo) support for injection operations.
//!
//! Two strategies are supported:
//!
//! 1. **Backup restore** -- if a backup was created before injection, copy it
//!    back over the target database.
//! 2. **Surgical delete** -- delete only the rows that were injected, using
//!    the `injected_ids` recorded in the `InjectionResult`.
//!
//! Backup restore is always preferred when a backup exists because it
//! guarantees perfect rollback regardless of any schema triggers or
//! cascading side-effects.

use crate::error::{InjectError, Result};
use crate::traits::{InjectionResult, Target};

/// Perform a rollback for the given injection result.
///
/// If a backup path is present, the backup is restored.  Otherwise we fall
/// back to surgical deletion.
pub fn rollback_injection(result: &InjectionResult) -> Result<()> {
    if let Some(backup) = &result.backup_path {
        return restore_backup(backup, &result.target);
    }
    surgical_rollback(result)
}

/// Copy the backup file back to the target database path.
fn restore_backup(backup: &std::path::Path, target: &Target) -> Result<()> {
    let dest = target_db_path(target)?;
    std::fs::copy(backup, &dest).map_err(|e| InjectError::RollbackFailed {
        reason: format!("failed to restore backup {} -> {}: {e}", backup.display(), dest.display()),
    })?;
    tracing::info!(
        backup = %backup.display(),
        dest = %dest.display(),
        "backup restored successfully"
    );
    Ok(())
}

/// Delete only the rows that were injected.
fn surgical_rollback(result: &InjectionResult) -> Result<()> {
    let (db_path, table, id_col) = rollback_params(&result.target)?;

    let conn = rusqlite::Connection::open(&db_path)?;

    let tx = conn.unchecked_transaction()?;
    for id in &result.injected_ids {
        let sql = format!("DELETE FROM \"{table}\" WHERE \"{id_col}\" = ?1");
        tx.execute(&sql, rusqlite::params![id])?;
    }
    tx.commit()?;

    tracing::info!(
        target = %result.target,
        deleted = result.injected_ids.len(),
        "surgical rollback complete"
    );
    Ok(())
}

/// Map a `Target` variant to (db_path, table_name, id_column).
fn rollback_params(target: &Target) -> Result<(std::path::PathBuf, &'static str, &'static str)> {
    match target {
        Target::FirefoxHistory { profile_path } => {
            Ok((profile_path.join("places.sqlite"), "moz_places", "id"))
        }
        Target::FirefoxCookies { profile_path } => {
            Ok((profile_path.join("cookies.sqlite"), "moz_cookies", "id"))
        }
        Target::ChromeHistory { profile_path } => {
            Ok((profile_path.join("History"), "urls", "id"))
        }
        Target::ChromeCookies { profile_path } => {
            Ok((profile_path.join("Cookies"), "cookies", "creation_utc"))
        }
        Target::SafariHistory { db_path } => {
            Ok((db_path.clone(), "history_items", "id"))
        }
        other => Err(InjectError::UnsupportedTarget {
            description: format!("rollback not implemented for {other}"),
        }),
    }
}

/// Resolve the database file path for a given target.
fn target_db_path(target: &Target) -> Result<std::path::PathBuf> {
    let (path, _, _) = rollback_params(target)?;
    Ok(path)
}
