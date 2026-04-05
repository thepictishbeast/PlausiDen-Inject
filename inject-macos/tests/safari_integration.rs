//! Integration tests for Safari history injection.
//!
//! Creates real SQLite databases matching Safari's History.db schema,
//! injects artifacts, then verifies the injected data is present and
//! correctly formatted.

use inject_core::{InjectionStrategy, Injector, Target};
use inject_macos::browser_safari::{
    coredata_to_unix, unix_to_coredata, SafariHistoryRecord, SafariInjector,
};
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

/// Create a Safari History.db with the real schema.
fn create_safari_history_db(dir: &std::path::Path) -> PathBuf {
    let db_path = dir.join("History.db");
    let conn = Connection::open(&db_path).unwrap();

    conn.execute_batch(
        "
        CREATE TABLE history_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL UNIQUE,
            domain_expansion TEXT,
            visit_count INTEGER NOT NULL DEFAULT 0,
            daily_visit_counts BLOB,
            title TEXT
        );

        CREATE TABLE history_visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_item INTEGER NOT NULL REFERENCES history_items(id),
            visit_time REAL NOT NULL
        );

        CREATE INDEX history_visits_item_index ON history_visits(history_item);
        ",
    )
    .unwrap();

    db_path
}

#[test]
fn test_inject_history_into_real_schema() {
    let dir = TempDir::new().unwrap();
    let db_path = create_safari_history_db(dir.path());

    let injector = SafariInjector::with_db_path(db_path.clone());

    let records = vec![
        SafariHistoryRecord {
            url: "https://www.example.com/page1".to_string(),
            title: Some("Example Page 1".to_string()),
            visit_time_unix: 1_700_000_000,
            visit_count: 1,
            domain_expansion: None, // auto-extracted
        },
        SafariHistoryRecord {
            url: "https://www.example.com/page2".to_string(),
            title: Some("Example Page 2".to_string()),
            visit_time_unix: 1_700_000_060,
            visit_count: 1,
            domain_expansion: Some("example.com".to_string()),
        },
    ];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector.inject(
        &artifact_bytes,
        &Target::SafariHistory {
            db_path: db_path.clone(),
        },
        InjectionStrategy::DirectInjection,
    );

    assert!(
        result.is_ok(),
        "injection should succeed: {:?}",
        result.err()
    );
    let result = result.unwrap();
    assert_eq!(result.records_injected, 2);

    // Verify the data is in the database.
    let conn = Connection::open(&db_path).unwrap();

    let item_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM history_items", [], |r| r.get(0))
        .unwrap();
    assert_eq!(item_count, 2, "should have 2 history items");

    let visit_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM history_visits", [], |r| r.get(0))
        .unwrap();
    assert_eq!(visit_count, 2, "should have 2 visits");

    // Verify URL and title.
    let (url, title): (String, String) = conn
        .query_row(
            "SELECT url, title FROM history_items WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(url, "https://www.example.com/page1");
    assert_eq!(title, "Example Page 1");

    // Verify domain_expansion was auto-extracted (strips www.).
    let domain: String = conn
        .query_row(
            "SELECT domain_expansion FROM history_items WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(domain, "example.com");

    // Verify visit_time is a CoreData timestamp.
    let visit_time: f64 = conn
        .query_row(
            "SELECT visit_time FROM history_visits WHERE history_item = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let recovered_unix = coredata_to_unix(visit_time);
    assert_eq!(recovered_unix, 1_700_000_000);
}

#[test]
fn test_coredata_timestamps_correct() {
    let dir = TempDir::new().unwrap();
    let db_path = create_safari_history_db(dir.path());

    let injector = SafariInjector::with_db_path(db_path.clone());

    // Use a well-known date: 2020-06-15 12:00:00 UTC = Unix 1592222400
    let unix_ts: i64 = 1_592_222_400;
    let expected_coredata = unix_to_coredata(unix_ts);

    let records = vec![SafariHistoryRecord {
        url: "https://timestamp-test.example.org".to_string(),
        title: Some("Timestamp Test".to_string()),
        visit_time_unix: unix_ts,
        visit_count: 1,
        domain_expansion: None,
    }];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    injector
        .inject(
            &artifact_bytes,
            &Target::SafariHistory {
                db_path: db_path.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();

    let conn = Connection::open(&db_path).unwrap();
    let stored_time: f64 = conn
        .query_row(
            "SELECT visit_time FROM history_visits LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();

    assert!(
        (stored_time - expected_coredata).abs() < f64::EPSILON,
        "stored CoreData timestamp {stored_time} should equal expected {expected_coredata}"
    );

    // Round-trip check.
    let roundtrip = coredata_to_unix(stored_time);
    assert_eq!(roundtrip, unix_ts, "round-trip should recover original Unix timestamp");
}

#[test]
fn test_duplicate_url_updates_visit_count() {
    let dir = TempDir::new().unwrap();
    let db_path = create_safari_history_db(dir.path());

    let injector = SafariInjector::with_db_path(db_path.clone());

    // Inject the same URL twice in a single batch.
    let records = vec![
        SafariHistoryRecord {
            url: "https://www.example.com".to_string(),
            title: Some("Example".to_string()),
            visit_time_unix: 1_700_000_000,
            visit_count: 1,
            domain_expansion: None,
        },
        SafariHistoryRecord {
            url: "https://www.example.com".to_string(),
            title: Some("Example".to_string()),
            visit_time_unix: 1_700_000_060,
            visit_count: 1,
            domain_expansion: None,
        },
    ];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    injector
        .inject(
            &artifact_bytes,
            &Target::SafariHistory {
                db_path: db_path.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();

    let conn = Connection::open(&db_path).unwrap();

    // Should have 1 history_item but 2 visits.
    let items: i64 = conn
        .query_row("SELECT COUNT(*) FROM history_items", [], |r| r.get(0))
        .unwrap();
    let visits: i64 = conn
        .query_row("SELECT COUNT(*) FROM history_visits", [], |r| r.get(0))
        .unwrap();

    assert_eq!(items, 1, "duplicate URL should not create duplicate item");
    assert_eq!(visits, 2, "each visit should be recorded");

    // visit_count should reflect both.
    let vc: i64 = conn
        .query_row(
            "SELECT visit_count FROM history_items WHERE url = ?1",
            ["https://www.example.com"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(vc >= 2, "visit_count should be at least 2, got {vc}");
}

#[test]
fn test_injection_creates_backup_and_rollback_restores() {
    let dir = TempDir::new().unwrap();
    let db_path = create_safari_history_db(dir.path());

    let injector = SafariInjector::with_db_path(db_path.clone());

    // Original state: empty.
    let conn = Connection::open(&db_path).unwrap();
    let original_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM history_items", [], |r| r.get(0))
        .unwrap();
    drop(conn);

    let records = vec![SafariHistoryRecord {
        url: "https://rollback-test.example.com".to_string(),
        title: Some("Rollback Test".to_string()),
        visit_time_unix: 1_700_000_000,
        visit_count: 1,
        domain_expansion: None,
    }];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector
        .inject(
            &artifact_bytes,
            &Target::SafariHistory {
                db_path: db_path.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();

    // Backup should exist.
    assert!(result.backup_path.is_some(), "backup should be created");
    if let Some(ref backup) = result.backup_path {
        assert!(backup.exists(), "backup file should exist at {:?}", backup);
    }

    // Verify injection happened.
    let conn = Connection::open(&db_path).unwrap();
    let injected_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM history_items", [], |r| r.get(0))
        .unwrap();
    assert_eq!(injected_count, original_count + 1);
    drop(conn);

    // Rollback.
    let rollback_result = injector.rollback(&result);
    assert!(rollback_result.is_ok(), "rollback should succeed");

    // Verify rollback restored original.
    let conn = Connection::open(&db_path).unwrap();
    let restored_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM history_items", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        restored_count, original_count,
        "rollback should restore original state"
    );
}

#[test]
fn test_verify_reports_all_present() {
    let dir = TempDir::new().unwrap();
    let db_path = create_safari_history_db(dir.path());

    let injector = SafariInjector::with_db_path(db_path.clone());

    let records = vec![
        SafariHistoryRecord {
            url: "https://verify-a.example.com".to_string(),
            title: Some("Verify A".to_string()),
            visit_time_unix: 1_700_000_000,
            visit_count: 1,
            domain_expansion: None,
        },
        SafariHistoryRecord {
            url: "https://verify-b.example.com".to_string(),
            title: Some("Verify B".to_string()),
            visit_time_unix: 1_700_000_060,
            visit_count: 1,
            domain_expansion: None,
        },
    ];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector
        .inject(
            &artifact_bytes,
            &Target::SafariHistory {
                db_path: db_path.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();

    let status = injector.verify(&result).unwrap();
    assert_eq!(
        status,
        inject_core::VerificationStatus::AllPresent { checked: 2 }
    );
}

#[test]
fn test_reject_unsupported_strategy() {
    let dir = TempDir::new().unwrap();
    let db_path = create_safari_history_db(dir.path());

    let injector = SafariInjector::with_db_path(db_path.clone());

    let records = vec![SafariHistoryRecord {
        url: "https://example.com".to_string(),
        title: None,
        visit_time_unix: 1_700_000_000,
        visit_count: 1,
        domain_expansion: None,
    }];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector.inject(
        &artifact_bytes,
        &Target::SafariHistory { db_path },
        InjectionStrategy::TranslatorInterposition,
    );

    assert!(result.is_err(), "non-DirectInjection should fail");
}

#[test]
fn test_empty_artifact_rejected() {
    let dir = TempDir::new().unwrap();
    let db_path = create_safari_history_db(dir.path());

    let injector = SafariInjector::with_db_path(db_path.clone());

    let empty: Vec<SafariHistoryRecord> = vec![];
    let artifact_bytes = serde_json::to_vec(&empty).unwrap();
    let result = injector.inject(
        &artifact_bytes,
        &Target::SafariHistory { db_path },
        InjectionStrategy::DirectInjection,
    );

    assert!(result.is_err(), "empty artifact should be rejected");
}
