//! Integration tests for Firefox history and cookie injection.
//!
//! Creates real SQLite databases matching Firefox's schema, injects
//! artifacts, then verifies the injected data is present and correctly
//! formatted — indistinguishable from real Firefox entries.

use inject_core::{InjectionStrategy, Injector, Target};
use inject_linux::browser_firefox::{CookieRecord, FirefoxInjector, HistoryRecord};
use rusqlite::Connection;
use std::path::PathBuf;
use tempfile::TempDir;

/// Create a Firefox places.sqlite with the real schema.
fn create_firefox_places_db(dir: &std::path::Path) -> PathBuf {
    let db_path = dir.join("places.sqlite");
    let conn = Connection::open(&db_path).unwrap();

    conn.execute_batch(
        "
        CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY,
            url TEXT,
            title TEXT,
            rev_host TEXT,
            visit_count INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0 NOT NULL,
            typed INTEGER DEFAULT 0 NOT NULL,
            frecency INTEGER DEFAULT -1 NOT NULL,
            last_visit_date INTEGER,
            guid TEXT,
            foreign_count INTEGER DEFAULT 0 NOT NULL,
            url_hash INTEGER DEFAULT 0 NOT NULL,
            description TEXT,
            preview_image_url TEXT,
            origin_id INTEGER
        );

        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY,
            from_visit INTEGER,
            place_id INTEGER,
            visit_date INTEGER,
            visit_type INTEGER,
            session INTEGER
        );

        CREATE INDEX moz_places_url_hashindex ON moz_places(url_hash);
        CREATE UNIQUE INDEX moz_places_url_uniqueindex ON moz_places(url);
        CREATE UNIQUE INDEX moz_places_guid_uniqueindex ON moz_places(guid);
        ",
    )
    .unwrap();

    db_path
}

/// Create a Firefox cookies.sqlite with the real schema.
fn create_firefox_cookies_db(dir: &std::path::Path) -> PathBuf {
    let db_path = dir.join("cookies.sqlite");
    let conn = Connection::open(&db_path).unwrap();

    conn.execute_batch(
        "
        CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY,
            originAttributes TEXT NOT NULL DEFAULT '',
            name TEXT,
            value TEXT,
            host TEXT,
            path TEXT,
            expiry INTEGER,
            lastAccessed INTEGER,
            creationTime INTEGER,
            isSecure INTEGER,
            isHttpOnly INTEGER,
            inBrowserElement INTEGER DEFAULT 0,
            sameSite INTEGER DEFAULT 0,
            rawSameSite INTEGER DEFAULT 0,
            schemeMap INTEGER DEFAULT 0
        );
        ",
    )
    .unwrap();

    db_path
}

#[test]
fn test_inject_history_into_real_schema() {
    let dir = TempDir::new().unwrap();
    create_firefox_places_db(dir.path());

    let injector = FirefoxInjector::with_profiles(vec![dir.path().to_path_buf()]);

    let records = vec![
        HistoryRecord {
            url: "https://www.example.com/page1".to_string(),
            title: Some("Example Page 1".to_string()),
            visit_date_us: 1700000000_000000, // microseconds
            visit_type: 1,                    // TRANSITION_LINK
            frecency: 100,
        },
        HistoryRecord {
            url: "https://www.example.com/page2".to_string(),
            title: Some("Example Page 2".to_string()),
            visit_date_us: 1700000060_000000,
            visit_type: 2, // TRANSITION_TYPED
            frecency: 200,
        },
    ];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector.inject(
        &artifact_bytes,
        &Target::FirefoxHistory {
            profile_path: dir.path().to_path_buf(),
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

    // Verify the data is in the database
    let conn = Connection::open(dir.path().join("places.sqlite")).unwrap();

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM moz_places", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2, "should have 2 places");

    let visit_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM moz_historyvisits", [], |r| r.get(0))
        .unwrap();
    assert_eq!(visit_count, 2, "should have 2 visits");

    // Verify the URLs are correct
    let url: String = conn
        .query_row("SELECT url FROM moz_places WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(url, "https://www.example.com/page1");

    // Verify visit_count was updated
    let vc: i64 = conn
        .query_row(
            "SELECT visit_count FROM moz_places WHERE url = ?1",
            ["https://www.example.com/page1"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(vc >= 1, "visit_count should be at least 1");
}

#[test]
fn test_inject_cookies_into_real_schema() {
    let dir = TempDir::new().unwrap();
    create_firefox_cookies_db(dir.path());

    let injector = FirefoxInjector::with_profiles(vec![dir.path().to_path_buf()]);

    let records = vec![
        CookieRecord {
            name: "_ga".to_string(),
            value: "GA1.2.1234567890.1700000000".to_string(),
            host: ".example.com".to_string(),
            path: "/".to_string(),
            expiry: 1800000000,
            is_secure: true,
            is_http_only: false,
            same_site: 0,
        },
        CookieRecord {
            name: "session_id".to_string(),
            value: "abc123def456".to_string(),
            host: ".example.com".to_string(),
            path: "/".to_string(),
            expiry: 1700003600,
            is_secure: true,
            is_http_only: true,
            same_site: 1,
        },
    ];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector.inject(
        &artifact_bytes,
        &Target::FirefoxCookies {
            profile_path: dir.path().to_path_buf(),
        },
        InjectionStrategy::DirectInjection,
    );

    assert!(
        result.is_ok(),
        "cookie injection should succeed: {:?}",
        result.err()
    );

    // Verify cookies are in the database
    let conn = Connection::open(dir.path().join("cookies.sqlite")).unwrap();

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM moz_cookies", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 2, "should have 2 cookies");

    // Verify cookie values
    let cookie_name: String = conn
        .query_row(
            "SELECT name FROM moz_cookies WHERE host = '.example.com' ORDER BY id LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(cookie_name, "_ga");
}

#[test]
fn test_inject_duplicate_url_updates_visit_count() {
    let dir = TempDir::new().unwrap();
    create_firefox_places_db(dir.path());

    let injector = FirefoxInjector::with_profiles(vec![dir.path().to_path_buf()]);

    // Inject the same URL twice
    let records = vec![
        HistoryRecord {
            url: "https://www.example.com".to_string(),
            title: Some("Example".to_string()),
            visit_date_us: 1700000000_000000,
            visit_type: 1,
            frecency: 100,
        },
        HistoryRecord {
            url: "https://www.example.com".to_string(),
            title: Some("Example".to_string()),
            visit_date_us: 1700000060_000000,
            visit_type: 1,
            frecency: 100,
        },
    ];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let _ = injector.inject(
        &artifact_bytes,
        &Target::FirefoxHistory {
            profile_path: dir.path().to_path_buf(),
        },
        InjectionStrategy::DirectInjection,
    );

    let conn = Connection::open(dir.path().join("places.sqlite")).unwrap();

    // Should have 1 place but 2 visits
    let places: i64 = conn
        .query_row("SELECT COUNT(*) FROM moz_places", [], |r| r.get(0))
        .unwrap();
    let visits: i64 = conn
        .query_row("SELECT COUNT(*) FROM moz_historyvisits", [], |r| r.get(0))
        .unwrap();

    assert_eq!(places, 1, "duplicate URL should not create duplicate place");
    assert_eq!(visits, 2, "each visit should be recorded");

    // Visit count should reflect both visits
    let vc: i64 = conn
        .query_row(
            "SELECT visit_count FROM moz_places WHERE url = ?1",
            ["https://www.example.com"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(vc >= 2, "visit_count should be at least 2, got {vc}");
}

#[test]
fn test_injection_creates_backup() {
    let dir = TempDir::new().unwrap();
    create_firefox_places_db(dir.path());

    let injector = FirefoxInjector::with_profiles(vec![dir.path().to_path_buf()]);

    let records = vec![HistoryRecord {
        url: "https://backup-test.com".to_string(),
        title: Some("Backup Test".to_string()),
        visit_date_us: 1700000000_000000,
        visit_type: 1,
        frecency: 50,
    }];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector
        .inject(
            &artifact_bytes,
            &Target::FirefoxHistory {
                profile_path: dir.path().to_path_buf(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();

    // A backup should have been created
    assert!(result.backup_path.is_some(), "backup should be created");
    if let Some(backup) = &result.backup_path {
        assert!(backup.exists(), "backup file should exist at {:?}", backup);
    }
}

#[test]
fn test_rollback_restores_original() {
    let dir = TempDir::new().unwrap();
    create_firefox_places_db(dir.path());

    let injector = FirefoxInjector::with_profiles(vec![dir.path().to_path_buf()]);

    // Get original state
    let conn = Connection::open(dir.path().join("places.sqlite")).unwrap();
    let original_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM moz_places", [], |r| r.get(0))
        .unwrap();
    drop(conn);

    // Inject
    let records = vec![HistoryRecord {
        url: "https://rollback-test.com".to_string(),
        title: Some("Rollback Test".to_string()),
        visit_date_us: 1700000000_000000,
        visit_type: 1,
        frecency: 50,
    }];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector
        .inject(
            &artifact_bytes,
            &Target::FirefoxHistory {
                profile_path: dir.path().to_path_buf(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();

    // Verify injection happened
    let conn = Connection::open(dir.path().join("places.sqlite")).unwrap();
    let injected_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM moz_places", [], |r| r.get(0))
        .unwrap();
    assert_eq!(injected_count, original_count + 1);
    drop(conn);

    // Rollback
    let rollback = injector.rollback(&result);
    assert!(rollback.is_ok(), "rollback should succeed");

    // Verify rollback restored original
    let conn = Connection::open(dir.path().join("places.sqlite")).unwrap();
    let restored_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM moz_places", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        restored_count, original_count,
        "rollback should restore original state"
    );
}
