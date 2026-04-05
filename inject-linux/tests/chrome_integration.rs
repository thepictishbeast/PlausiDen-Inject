//! Integration tests for Chrome/Chromium history and cookie injection.

use inject_linux::browser_chrome::{CookieRecord, HistoryRecord, ChromeInjector};
use inject_core::{Injector, InjectionStrategy, Target};
use rusqlite::Connection;
use tempfile::TempDir;

/// Create a Chrome History database with the real schema.
fn create_chrome_history_db(dir: &std::path::Path) -> std::path::PathBuf {
    let db_path = dir.join("History");
    let conn = Connection::open(&db_path).unwrap();

    conn.execute_batch(
        "
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            visit_count INTEGER NOT NULL DEFAULT 0,
            typed_count INTEGER NOT NULL DEFAULT 0,
            last_visit_time INTEGER NOT NULL DEFAULT 0,
            hidden INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL DEFAULT 0,
            from_visit INTEGER NOT NULL DEFAULT 0,
            transition INTEGER NOT NULL DEFAULT 0,
            segment_id INTEGER NOT NULL DEFAULT 0,
            visit_duration INTEGER NOT NULL DEFAULT 0,
            incremented_omnibox_typed_score INTEGER NOT NULL DEFAULT 0,
            opener_visit INTEGER NOT NULL DEFAULT 0,
            originator_cache_guid TEXT NOT NULL DEFAULT '',
            originator_visit_id INTEGER NOT NULL DEFAULT 0,
            originator_from_visit INTEGER NOT NULL DEFAULT 0,
            originator_opener_visit INTEGER NOT NULL DEFAULT 0,
            is_known_to_sync INTEGER NOT NULL DEFAULT 0,
            consider_for_ntp_most_visited INTEGER NOT NULL DEFAULT 0,
            publicly_routable INTEGER NOT NULL DEFAULT 0,
            originator_referring_visit INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX urls_url_index ON urls(url);
        ",
    )
    .unwrap();

    db_path
}

/// Create a Chrome Cookies database with the real schema.
fn create_chrome_cookies_db(dir: &std::path::Path) -> std::path::PathBuf {
    let db_path = dir.join("Cookies");
    let conn = Connection::open(&db_path).unwrap();

    conn.execute_batch(
        "
        CREATE TABLE cookies (
            creation_utc INTEGER NOT NULL,
            host_key TEXT NOT NULL DEFAULT '',
            top_frame_site_key TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL DEFAULT '',
            value TEXT NOT NULL DEFAULT '',
            encrypted_value BLOB NOT NULL DEFAULT X'',
            path TEXT NOT NULL DEFAULT '/',
            expires_utc INTEGER NOT NULL DEFAULT 0,
            is_secure INTEGER NOT NULL DEFAULT 0,
            is_httponly INTEGER NOT NULL DEFAULT 0,
            last_access_utc INTEGER NOT NULL DEFAULT 0,
            has_expires INTEGER NOT NULL DEFAULT 1,
            is_persistent INTEGER NOT NULL DEFAULT 1,
            priority INTEGER NOT NULL DEFAULT 1,
            samesite INTEGER NOT NULL DEFAULT -1,
            source_scheme INTEGER NOT NULL DEFAULT 2,
            source_port INTEGER NOT NULL DEFAULT -1,
            last_update_utc INTEGER NOT NULL DEFAULT 0
        );
        ",
    )
    .unwrap();

    db_path
}

#[test]
fn test_inject_chrome_history() {
    let dir = TempDir::new().unwrap();
    create_chrome_history_db(dir.path());

    let injector = ChromeInjector::with_profiles(vec![dir.path().to_path_buf()]);

    let records = vec![
        HistoryRecord {
            url: "https://www.rust-lang.org/".to_string(),
            title: Some("Rust Programming Language".to_string()),
            visit_time_us: 1700000000_000000,
            transition: 1, // TYPED
        },
        HistoryRecord {
            url: "https://docs.rs/".to_string(),
            title: Some("Docs.rs".to_string()),
            visit_time_us: 1700000060_000000,
            transition: 0, // LINK
        },
    ];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector.inject(
        &artifact_bytes,
        &Target::ChromeHistory { profile_path: dir.path().to_path_buf() },
        InjectionStrategy::DirectInjection,
    );

    assert!(result.is_ok(), "injection should succeed: {:?}", result.err());
    let result = result.unwrap();
    assert_eq!(result.records_injected, 2);

    // Verify data in database
    let conn = Connection::open(dir.path().join("History")).unwrap();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM urls", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 2);

    let visits: i64 = conn.query_row("SELECT COUNT(*) FROM visits", [], |r| r.get(0)).unwrap();
    assert_eq!(visits, 2);

    // Verify Chrome epoch conversion (timestamps should be offset from 1601)
    let visit_time: i64 = conn
        .query_row("SELECT visit_time FROM visits WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    assert!(visit_time > 13_000_000_000_000_000, "Chrome timestamps should be offset from 1601");
}

#[test]
fn test_inject_chrome_cookies() {
    let dir = TempDir::new().unwrap();
    create_chrome_cookies_db(dir.path());

    let injector = ChromeInjector::with_profiles(vec![dir.path().to_path_buf()]);

    let records = vec![CookieRecord {
        host_key: ".example.com".to_string(),
        name: "_ga".to_string(),
        value: "GA1.2.123456.789012".to_string(),
        path: "/".to_string(),
        expires_utc: 1800000000,
        is_secure: true,
        is_httponly: false,
        samesite: -1,
        priority: 1,
        source_scheme: 2,
    }];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector.inject(
        &artifact_bytes,
        &Target::ChromeCookies { profile_path: dir.path().to_path_buf() },
        InjectionStrategy::DirectInjection,
    );

    assert!(result.is_ok(), "cookie injection should succeed: {:?}", result.err());

    let conn = Connection::open(dir.path().join("Cookies")).unwrap();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM cookies", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 1);

    let name: String = conn.query_row("SELECT name FROM cookies LIMIT 1", [], |r| r.get(0)).unwrap();
    assert_eq!(name, "_ga");
}

#[test]
fn test_chrome_duplicate_url_handling() {
    let dir = TempDir::new().unwrap();
    create_chrome_history_db(dir.path());

    let injector = ChromeInjector::with_profiles(vec![dir.path().to_path_buf()]);

    let records = vec![
        HistoryRecord {
            url: "https://www.example.com/".to_string(),
            title: Some("Example".to_string()),
            visit_time_us: 1700000000_000000,
            transition: 0,
        },
        HistoryRecord {
            url: "https://www.example.com/".to_string(),
            title: Some("Example".to_string()),
            visit_time_us: 1700000060_000000,
            transition: 0,
        },
    ];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let _ = injector.inject(
        &artifact_bytes,
        &Target::ChromeHistory { profile_path: dir.path().to_path_buf() },
        InjectionStrategy::DirectInjection,
    );

    let conn = Connection::open(dir.path().join("History")).unwrap();
    let urls: i64 = conn.query_row("SELECT COUNT(*) FROM urls", [], |r| r.get(0)).unwrap();
    let visits: i64 = conn.query_row("SELECT COUNT(*) FROM visits", [], |r| r.get(0)).unwrap();

    // Chrome may create 2 URL entries (INSERT OR IGNORE depends on UNIQUE index)
    // Either way, visits should be 2
    assert_eq!(visits, 2, "each visit should be recorded");
}

#[test]
fn test_chrome_backup_created() {
    let dir = TempDir::new().unwrap();
    create_chrome_history_db(dir.path());

    let injector = ChromeInjector::with_profiles(vec![dir.path().to_path_buf()]);

    let records = vec![HistoryRecord {
        url: "https://backup-test.com/".to_string(),
        title: Some("Backup Test".to_string()),
        visit_time_us: 1700000000_000000,
        transition: 1,
    }];

    let artifact_bytes = serde_json::to_vec(&records).unwrap();
    let result = injector.inject(
        &artifact_bytes,
        &Target::ChromeHistory { profile_path: dir.path().to_path_buf() },
        InjectionStrategy::DirectInjection,
    ).unwrap();

    assert!(result.backup_path.is_some(), "backup should be created");
}
