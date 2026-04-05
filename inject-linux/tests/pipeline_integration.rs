//! Pipeline integration test — verifies engine artifacts can be injected.
//!
//! This test creates a mock Firefox database, generates artifacts using
//! the same format the engine produces, injects them, and verifies they
//! appear correctly in the database.

use inject_core::sanitizer;
use inject_linux::browser_firefox::{FirefoxInjector, HistoryRecord, CookieRecord};
use inject_core::{Injector, InjectionStrategy, Target};
use rusqlite::Connection;
use tempfile::TempDir;

fn create_firefox_db(dir: &std::path::Path) {
    let conn = Connection::open(dir.join("places.sqlite")).unwrap();
    conn.execute_batch(
        "CREATE TABLE moz_places (
            id INTEGER PRIMARY KEY, url TEXT, title TEXT, rev_host TEXT,
            visit_count INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0,
            typed INTEGER DEFAULT 0, frecency INTEGER DEFAULT -1,
            last_visit_date INTEGER, guid TEXT, foreign_count INTEGER DEFAULT 0,
            url_hash INTEGER DEFAULT 0, description TEXT, preview_image_url TEXT,
            origin_id INTEGER
        );
        CREATE TABLE moz_historyvisits (
            id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
            visit_date INTEGER, visit_type INTEGER, session INTEGER
        );
        CREATE UNIQUE INDEX moz_places_url_uniqueindex ON moz_places(url);
        CREATE UNIQUE INDEX moz_places_guid_uniqueindex ON moz_places(guid);"
    ).unwrap();

    let conn2 = Connection::open(dir.join("cookies.sqlite")).unwrap();
    conn2.execute_batch(
        "CREATE TABLE moz_cookies (
            id INTEGER PRIMARY KEY, originAttributes TEXT DEFAULT '',
            name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER,
            lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER,
            isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0,
            sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0,
            schemeMap INTEGER DEFAULT 0
        );"
    ).unwrap();
}

/// Test: Generate engine-format artifacts → sanitize → inject → verify
#[test]
fn test_engine_to_inject_pipeline() {
    let dir = TempDir::new().unwrap();
    create_firefox_db(dir.path());

    // Simulate engine output (same JSON format as engine-browser)
    let engine_output = serde_json::json!([{
        "meta": {
            "id": "00000000-0000-0000-0000-000000000001",
            "category": "BrowserActivity",
            "created_at": "2026-04-05T10:00:00Z",
            "modified_at": "2026-04-05T10:00:00Z",
            "size_bytes": 200
        },
        "url": "https://www.rust-lang.org/learn",
        "title": "Learn Rust",
        "visit_time": "2026-04-05T10:00:00Z",
        "referrer": null,
        "transition": "Typed",
        "visit_count": 1
    }]);

    // Sanitize — strip engine metadata
    let raw_bytes = serde_json::to_vec(&engine_output).unwrap();
    let sanitized = sanitizer::sanitize_for_injection(&raw_bytes).unwrap();

    // Verify no PlausiDen markers
    sanitizer::verify_no_markers(&sanitized).unwrap();

    // Convert to inject format
    let records = vec![HistoryRecord {
        url: "https://www.rust-lang.org/learn".to_string(),
        title: Some("Learn Rust".to_string()),
        visit_date_us: 1712311200_000000,
        visit_type: 2, // TYPED
        frecency: 100,
    }];

    let inject_bytes = serde_json::to_vec(&records).unwrap();

    // Inject
    let injector = FirefoxInjector::with_profiles(vec![dir.path().to_path_buf()]);
    let result = injector.inject(
        &inject_bytes,
        &Target::FirefoxHistory { profile_path: dir.path().to_path_buf() },
        InjectionStrategy::DirectInjection,
    ).unwrap();

    assert_eq!(result.records_injected, 1);

    // Verify in database
    let conn = Connection::open(dir.path().join("places.sqlite")).unwrap();
    let url: String = conn.query_row(
        "SELECT url FROM moz_places LIMIT 1", [], |r| r.get(0)
    ).unwrap();
    assert_eq!(url, "https://www.rust-lang.org/learn");
}

/// Test: Sanitized output contains no engine markers
#[test]
fn test_sanitizer_strips_all_markers() {
    let engine_json = serde_json::json!({
        "meta": {"id": "test", "category": "BrowserActivity"},
        "artifact_id": "should-be-removed",
        "generation_context": {"seed": 42},
        "url": "https://example.com",
        "title": "Test"
    });

    let bytes = serde_json::to_vec(&engine_json).unwrap();
    let sanitized = sanitizer::sanitize_for_injection(&bytes).unwrap();

    let parsed: serde_json::Value = serde_json::from_slice(&sanitized).unwrap();
    assert!(parsed.get("meta").is_none(), "meta should be stripped");
    assert!(parsed.get("artifact_id").is_none(), "artifact_id should be stripped");
    assert!(parsed.get("generation_context").is_none(), "generation_context should be stripped");
    assert!(parsed.get("url").is_some(), "url should be preserved");
}

/// Test: Injected cookies have correct format
#[test]
fn test_cookie_injection_roundtrip() {
    let dir = TempDir::new().unwrap();
    create_firefox_db(dir.path());

    let records = vec![
        CookieRecord {
            name: "_ga".to_string(),
            value: "GA1.2.123456.789012".to_string(),
            host: ".rust-lang.org".to_string(),
            path: "/".to_string(),
            expiry: 1800000000,
            is_secure: true,
            is_http_only: false,
            same_site: 0,
        },
    ];

    let bytes = serde_json::to_vec(&records).unwrap();
    let injector = FirefoxInjector::with_profiles(vec![dir.path().to_path_buf()]);

    let result = injector.inject(
        &bytes,
        &Target::FirefoxCookies { profile_path: dir.path().to_path_buf() },
        InjectionStrategy::DirectInjection,
    ).unwrap();

    assert_eq!(result.records_injected, 1);

    let conn = Connection::open(dir.path().join("cookies.sqlite")).unwrap();
    let name: String = conn.query_row("SELECT name FROM moz_cookies LIMIT 1", [], |r| r.get(0)).unwrap();
    assert_eq!(name, "_ga");
}
