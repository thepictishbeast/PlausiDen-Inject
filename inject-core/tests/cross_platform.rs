//! Cross-platform integration tests for the PlausiDen injection subsystem.
//!
//! These tests verify that all six platform injectors share consistent
//! behaviour: instantiation, strategy reporting, empty-artifact rejection,
//! and correct output for representative artifact payloads.

use inject_core::{InjectionStrategy, Injector};
use tempfile::TempDir;

// -----------------------------------------------------------------------
// Helpers -- construct every platform injector with a temp output directory
// -----------------------------------------------------------------------

fn make_linux_firefox() -> inject_linux::FirefoxInjector {
    inject_linux::FirefoxInjector::new()
}

fn make_linux_chrome() -> inject_linux::ChromeInjector {
    inject_linux::ChromeInjector::new()
}

fn make_macos_safari() -> inject_macos::browser_safari::SafariInjector {
    inject_macos::browser_safari::SafariInjector::new()
}

fn make_macos_spotlight(dir: &std::path::Path) -> inject_macos::spotlight::SpotlightInjector {
    inject_macos::spotlight::SpotlightInjector::with_output_dir(dir.to_path_buf())
}

fn make_macos_filesystem(
    dir: &std::path::Path,
) -> inject_macos::filesystem::MacosFilesystemInjector {
    inject_macos::filesystem::MacosFilesystemInjector::with_output_dir(dir.to_path_buf())
}

fn make_macos_coredata(dir: &std::path::Path) -> inject_macos::coredata::CoreDataInjector {
    inject_macos::coredata::CoreDataInjector::with_output_dir(dir.to_path_buf())
}

fn make_macos_fsevents(dir: &std::path::Path) -> inject_macos::fsevents::FsEventsInjector {
    inject_macos::fsevents::FsEventsInjector::with_output_dir(dir.to_path_buf())
}

fn make_windows_registry(dir: &std::path::Path) -> inject_windows::registry::RegistryInjector {
    inject_windows::registry::RegistryInjector::with_output_path(dir.join("test.reg"))
}

fn make_windows_prefetch(dir: &std::path::Path) -> inject_windows::prefetch::PrefetchInjector {
    inject_windows::prefetch::PrefetchInjector::new(dir.to_path_buf())
}

fn make_windows_eventlog(dir: &std::path::Path) -> inject_windows::eventlog::EventLogInjector {
    inject_windows::eventlog::EventLogInjector::new(dir.to_path_buf())
}

fn make_windows_lnk(dir: &std::path::Path) -> inject_windows::lnk::LnkInjector {
    inject_windows::lnk::LnkInjector::new(dir.to_path_buf())
}

fn make_windows_recyclebin(
    dir: &std::path::Path,
) -> inject_windows::recycle_bin::RecycleBinInjector {
    inject_windows::recycle_bin::RecycleBinInjector::new(dir.to_path_buf())
}

fn make_windows_thumbcache(
    dir: &std::path::Path,
) -> inject_windows::thumbcache::ThumbcacheInjector {
    inject_windows::thumbcache::ThumbcacheInjector::new(dir.to_path_buf())
}

fn make_windows_ntfs(dir: &std::path::Path) -> inject_windows::ntfs::NtfsInjector {
    inject_windows::ntfs::NtfsInjector::new(dir.to_path_buf())
}

fn make_android_content_provider(
    dir: &std::path::Path,
) -> inject_android::content_provider::ContentProviderInjector {
    inject_android::content_provider::ContentProviderInjector::new(dir.to_path_buf())
}

fn make_android_sqlite(dir: &std::path::Path) -> inject_android::sqlite::AndroidSqliteInjector {
    inject_android::sqlite::AndroidSqliteInjector::new(dir.to_path_buf())
}

fn make_android_shared_prefs(
    dir: &std::path::Path,
) -> inject_android::shared_prefs::SharedPrefsInjector {
    inject_android::shared_prefs::SharedPrefsInjector::new(dir.to_path_buf())
}

fn make_android_media_store(
    dir: &std::path::Path,
) -> inject_android::media_store::MediaStoreInjector {
    inject_android::media_store::MediaStoreInjector::new(dir.to_path_buf())
}

fn make_android_files(dir: &std::path::Path) -> inject_android::files::AndroidFileInjector {
    inject_android::files::AndroidFileInjector::new(dir.to_path_buf())
}

fn make_ios_contacts(dir: &std::path::Path) -> inject_ios::contacts::ContactsInjector {
    inject_ios::contacts::ContactsInjector::new(dir.to_path_buf())
}

fn make_ios_calendar(dir: &std::path::Path) -> inject_ios::calendar::CalendarInjector {
    inject_ios::calendar::CalendarInjector::new(dir.to_path_buf())
}

fn make_ios_photos(dir: &std::path::Path) -> inject_ios::photos::PhotosInjector {
    inject_ios::photos::PhotosInjector::new(dir.to_path_buf())
}

fn make_ios_sandbox(dir: &std::path::Path) -> inject_ios::sandbox::SandboxInjector {
    inject_ios::sandbox::SandboxInjector::new(dir.to_path_buf())
}

// =======================================================================
// Test 1: All 6 platform injectors can be instantiated without panic
// =======================================================================

#[test]
fn all_platform_injectors_instantiate_without_panic() {
    let tmp = TempDir::new().unwrap();
    let d = tmp.path();

    // Linux
    let _firefox = make_linux_firefox();
    let _chrome = make_linux_chrome();

    // macOS
    let _safari = make_macos_safari();
    let _spotlight = make_macos_spotlight(d);
    let _filesystem = make_macos_filesystem(d);
    let _coredata = make_macos_coredata(d);
    let _fsevents = make_macos_fsevents(d);

    // Windows
    let _registry = make_windows_registry(d);
    let _prefetch = make_windows_prefetch(d);
    let _eventlog = make_windows_eventlog(d);
    let _lnk = make_windows_lnk(d);
    let _recyclebin = make_windows_recyclebin(d);
    let _thumbcache = make_windows_thumbcache(d);
    let _ntfs = make_windows_ntfs(d);

    // Android
    let _content_provider = make_android_content_provider(d);
    let _sqlite = make_android_sqlite(d);
    let _shared_prefs = make_android_shared_prefs(d);
    let _media_store = make_android_media_store(d);
    let _files = make_android_files(d);

    // iOS
    let _contacts = make_ios_contacts(d);
    let _calendar = make_ios_calendar(d);
    let _photos = make_ios_photos(d);
    let _sandbox = make_ios_sandbox(d);
}

// =======================================================================
// Test 2: All injectors return correct supported_strategies
// =======================================================================

#[test]
fn all_injectors_return_correct_supported_strategies() {
    let tmp = TempDir::new().unwrap();
    let d = tmp.path();

    // Every injector in the current codebase supports DirectInjection.
    let injectors: Vec<(&str, Box<dyn Injector>)> = vec![
        ("FirefoxInjector", Box::new(make_linux_firefox())),
        ("ChromeInjector", Box::new(make_linux_chrome())),
        ("SafariInjector", Box::new(make_macos_safari())),
        ("SpotlightInjector", Box::new(make_macos_spotlight(d))),
        (
            "MacosFilesystemInjector",
            Box::new(make_macos_filesystem(d)),
        ),
        ("CoreDataInjector", Box::new(make_macos_coredata(d))),
        ("FsEventsInjector", Box::new(make_macos_fsevents(d))),
        ("RegistryInjector", Box::new(make_windows_registry(d))),
        ("PrefetchInjector", Box::new(make_windows_prefetch(d))),
        ("EventLogInjector", Box::new(make_windows_eventlog(d))),
        ("LnkInjector", Box::new(make_windows_lnk(d))),
        ("RecycleBinInjector", Box::new(make_windows_recyclebin(d))),
        ("ThumbcacheInjector", Box::new(make_windows_thumbcache(d))),
        ("NtfsInjector", Box::new(make_windows_ntfs(d))),
        (
            "ContentProviderInjector",
            Box::new(make_android_content_provider(d)),
        ),
        ("AndroidSqliteInjector", Box::new(make_android_sqlite(d))),
        (
            "SharedPrefsInjector",
            Box::new(make_android_shared_prefs(d)),
        ),
        ("MediaStoreInjector", Box::new(make_android_media_store(d))),
        ("AndroidFileInjector", Box::new(make_android_files(d))),
        ("ContactsInjector", Box::new(make_ios_contacts(d))),
        ("CalendarInjector", Box::new(make_ios_calendar(d))),
        ("PhotosInjector", Box::new(make_ios_photos(d))),
        ("SandboxInjector", Box::new(make_ios_sandbox(d))),
    ];

    for (name, injector) in &injectors {
        let strategies = injector.supported_strategies();
        assert!(
            !strategies.is_empty(),
            "{name} returned empty supported_strategies"
        );
        assert!(
            strategies.contains(&InjectionStrategy::DirectInjection),
            "{name} must support DirectInjection"
        );
    }
}

// =======================================================================
// Test 3: All injectors reject empty artifact bytes
// =======================================================================

#[test]
fn all_injectors_reject_empty_artifact_bytes() {
    use inject_core::Target;

    let tmp = TempDir::new().unwrap();
    let d = tmp.path();

    // Empty JSON array -- valid JSON but zero records.
    let empty_array = b"[]";

    let injectors: Vec<(&str, Box<dyn Injector>, Target)> = vec![
        (
            "FirefoxInjector",
            Box::new(make_linux_firefox()),
            Target::FirefoxHistory {
                profile_path: d.to_path_buf(),
            },
        ),
        (
            "ChromeInjector",
            Box::new(make_linux_chrome()),
            Target::ChromeHistory {
                profile_path: d.to_path_buf(),
            },
        ),
        (
            "SafariInjector",
            Box::new(make_macos_safari()),
            Target::SafariHistory {
                db_path: d.join("History.db"),
            },
        ),
        (
            "SpotlightInjector",
            Box::new(make_macos_spotlight(d)),
            Target::MacosSpotlight {
                store_path: d.to_path_buf(),
            },
        ),
        (
            "MacosFilesystemInjector",
            Box::new(make_macos_filesystem(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "CoreDataInjector",
            Box::new(make_macos_coredata(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "FsEventsInjector",
            Box::new(make_macos_fsevents(d)),
            Target::MacosFsEvents {
                log_path: d.to_path_buf(),
            },
        ),
        (
            "RegistryInjector",
            Box::new(make_windows_registry(d)),
            Target::WindowsRegistry {
                hive_path: d.join("test.reg"),
            },
        ),
        (
            "PrefetchInjector",
            Box::new(make_windows_prefetch(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "EventLogInjector",
            Box::new(make_windows_eventlog(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "LnkInjector",
            Box::new(make_windows_lnk(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "RecycleBinInjector",
            Box::new(make_windows_recyclebin(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "ThumbcacheInjector",
            Box::new(make_windows_thumbcache(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "NtfsInjector",
            Box::new(make_windows_ntfs(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "ContentProviderInjector",
            Box::new(make_android_content_provider(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "AndroidSqliteInjector",
            Box::new(make_android_sqlite(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "SharedPrefsInjector",
            Box::new(make_android_shared_prefs(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "MediaStoreInjector",
            Box::new(make_android_media_store(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "AndroidFileInjector",
            Box::new(make_android_files(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "ContactsInjector",
            Box::new(make_ios_contacts(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "CalendarInjector",
            Box::new(make_ios_calendar(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "PhotosInjector",
            Box::new(make_ios_photos(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
        (
            "SandboxInjector",
            Box::new(make_ios_sandbox(d)),
            Target::Filesystem {
                path: d.to_path_buf(),
            },
        ),
    ];

    for (name, injector, target) in &injectors {
        let result = injector.inject(empty_array, target, InjectionStrategy::DirectInjection);
        assert!(result.is_err(), "{name} should reject an empty artifact");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("no injectable records")
                || err_msg.contains("EmptyArtifact")
                || err_msg.contains("empty"),
            "{name}: unexpected error message: {err_msg}"
        );
    }
}

// =======================================================================
// Test 4: Firefox + Chrome + Safari all handle the same history record format
// =======================================================================

#[test]
fn browser_injectors_handle_same_history_format() {
    use inject_core::Target;

    let tmp = TempDir::new().unwrap();
    let d = tmp.path();

    // A common browsing-history payload that each browser injector should
    // be able to *parse* (even though the database won't exist to write to,
    // we verify the deserialization path doesn't panic and the error is
    // about the missing database, not a schema mismatch).

    // Firefox format
    let firefox_payload = serde_json::to_vec(&[serde_json::json!({
        "url": "https://example.com/page",
        "title": "Example",
        "visit_date_us": 1_700_000_000_000_000_i64,
        "visit_type": 1,
        "frecency": 100
    })])
    .unwrap();

    let firefox = make_linux_firefox();
    let ff_target = Target::FirefoxHistory {
        profile_path: d.to_path_buf(),
    };
    let ff_result = firefox.inject(
        &firefox_payload,
        &ff_target,
        InjectionStrategy::DirectInjection,
    );
    // Should fail because places.sqlite doesn't exist, not because of
    // deserialization.
    assert!(ff_result.is_err());
    let ff_err = format!("{}", ff_result.unwrap_err());
    assert!(
        ff_err.contains("not found") || ff_err.contains("DatabaseNotFound"),
        "Firefox: expected DatabaseNotFound, got: {ff_err}"
    );

    // Chrome format
    let chrome_payload = serde_json::to_vec(&[serde_json::json!({
        "url": "https://example.com/page",
        "title": "Example",
        "visit_time_us": 1_700_000_000_000_000_i64,
        "transition": 0
    })])
    .unwrap();

    let chrome = make_linux_chrome();
    let ch_target = Target::ChromeHistory {
        profile_path: d.to_path_buf(),
    };
    let ch_result = chrome.inject(
        &chrome_payload,
        &ch_target,
        InjectionStrategy::DirectInjection,
    );
    assert!(ch_result.is_err());
    let ch_err = format!("{}", ch_result.unwrap_err());
    assert!(
        ch_err.contains("not found") || ch_err.contains("DatabaseNotFound"),
        "Chrome: expected DatabaseNotFound, got: {ch_err}"
    );

    // Safari format
    let safari_payload = serde_json::to_vec(&[serde_json::json!({
        "url": "https://example.com/page",
        "title": "Example",
        "visit_time_unix": 1_700_000_000_i64,
        "visit_count": 1,
        "domain_expansion": "example.com"
    })])
    .unwrap();

    let safari = make_macos_safari();
    let sf_target = Target::SafariHistory {
        db_path: d.join("History.db"),
    };
    let sf_result = safari.inject(
        &safari_payload,
        &sf_target,
        InjectionStrategy::DirectInjection,
    );
    assert!(sf_result.is_err());
    let sf_err = format!("{}", sf_result.unwrap_err());
    assert!(
        sf_err.contains("not found") || sf_err.contains("DatabaseNotFound"),
        "Safari: expected DatabaseNotFound, got: {sf_err}"
    );
}

// =======================================================================
// Test 5: Windows injectors write to correct locations
// =======================================================================

#[test]
fn windows_injectors_write_to_correct_locations() {
    use inject_core::{Target, VerificationStatus};

    let tmp = TempDir::new().unwrap();
    let d = tmp.path();

    // -- Registry: writes a .reg file --
    let reg_dir = d.join("registry");
    std::fs::create_dir_all(&reg_dir).unwrap();
    let reg_injector = make_windows_registry(&reg_dir);

    let reg_entries = serde_json::to_vec(&[serde_json::json!({
        "key_path": r"HKEY_CURRENT_USER\Software\Test",
        "value_name": "TestValue",
        "value_type": "RegSz",
        "value_data": {"String": "hello"}
    })])
    .unwrap();

    let reg_target = Target::WindowsRegistry {
        hive_path: reg_dir.join("test.reg"),
    };
    let reg_result = reg_injector
        .inject(
            &reg_entries,
            &reg_target,
            InjectionStrategy::DirectInjection,
        )
        .unwrap();
    assert_eq!(reg_result.records_injected, 1);
    assert!(
        reg_dir.join("test.reg").exists(),
        "registry .reg file must exist"
    );
    let reg_content = std::fs::read_to_string(reg_dir.join("test.reg")).unwrap();
    assert!(reg_content.contains("Windows Registry Editor Version 5.00"));

    // -- Prefetch: writes .pf files --
    let pf_dir = d.join("prefetch");
    let pf_injector = make_windows_prefetch(&pf_dir);
    let pf_records = serde_json::to_vec(&[serde_json::json!({
        "executable_name": "NOTEPAD.EXE",
        "prefetch_hash": "AABB1122",
        "run_count": 5,
        "last_run_times": ["2026-01-01T00:00:00Z"],
        "files_accessed": ["C:\\Windows\\notepad.exe"]
    })])
    .unwrap();

    let pf_result = pf_injector
        .inject(
            &pf_records,
            &Target::Filesystem {
                path: pf_dir.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();
    assert_eq!(pf_result.records_injected, 1);
    assert!(pf_dir.join("NOTEPAD.EXE-AABB1122.pf").exists());

    // -- EventLog: writes XML files --
    let el_dir = d.join("eventlog");
    let el_injector = make_windows_eventlog(&el_dir);
    let el_records = serde_json::to_vec(&[serde_json::json!({
        "event_id": 4624,
        "level": "Information",
        "source": "Security",
        "channel": "Security",
        "computer": "WORKSTATION",
        "timestamp": "2026-01-01T00:00:00Z",
        "message": "Logon success"
    })])
    .unwrap();

    let el_result = el_injector
        .inject(
            &el_records,
            &Target::Filesystem {
                path: el_dir.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();
    assert_eq!(el_result.records_injected, 1);
    let xml = std::fs::read_to_string(el_dir.join("event_000000.xml")).unwrap();
    assert!(xml.contains("4624"));

    // -- LNK: writes .lnk.json files --
    let lnk_dir = d.join("lnk");
    let lnk_injector = make_windows_lnk(&lnk_dir);
    let lnk_records = serde_json::to_vec(&[serde_json::json!({
        "target_path": "C:\\Program Files\\app.exe",
        "working_dir": "C:\\Program Files",
        "description": "Application",
        "icon_location": null,
        "created_at": "2026-01-01T00:00:00Z",
        "modified_at": "2026-01-01T00:00:00Z",
        "accessed_at": "2026-01-01T00:00:00Z",
        "target_size": 1024,
        "show_command": "Normal"
    })])
    .unwrap();

    let lnk_result = lnk_injector
        .inject(
            &lnk_records,
            &Target::Filesystem {
                path: lnk_dir.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();
    assert_eq!(lnk_result.records_injected, 1);
    assert!(
        lnk_result.injected_ids[0].contains(".lnk.json"),
        "LNK output should be .lnk.json"
    );

    // -- RecycleBin: writes $I*.json files --
    let rb_dir = d.join("recyclebin");
    let rb_injector = make_windows_recyclebin(&rb_dir);
    let rb_records = serde_json::to_vec(&[serde_json::json!({
        "original_path": "C:\\Users\\user\\secret.docx",
        "file_size": 50000,
        "deleted_at": "2026-01-01T00:00:00Z"
    })])
    .unwrap();

    let rb_result = rb_injector
        .inject(
            &rb_records,
            &Target::Filesystem {
                path: rb_dir.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();
    assert_eq!(rb_result.records_injected, 1);
    assert!(rb_dir.join("$I000000.json").exists());

    // -- Thumbcache: writes thumb_*.json files --
    let tc_dir = d.join("thumbcache");
    let tc_injector = make_windows_thumbcache(&tc_dir);
    let tc_records = serde_json::to_vec(&[serde_json::json!({
        "original_path": "C:\\Users\\user\\photo.jpg",
        "thumbnail_size": "Medium",
        "image_hash": "abc123",
        "cached_at": "2026-01-01T00:00:00Z"
    })])
    .unwrap();

    let tc_result = tc_injector
        .inject(
            &tc_records,
            &Target::Filesystem {
                path: tc_dir.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();
    assert_eq!(tc_result.records_injected, 1);
    assert!(tc_dir.join("thumb_0000.json").exists());

    // -- NTFS: writes mft_*.json files --
    let ntfs_dir = d.join("ntfs");
    let ntfs_injector = make_windows_ntfs(&ntfs_dir);
    let ntfs_records = serde_json::to_vec(&[serde_json::json!({
        "record_number": 12345,
        "file_path": "C:\\Users\\user\\doc.txt",
        "parent_record": 100,
        "created_at": "2026-01-01T00:00:00Z",
        "modified_at": "2026-01-01T00:00:00Z",
        "accessed_at": "2026-01-01T00:00:00Z",
        "mft_modified_at": "2026-01-01T00:00:00Z",
        "file_size": 4096,
        "is_directory": false,
        "is_deleted": false
    })])
    .unwrap();

    let ntfs_result = ntfs_injector
        .inject(
            &ntfs_records,
            &Target::Filesystem {
                path: ntfs_dir.clone(),
            },
            InjectionStrategy::DirectInjection,
        )
        .unwrap();
    assert_eq!(ntfs_result.records_injected, 1);
    assert!(ntfs_dir.join("mft_12345.json").exists());

    // Verify all results report AllPresent.
    for (name, injector, result) in [
        ("Prefetch", &pf_injector as &dyn Injector, &pf_result),
        ("EventLog", &el_injector as &dyn Injector, &el_result),
        ("LNK", &lnk_injector as &dyn Injector, &lnk_result),
        ("RecycleBin", &rb_injector as &dyn Injector, &rb_result),
        ("Thumbcache", &tc_injector as &dyn Injector, &tc_result),
        ("NTFS", &ntfs_injector as &dyn Injector, &ntfs_result),
    ] {
        let status = injector.verify(result).unwrap();
        assert!(
            matches!(status, VerificationStatus::AllPresent { .. }),
            "{name} verification should report AllPresent"
        );
    }
}

// =======================================================================
// Test 6: macOS injectors produce valid output
// =======================================================================

#[test]
fn macos_injectors_produce_valid_output() {
    use inject_core::{Target, VerificationStatus};

    let tmp = TempDir::new().unwrap();
    let d = tmp.path();

    // -- Safari: can deserialize payload (db missing is expected) --
    let safari = make_macos_safari();
    let safari_payload = serde_json::to_vec(&[serde_json::json!({
        "url": "https://example.com",
        "title": "Example",
        "visit_time_unix": 1_700_000_000_i64,
        "visit_count": 1,
        "domain_expansion": "example.com"
    })])
    .unwrap();

    let safari_target = Target::SafariHistory {
        db_path: d.join("History.db"),
    };
    let safari_err = safari
        .inject(
            &safari_payload,
            &safari_target,
            InjectionStrategy::DirectInjection,
        )
        .unwrap_err();
    let err_str = format!("{safari_err}");
    assert!(
        err_str.contains("not found"),
        "Safari should fail with db not found, got: {err_str}"
    );

    // -- Spotlight: writes JSON with records --
    let sl_dir = d.join("spotlight");
    let sl_injector = make_macos_spotlight(&sl_dir);
    let sl_records = serde_json::to_vec(&[serde_json::json!({
        "file_path": "/Users/test/report.pdf",
        "content_type": "com.adobe.pdf",
        "display_name": "report.pdf",
        "last_used": "2026-03-15T14:30:00Z",
        "content_hash": "a1b2c3d4"
    })])
    .unwrap();

    let sl_target = Target::MacosSpotlight {
        store_path: sl_dir.clone(),
    };
    let sl_result = sl_injector
        .inject(&sl_records, &sl_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(sl_result.records_injected, 1);
    let sl_status = sl_injector.verify(&sl_result).unwrap();
    assert!(matches!(sl_status, VerificationStatus::AllPresent { .. }));

    // -- Filesystem: writes JSON with xattrs --
    let fs_dir = d.join("filesystem");
    let fs_injector = make_macos_filesystem(&fs_dir);
    let fs_records = serde_json::to_vec(&[serde_json::json!({
        "path": "/Users/test/Downloads/doc.pdf",
        "filename": "doc.pdf",
        "file_size": 1024,
        "xattrs": {"com.apple.quarantine": "test"},
        "resource_fork": null,
        "spotlight_comment": "important",
        "created": "2026-01-01T00:00:00Z",
        "modified": "2026-01-01T00:00:00Z",
        "accessed": null
    })])
    .unwrap();

    let fs_target = Target::Filesystem {
        path: fs_dir.clone(),
    };
    let fs_result = fs_injector
        .inject(&fs_records, &fs_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(fs_result.records_injected, 1);
    let fs_status = fs_injector.verify(&fs_result).unwrap();
    assert!(matches!(fs_status, VerificationStatus::AllPresent { .. }));

    // -- CoreData: writes JSON with converted timestamps --
    let cd_dir = d.join("coredata");
    let cd_injector = make_macos_coredata(&cd_dir);
    let cd_records = serde_json::to_vec(&[serde_json::json!({
        "entity_name": "ZNOTE",
        "object_id": 42,
        "attributes": {"ZTITLE": "Test Note"},
        "relationships": {},
        "created_at": "2026-01-01T00:00:00Z",
        "modified_at": "2026-01-01T00:00:00Z"
    })])
    .unwrap();

    let cd_target = Target::Filesystem {
        path: cd_dir.clone(),
    };
    let cd_result = cd_injector
        .inject(&cd_records, &cd_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(cd_result.records_injected, 1);
    let cd_status = cd_injector.verify(&cd_result).unwrap();
    assert!(matches!(cd_status, VerificationStatus::AllPresent { .. }));

    // Verify the CoreData output contains z_creation_date (epoch-converted).
    let cd_file = cd_result.injected_ids[0].split("::").next().unwrap();
    let cd_content = std::fs::read_to_string(cd_file).unwrap();
    assert!(
        cd_content.contains("z_creation_date"),
        "CoreData output must contain z_creation_date"
    );

    // -- FSEvents: writes JSON with raw flags --
    let fe_dir = d.join("fsevents");
    let fe_injector = make_macos_fsevents(&fe_dir);
    let fe_records = serde_json::to_vec(&[serde_json::json!({
        "event_id": 1001,
        "path": "/Users/test/Documents/report.pdf",
        "flags": ["Created"],
        "timestamp": "2026-03-15T14:30:00Z"
    })])
    .unwrap();

    let fe_target = Target::MacosFsEvents {
        log_path: fe_dir.clone(),
    };
    let fe_result = fe_injector
        .inject(&fe_records, &fe_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(fe_result.records_injected, 1);
    let fe_status = fe_injector.verify(&fe_result).unwrap();
    assert!(matches!(fe_status, VerificationStatus::AllPresent { .. }));

    // Verify the FSEvents output contains raw_flags.
    let fe_file = fe_result.injected_ids[0].split("::").next().unwrap();
    let fe_content = std::fs::read_to_string(fe_file).unwrap();
    assert!(
        fe_content.contains("raw_flags"),
        "FSEvents output must contain raw_flags"
    );
}

// =======================================================================
// Test 7: Android injectors produce valid output
// =======================================================================

#[test]
fn android_injectors_produce_valid_output() {
    use inject_core::{Target, VerificationStatus};

    let tmp = TempDir::new().unwrap();
    let d = tmp.path();

    // -- ContentProvider --
    let cp_dir = d.join("content_provider");
    let cp_injector = make_android_content_provider(&cp_dir);
    let cp_records = serde_json::to_vec(&[serde_json::json!({
        "uri": "content://com.android.contacts/contacts",
        "display_name": "Alice Smith",
        "mime_type": "vnd.android.cursor.item/contact",
        "columns": {"phone": "+1-555-0100"},
        "last_modified": "2026-01-01T00:00:00Z"
    })])
    .unwrap();

    let cp_target = Target::Filesystem {
        path: cp_dir.clone(),
    };
    let cp_result = cp_injector
        .inject(&cp_records, &cp_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(cp_result.records_injected, 1);
    let cp_status = cp_injector.verify(&cp_result).unwrap();
    assert!(matches!(cp_status, VerificationStatus::AllPresent { .. }));
    // Verify content is parseable JSON.
    let cp_content = std::fs::read_to_string(&cp_result.injected_ids[0]).unwrap();
    let _: serde_json::Value = serde_json::from_str(&cp_content).unwrap();

    // -- SQLite --
    let sq_dir = d.join("sqlite");
    let sq_injector = make_android_sqlite(&sq_dir);
    let sq_records = serde_json::to_vec(&[serde_json::json!({
        "package_name": "com.android.providers.telephony",
        "database_name": "mmssms.db",
        "table_name": "sms",
        "row_data": {"_id": "1", "body": "Hello"},
        "created_at": "2026-01-01T00:00:00Z"
    })])
    .unwrap();

    let sq_target = Target::Filesystem {
        path: sq_dir.clone(),
    };
    let sq_result = sq_injector
        .inject(&sq_records, &sq_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(sq_result.records_injected, 1);
    let sq_status = sq_injector.verify(&sq_result).unwrap();
    assert!(matches!(sq_status, VerificationStatus::AllPresent { .. }));

    // -- SharedPrefs --
    let sp_dir = d.join("shared_prefs");
    let sp_injector = make_android_shared_prefs(&sp_dir);
    let sp_records = serde_json::to_vec(&[serde_json::json!({
        "package_name": "com.example.app",
        "prefs_name": "settings",
        "entries": [
            {"key": "username", "value": {"type": "StringVal", "value": "demo"}},
            {"key": "count", "value": {"type": "IntVal", "value": 42}},
            {"key": "dark", "value": {"type": "BoolVal", "value": true}}
        ]
    })])
    .unwrap();

    let sp_target = Target::Filesystem {
        path: sp_dir.clone(),
    };
    let sp_result = sp_injector
        .inject(&sp_records, &sp_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(sp_result.records_injected, 1);
    let sp_status = sp_injector.verify(&sp_result).unwrap();
    assert!(matches!(sp_status, VerificationStatus::AllPresent { .. }));
    // Verify the output is XML.
    let sp_content = std::fs::read_to_string(&sp_result.injected_ids[0]).unwrap();
    assert!(
        sp_content.contains("<map>"),
        "SharedPrefs output must be XML"
    );

    // -- MediaStore --
    let ms_dir = d.join("media_store");
    let ms_injector = make_android_media_store(&ms_dir);
    let ms_records = serde_json::to_vec(&[serde_json::json!({
        "relative_path": "DCIM/Camera/IMG_001.jpg",
        "display_name": "IMG_001.jpg",
        "mime_type": "image/jpeg",
        "media_type": "Image",
        "size_bytes": 3_500_000,
        "date_taken": "2026-01-01T00:00:00Z",
        "date_added": "2026-01-01T00:00:00Z",
        "width": 4032,
        "height": 3024
    })])
    .unwrap();

    let ms_target = Target::Filesystem {
        path: ms_dir.clone(),
    };
    let ms_result = ms_injector
        .inject(&ms_records, &ms_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(ms_result.records_injected, 1);
    let ms_status = ms_injector.verify(&ms_result).unwrap();
    assert!(matches!(ms_status, VerificationStatus::AllPresent { .. }));

    // -- Files --
    let af_dir = d.join("files");
    let af_injector = make_android_files(&af_dir);
    let af_records = serde_json::to_vec(&[serde_json::json!({
        "device_path": "/sdcard/Download/report.pdf",
        "filename": "report.pdf",
        "mime_type": "application/pdf",
        "size_bytes": 125_000,
        "created": "2026-01-01T00:00:00Z",
        "modified": "2026-01-01T00:00:00Z",
        "owner_package": ""
    })])
    .unwrap();

    let af_target = Target::Filesystem {
        path: af_dir.clone(),
    };
    let af_result = af_injector
        .inject(&af_records, &af_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(af_result.records_injected, 1);
    let af_status = af_injector.verify(&af_result).unwrap();
    assert!(matches!(af_status, VerificationStatus::AllPresent { .. }));
}

// =======================================================================
// Test 8: iOS injectors produce valid output
// =======================================================================

#[test]
fn ios_injectors_produce_valid_output() {
    use inject_core::{Target, VerificationStatus};

    let tmp = TempDir::new().unwrap();
    let d = tmp.path();

    // -- Contacts --
    let ct_dir = d.join("contacts");
    let ct_injector = make_ios_contacts(&ct_dir);
    let ct_records = serde_json::to_vec(&[serde_json::json!({
        "first_name": "Jane",
        "last_name": "Doe",
        "phone_numbers": ["+1-555-0199"],
        "emails": ["jane@example.com"],
        "organization": "Example Corp",
        "creation_date": "2026-01-01T00:00:00Z",
        "modification_date": "2026-01-01T00:00:00Z"
    })])
    .unwrap();

    let ct_target = Target::Filesystem {
        path: ct_dir.clone(),
    };
    let ct_result = ct_injector
        .inject(&ct_records, &ct_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(ct_result.records_injected, 1);
    let ct_status = ct_injector.verify(&ct_result).unwrap();
    assert!(matches!(ct_status, VerificationStatus::AllPresent { .. }));
    // Verify content is parseable JSON with correct fields.
    let ct_content = std::fs::read_to_string(&ct_result.injected_ids[0]).unwrap();
    let ct_val: serde_json::Value = serde_json::from_str(&ct_content).unwrap();
    assert_eq!(ct_val["first_name"], "Jane");
    assert_eq!(ct_val["last_name"], "Doe");

    // -- Calendar --
    let cal_dir = d.join("calendar");
    let cal_injector = make_ios_calendar(&cal_dir);
    let cal_records = serde_json::to_vec(&[serde_json::json!({
        "title": "Team Standup",
        "calendar_name": "Work",
        "location": "Room B",
        "notes": "Weekly sync",
        "start_date": "2026-04-01T09:00:00Z",
        "end_date": "2026-04-01T10:00:00Z",
        "all_day": false,
        "creation_date": "2026-01-01T00:00:00Z"
    })])
    .unwrap();

    let cal_target = Target::Filesystem {
        path: cal_dir.clone(),
    };
    let cal_result = cal_injector
        .inject(
            &cal_records,
            &cal_target,
            InjectionStrategy::DirectInjection,
        )
        .unwrap();
    assert_eq!(cal_result.records_injected, 1);
    let cal_status = cal_injector.verify(&cal_result).unwrap();
    assert!(matches!(cal_status, VerificationStatus::AllPresent { .. }));
    let cal_content = std::fs::read_to_string(&cal_result.injected_ids[0]).unwrap();
    let cal_val: serde_json::Value = serde_json::from_str(&cal_content).unwrap();
    assert_eq!(cal_val["title"], "Team Standup");

    // -- Photos --
    let ph_dir = d.join("photos");
    let ph_injector = make_ios_photos(&ph_dir);
    let ph_records = serde_json::to_vec(&[serde_json::json!({
        "filename": "IMG_0042.HEIC",
        "directory": "DCIM/100APPLE",
        "uniform_type_id": "public.heic",
        "pixel_width": 4032,
        "pixel_height": 3024,
        "file_size": 2_800_000,
        "date_created": "2026-01-01T00:00:00Z",
        "date_added": "2026-01-01T00:00:00Z",
        "favorite": false,
        "hidden": false
    })])
    .unwrap();

    let ph_target = Target::Filesystem {
        path: ph_dir.clone(),
    };
    let ph_result = ph_injector
        .inject(&ph_records, &ph_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(ph_result.records_injected, 1);
    let ph_status = ph_injector.verify(&ph_result).unwrap();
    assert!(matches!(ph_status, VerificationStatus::AllPresent { .. }));

    // -- Sandbox --
    let sb_dir = d.join("sandbox");
    let sb_injector = make_ios_sandbox(&sb_dir);
    let sb_records = serde_json::to_vec(&[serde_json::json!({
        "bundle_id": "com.example.notes",
        "location": "Documents",
        "filename": "user_data.sqlite",
        "mime_type": "application/x-sqlite3",
        "size_bytes": 48_000,
        "created": "2026-01-01T00:00:00Z",
        "modified": "2026-01-01T00:00:00Z"
    })])
    .unwrap();

    let sb_target = Target::Filesystem {
        path: sb_dir.clone(),
    };
    let sb_result = sb_injector
        .inject(&sb_records, &sb_target, InjectionStrategy::DirectInjection)
        .unwrap();
    assert_eq!(sb_result.records_injected, 1);
    let sb_status = sb_injector.verify(&sb_result).unwrap();
    assert!(matches!(sb_status, VerificationStatus::AllPresent { .. }));
    let sb_content = std::fs::read_to_string(&sb_result.injected_ids[0]).unwrap();
    let sb_val: serde_json::Value = serde_json::from_str(&sb_content).unwrap();
    assert_eq!(sb_val["bundle_id"], "com.example.notes");
    assert_eq!(sb_val["location"], "Documents");
}
