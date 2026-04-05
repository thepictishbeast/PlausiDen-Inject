//! Core traits and enums that every platform adapter must implement.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::Result;

// ---------------------------------------------------------------------------
// Injection strategy
// ---------------------------------------------------------------------------

/// How artifacts are written into the target data store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InjectionStrategy {
    /// Tier 2 -- write directly into the target's backing store (e.g. SQLite
    /// INSERT into `places.sqlite`).  Fast and portable but requires the
    /// target application to be stopped while the database is open.
    DirectInjection,

    /// Tier 3 -- interpose a translator (Hurd-style) between the application
    /// and the filesystem so that reads are transparently rewritten.
    /// Experimental; currently only prototyped on Linux via LD_PRELOAD /
    /// FUSE.
    TranslatorInterposition,

    /// Combination: seed the database with `DirectInjection`, then install a
    /// translator to keep the data consistent across application restarts.
    Hybrid,
}

impl std::fmt::Display for InjectionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectInjection => write!(f, "DirectInjection"),
            Self::TranslatorInterposition => write!(f, "TranslatorInterposition"),
            Self::Hybrid => write!(f, "Hybrid"),
        }
    }
}

// ---------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------

/// A concrete injection target -- identifies *what* data store to write into
/// and where it lives on disk.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Target {
    /// Firefox browsing history (`places.sqlite`).
    FirefoxHistory { profile_path: PathBuf },

    /// Firefox cookies (`cookies.sqlite`).
    FirefoxCookies { profile_path: PathBuf },

    /// Chromium / Chrome / Edge browsing history (`History` SQLite db).
    ChromeHistory { profile_path: PathBuf },

    /// Chromium / Chrome / Edge cookies (`Cookies` SQLite db).
    ChromeCookies { profile_path: PathBuf },

    /// Generic filesystem artifact (any file written to a path).
    Filesystem { path: PathBuf },

    /// System or application log file.
    LogFile { path: PathBuf },

    /// Linux `/proc`-adjacent injection (e.g. `/proc/self/fdinfo`).
    LinuxProc { path: PathBuf },

    /// macOS Spotlight metadata store.
    MacosSpotlight { store_path: PathBuf },

    /// macOS FSEvents log.
    MacosFsEvents { log_path: PathBuf },

    /// Windows NTFS metadata ($MFT, $UsnJrnl).
    WindowsNtfs { volume: PathBuf },

    /// Windows Registry hive.
    WindowsRegistry { hive_path: PathBuf },

    /// Windows Prefetch directory.
    WindowsPrefetch { path: PathBuf },

    /// Windows Event Log (.evtx).
    WindowsEventLog { path: PathBuf },

    /// Android content-provider--backed store.
    AndroidContentProvider { authority: String },

    /// Android SQLite database (app-private).
    AndroidSqlite { db_path: PathBuf },

    /// iOS Contacts store.
    IosContacts { container_path: PathBuf },

    /// iOS Photos library.
    IosPhotos { container_path: PathBuf },

    /// Safari browsing history (`History.db`).
    SafariHistory { db_path: PathBuf },
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirefoxHistory { profile_path } => {
                write!(f, "FirefoxHistory({})", profile_path.display())
            }
            Self::FirefoxCookies { profile_path } => {
                write!(f, "FirefoxCookies({})", profile_path.display())
            }
            Self::ChromeHistory { profile_path } => {
                write!(f, "ChromeHistory({})", profile_path.display())
            }
            Self::ChromeCookies { profile_path } => {
                write!(f, "ChromeCookies({})", profile_path.display())
            }
            Self::Filesystem { path } => write!(f, "Filesystem({})", path.display()),
            Self::LogFile { path } => write!(f, "LogFile({})", path.display()),
            Self::LinuxProc { path } => write!(f, "LinuxProc({})", path.display()),
            Self::MacosSpotlight { store_path } => {
                write!(f, "MacosSpotlight({})", store_path.display())
            }
            Self::MacosFsEvents { log_path } => {
                write!(f, "MacosFsEvents({})", log_path.display())
            }
            Self::WindowsNtfs { volume } => write!(f, "WindowsNtfs({})", volume.display()),
            Self::WindowsRegistry { hive_path } => {
                write!(f, "WindowsRegistry({})", hive_path.display())
            }
            Self::WindowsPrefetch { path } => write!(f, "WindowsPrefetch({})", path.display()),
            Self::WindowsEventLog { path } => write!(f, "WindowsEventLog({})", path.display()),
            Self::AndroidContentProvider { authority } => {
                write!(f, "AndroidContentProvider({authority})")
            }
            Self::AndroidSqlite { db_path } => {
                write!(f, "AndroidSqlite({})", db_path.display())
            }
            Self::IosContacts { container_path } => {
                write!(f, "IosContacts({})", container_path.display())
            }
            Self::IosPhotos { container_path } => {
                write!(f, "IosPhotos({})", container_path.display())
            }
            Self::SafariHistory { db_path } => {
                write!(f, "SafariHistory({})", db_path.display())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// Outcome of a successful injection operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionResult {
    /// Unique identifier for this injection run.
    pub run_id: uuid::Uuid,

    /// Which target was written to.
    pub target: Target,

    /// Strategy that was used.
    pub strategy: InjectionStrategy,

    /// Number of records injected.
    pub records_injected: usize,

    /// Path to the pre-injection backup (if one was created).
    pub backup_path: Option<PathBuf>,

    /// Wall-clock time of the injection (UTC).
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// IDs or keys of the rows that were inserted, so verification and
    /// rollback can locate them.
    pub injected_ids: Vec<String>,
}

/// Result of post-injection verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Every injected record was found in the target store.
    AllPresent {
        checked: usize,
    },

    /// Some injected records are missing.
    PartiallyPresent {
        present: usize,
        missing: usize,
        missing_ids: Vec<String>,
    },

    /// No injected records were found at all.
    NonePresent {
        expected: usize,
    },
}

// ---------------------------------------------------------------------------
// The Injector trait
// ---------------------------------------------------------------------------

/// Platform adapter interface.  Each OS crate provides one or more concrete
/// implementations.
pub trait Injector: Send + Sync {
    /// Deserialize `artifact_bytes` (JSON produced by plausiden-engine) and
    /// write the resulting records into `target` using `strategy`.
    fn inject(
        &self,
        artifact_bytes: &[u8],
        target: &Target,
        strategy: InjectionStrategy,
    ) -> Result<InjectionResult>;

    /// Check whether the records described in `result` are still present in
    /// the target store.
    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus>;

    /// Remove all records that were injected during `result`, restoring the
    /// target to its pre-injection state.
    fn rollback(&self, result: &InjectionResult) -> Result<()>;

    /// Enumerate the targets that this injector can write to on the current
    /// system (e.g. discovered Firefox profiles).
    fn available_targets(&self) -> Vec<Target>;

    /// Which strategies does this injector support?
    fn supported_strategies(&self) -> Vec<InjectionStrategy>;
}
