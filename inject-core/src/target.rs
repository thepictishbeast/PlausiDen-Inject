//! Platform-specific default paths for browser databases and other targets.
//!
//! These helpers return well-known locations where browsers store their
//! SQLite databases.  The caller is expected to glob or iterate over profile
//! directories where multiple profiles may exist.

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Firefox
// ---------------------------------------------------------------------------

/// Return the platform-specific root directory where Firefox stores profiles.
///
/// - Linux:   `~/.mozilla/firefox/`
/// - macOS:   `~/Library/Application Support/Firefox/Profiles/`
/// - Windows: `%APPDATA%\Mozilla\Firefox\Profiles\`
pub fn firefox_profiles_root() -> Option<PathBuf> {
    let home = dirs_home()?;

    #[cfg(target_os = "linux")]
    {
        Some(home.join(".mozilla/firefox"))
    }

    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library/Application Support/Firefox/Profiles"))
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|appdata| PathBuf::from(appdata).join("Mozilla\\Firefox\\Profiles"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Given a Firefox profile directory, return the path to `places.sqlite`.
pub fn firefox_places(profile: &Path) -> PathBuf {
    profile.join("places.sqlite")
}

/// Given a Firefox profile directory, return the path to `cookies.sqlite`.
pub fn firefox_cookies(profile: &Path) -> PathBuf {
    profile.join("cookies.sqlite")
}

// ---------------------------------------------------------------------------
// Chrome / Chromium
// ---------------------------------------------------------------------------

/// Return the platform-specific root directory for Chrome user data.
///
/// - Linux:   `~/.config/google-chrome/`
/// - macOS:   `~/Library/Application Support/Google/Chrome/`
/// - Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\`
pub fn chrome_user_data_root() -> Option<PathBuf> {
    let home = dirs_home()?;

    #[cfg(target_os = "linux")]
    {
        Some(home.join(".config/google-chrome"))
    }

    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library/Application Support/Google/Chrome"))
    }

    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|local| PathBuf::from(local).join("Google\\Chrome\\User Data"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Given a Chrome profile directory (e.g. `Default`), return the `History`
/// database path.
pub fn chrome_history(profile: &Path) -> PathBuf {
    profile.join("History")
}

/// Given a Chrome profile directory, return the `Cookies` database path.
pub fn chrome_cookies(profile: &Path) -> PathBuf {
    profile.join("Cookies")
}

// ---------------------------------------------------------------------------
// Chromium (generic)
// ---------------------------------------------------------------------------

/// Root directory for Chromium (non-branded).
///
/// - Linux: `~/.config/chromium/`
pub fn chromium_user_data_root() -> Option<PathBuf> {
    let home = dirs_home()?;

    #[cfg(target_os = "linux")]
    {
        Some(home.join(".config/chromium"))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = home;
        None
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Discover Firefox profile directories under the profiles root.
pub fn discover_firefox_profiles() -> Vec<PathBuf> {
    let Some(root) = firefox_profiles_root() else {
        return Vec::new();
    };
    discover_subdirs(&root)
}

/// Discover Chrome profile directories under the user-data root.
pub fn discover_chrome_profiles() -> Vec<PathBuf> {
    let Some(root) = chrome_user_data_root() else {
        return Vec::new();
    };
    // Chrome uses "Default", "Profile 1", "Profile 2", etc.
    discover_subdirs(&root)
        .into_iter()
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "Default" || name.starts_with("Profile ")
        })
        .collect()
}

/// List immediate subdirectories of `root`.
fn discover_subdirs(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect()
}

/// Return the user's home directory.
fn dirs_home() -> Option<PathBuf> {
    // Prefer $HOME; fall back to platform-specific lookup.
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            #[cfg(target_os = "windows")]
            {
                std::env::var("USERPROFILE").ok().map(PathBuf::from)
            }
            #[cfg(not(target_os = "windows"))]
            {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firefox_places_path_ends_correctly() {
        let profile = PathBuf::from("/home/user/.mozilla/firefox/abc123.default");
        let places = firefox_places(&profile);
        assert!(places.ends_with("places.sqlite"));
    }

    #[test]
    fn chrome_history_path_ends_correctly() {
        let profile = PathBuf::from("/home/user/.config/google-chrome/Default");
        let history = chrome_history(&profile);
        assert!(history.ends_with("History"));
    }
}
