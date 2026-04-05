//! `inject-android` -- Android injection adapters for PlausiDen.
//!
//! Provides scaffolded adapters for Android data stores including content
//! providers, app-private SQLite databases, SharedPreferences XML files,
//! the MediaStore, and general file injection.

pub mod content_provider;
pub mod files;
pub mod media_store;
pub mod shared_prefs;
pub mod sqlite;
