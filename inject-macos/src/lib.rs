//! `inject-macos` -- macOS injection adapters for PlausiDen.
//!
//! Provides scaffolded adapters for macOS-specific data stores including
//! the filesystem, Spotlight metadata, Core Data persistent stores,
//! FSEvents logs, and Safari browser data.

pub mod browser_safari;
pub mod coredata;
pub mod filesystem;
pub mod fsevents;
pub mod spotlight;
