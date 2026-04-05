//! `inject-linux` -- Linux injection adapters for PlausiDen.
//!
//! This crate provides concrete [`Injector`](inject_core::Injector)
//! implementations that write engine-generated artifacts into Linux data
//! stores: browser SQLite databases, log files, the filesystem, and
//! (experimentally) translator-interposed views.

pub mod browser_chrome;
pub mod browser_firefox;
pub mod filesystem;
pub mod input;
pub mod logs;
pub mod proc;
pub mod translator;

// Re-export the main injector types for convenience.
pub use browser_chrome::ChromeInjector;
pub use browser_firefox::FirefoxInjector;
pub use filesystem::FilesystemInjector;
pub use input::InputInjector;
pub use logs::LogInjector;
pub use proc::ProcInjector;
pub use translator::TranslatorInjector;
