//! `inject-core` -- shared traits, types, and utilities for PlausiDen
//! injection adapters.
//!
//! This crate defines the [`Injector`] trait that every platform adapter
//! must implement, together with supporting types ([`Target`],
//! [`InjectionStrategy`], [`InjectionResult`], [`VerificationStatus`]) and
//! common helper functions for verification and rollback.

pub mod attribution_scrubber;
pub mod conflict_detector;
pub mod error;
pub mod injection_stats;
pub mod rollback;
pub mod rollback_registry;
pub mod sanitizer;
pub mod schema_check;
pub mod snapshot_store;
pub mod sql_sanitizer;
pub mod target;
pub mod target_health;
pub mod traits;
pub mod transaction;
pub mod verification;

// Re-export the public API at crate root for convenience.
pub use error::{InjectError, Result};
pub use traits::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
