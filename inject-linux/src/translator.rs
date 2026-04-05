//! Hurd-on-Linux translator interposition (experimental).
//!
//! Implements a Tier 3 injection strategy: instead of writing directly into
//! a browser's SQLite database, a FUSE-based or LD_PRELOAD-based translator
//! intercepts the application's filesystem reads and transparently splices
//! injected data into the response.
//!
//! This approach is inspired by the GNU Hurd translator model, where any
//! filesystem node can be backed by a user-space server.  On Linux we
//! approximate this with:
//!
//! - **FUSE overlay**: mount a filesystem that proxies reads to the real
//!   database but injects additional rows on SELECT queries.
//! - **LD_PRELOAD shim**: intercept `open()` / `read()` / `sqlite3_step()`
//!   at the C library level.
//!
//! Both approaches avoid modifying the on-disk database, which is useful
//! when the target application must remain running.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

/// Translator-based injector (Hurd-on-Linux model).
pub struct TranslatorInjector;

impl Injector for TranslatorInjector {
    fn inject(
        &self,
        _artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        todo!("TranslatorInjector::inject -- FUSE/LD_PRELOAD translator not yet implemented")
    }

    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("TranslatorInjector::verify")
    }

    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("TranslatorInjector::rollback")
    }

    fn available_targets(&self) -> Vec<Target> {
        todo!("TranslatorInjector::available_targets")
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        vec![InjectionStrategy::TranslatorInterposition]
    }
}
