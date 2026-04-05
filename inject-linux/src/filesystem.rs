//! Filesystem artifact injection (timestamps, file content, metadata).
//!
//! Writes generated files to disk with controlled timestamps, ownership,
//! and extended attributes to match plausiden-engine output.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

/// Linux filesystem injector.
pub struct FilesystemInjector;

impl Injector for FilesystemInjector {
    fn inject(
        &self,
        _artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        todo!("FilesystemInjector::inject")
    }

    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("FilesystemInjector::verify")
    }

    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("FilesystemInjector::rollback")
    }

    fn available_targets(&self) -> Vec<Target> {
        todo!("FilesystemInjector::available_targets")
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("FilesystemInjector::supported_strategies")
    }
}
