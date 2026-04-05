//! `/proc` filesystem injection.
//!
//! Uses FUSE or bind-mounts to present synthetic `/proc` entries that
//! corroborate injected artifacts (e.g. `/proc/self/fdinfo` for open
//! file descriptors).

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

/// Linux `/proc` injector.
pub struct ProcInjector;

impl Injector for ProcInjector {
    fn inject(
        &self,
        _artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        todo!("ProcInjector::inject")
    }

    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("ProcInjector::verify")
    }

    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("ProcInjector::rollback")
    }

    fn available_targets(&self) -> Vec<Target> {
        todo!("ProcInjector::available_targets")
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("ProcInjector::supported_strategies")
    }
}
