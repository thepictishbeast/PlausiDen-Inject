//! System and application log injection.
//!
//! Injects log lines into syslog, journald, and application-specific log
//! files with correct timestamps and formatting.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

/// Linux log-file injector.
pub struct LogInjector;

impl Injector for LogInjector {
    fn inject(
        &self,
        _artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        todo!("LogInjector::inject")
    }

    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("LogInjector::verify")
    }

    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("LogInjector::rollback")
    }

    fn available_targets(&self) -> Vec<Target> {
        todo!("LogInjector::available_targets")
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("LogInjector::supported_strategies")
    }
}
