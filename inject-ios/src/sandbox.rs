//! iOS app sandbox injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct SandboxInjector;

impl Injector for SandboxInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("SandboxInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("SandboxInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("SandboxInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("SandboxInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("SandboxInjector::supported_strategies")
    }
}
