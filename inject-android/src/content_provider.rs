//! Android ContentProvider injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct ContentProviderInjector;

impl Injector for ContentProviderInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("ContentProviderInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("ContentProviderInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("ContentProviderInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("ContentProviderInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("ContentProviderInjector::supported_strategies")
    }
}
