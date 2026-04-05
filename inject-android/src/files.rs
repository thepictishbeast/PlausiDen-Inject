//! Android general file injection (external storage, app data directory).

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct AndroidFileInjector;

impl Injector for AndroidFileInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("AndroidFileInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("AndroidFileInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("AndroidFileInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("AndroidFileInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("AndroidFileInjector::supported_strategies")
    }
}
