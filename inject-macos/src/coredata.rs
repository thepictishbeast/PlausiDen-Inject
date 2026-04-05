//! Core Data persistent store injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct CoreDataInjector;

impl Injector for CoreDataInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("CoreDataInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("CoreDataInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("CoreDataInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("CoreDataInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("CoreDataInjector::supported_strategies")
    }
}
