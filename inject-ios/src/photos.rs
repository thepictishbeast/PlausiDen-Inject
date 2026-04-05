//! iOS Photos library injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct PhotosInjector;

impl Injector for PhotosInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("PhotosInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("PhotosInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("PhotosInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("PhotosInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("PhotosInjector::supported_strategies")
    }
}
