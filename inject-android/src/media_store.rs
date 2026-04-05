//! Android MediaStore injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct MediaStoreInjector;

impl Injector for MediaStoreInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("MediaStoreInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("MediaStoreInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("MediaStoreInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("MediaStoreInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("MediaStoreInjector::supported_strategies")
    }
}
