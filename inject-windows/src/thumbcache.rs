//! Windows thumbnail cache injection (thumbcache_*.db).

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct ThumbcacheInjector;

impl Injector for ThumbcacheInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("ThumbcacheInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("ThumbcacheInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("ThumbcacheInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("ThumbcacheInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("ThumbcacheInjector::supported_strategies")
    }
}
