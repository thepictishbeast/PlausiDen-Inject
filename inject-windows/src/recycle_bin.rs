//! Windows Recycle Bin ($I / $R file) injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct RecycleBinInjector;

impl Injector for RecycleBinInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("RecycleBinInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("RecycleBinInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("RecycleBinInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("RecycleBinInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("RecycleBinInjector::supported_strategies")
    }
}
