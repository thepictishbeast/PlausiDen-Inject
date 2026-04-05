//! Android SharedPreferences XML injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct SharedPrefsInjector;

impl Injector for SharedPrefsInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("SharedPrefsInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("SharedPrefsInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("SharedPrefsInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("SharedPrefsInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("SharedPrefsInjector::supported_strategies")
    }
}
