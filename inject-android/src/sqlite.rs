//! Android app-private SQLite database injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct AndroidSqliteInjector;

impl Injector for AndroidSqliteInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("AndroidSqliteInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("AndroidSqliteInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("AndroidSqliteInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("AndroidSqliteInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("AndroidSqliteInjector::supported_strategies")
    }
}
