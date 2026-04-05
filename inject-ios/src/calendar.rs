//! iOS Calendar injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct CalendarInjector;

impl Injector for CalendarInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("CalendarInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("CalendarInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("CalendarInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("CalendarInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("CalendarInjector::supported_strategies")
    }
}
