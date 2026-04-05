//! Windows Event Log (.evtx) injection.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct EventLogInjector;

impl Injector for EventLogInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("EventLogInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("EventLogInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("EventLogInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("EventLogInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("EventLogInjector::supported_strategies")
    }
}
