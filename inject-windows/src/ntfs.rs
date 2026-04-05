//! NTFS metadata injection ($MFT, $UsnJrnl, $LogFile).

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct NtfsInjector;

impl Injector for NtfsInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("NtfsInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("NtfsInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("NtfsInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("NtfsInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("NtfsInjector::supported_strategies")
    }
}
