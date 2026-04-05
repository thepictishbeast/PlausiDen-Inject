//! macOS filesystem artifact injection (APFS metadata, xattrs, timestamps).

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

pub struct MacosFilesystemInjector;

impl Injector for MacosFilesystemInjector {
    fn inject(&self, _artifact_bytes: &[u8], _target: &Target, _strategy: InjectionStrategy) -> Result<InjectionResult> {
        todo!("MacosFilesystemInjector::inject")
    }
    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("MacosFilesystemInjector::verify")
    }
    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("MacosFilesystemInjector::rollback")
    }
    fn available_targets(&self) -> Vec<Target> {
        todo!("MacosFilesystemInjector::available_targets")
    }
    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("MacosFilesystemInjector::supported_strategies")
    }
}
