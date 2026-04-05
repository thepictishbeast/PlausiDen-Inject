//! Input-event injection via `/dev/uinput` or `evdev`.
//!
//! Replays mouse movements, keystrokes, and touch events to make
//! browser-history injections consistent with input telemetry.

use inject_core::{
    InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus,
};
use inject_core::error::Result;

/// Linux input-event injector.
pub struct InputInjector;

impl Injector for InputInjector {
    fn inject(
        &self,
        _artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        todo!("InputInjector::inject")
    }

    fn verify(&self, _result: &InjectionResult) -> Result<VerificationStatus> {
        todo!("InputInjector::verify")
    }

    fn rollback(&self, _result: &InjectionResult) -> Result<()> {
        todo!("InputInjector::rollback")
    }

    fn available_targets(&self) -> Vec<Target> {
        todo!("InputInjector::available_targets")
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        todo!("InputInjector::supported_strategies")
    }
}
