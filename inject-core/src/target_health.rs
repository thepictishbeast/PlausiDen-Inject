//! Target health checker — verify injection targets are ready before writing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Health status of an injection target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Ready,
    Locked,
    Missing,
    Readonly,
    CorruptedSchema,
    InUse,
    UnsupportedVersion,
    UnknownError,
}

/// Health check report for a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub target_id: String,
    pub path: PathBuf,
    pub status: HealthStatus,
    pub checked_at: DateTime<Utc>,
    pub last_ready: Option<DateTime<Utc>>,
    pub consecutive_failures: u32,
    pub detail: Option<String>,
}

impl HealthReport {
    pub fn is_ready(&self) -> bool {
        self.status == HealthStatus::Ready
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self.status, HealthStatus::Locked | HealthStatus::InUse)
    }

    pub fn is_permanent_failure(&self) -> bool {
        matches!(
            self.status,
            HealthStatus::Missing
                | HealthStatus::Readonly
                | HealthStatus::CorruptedSchema
                | HealthStatus::UnsupportedVersion
        )
    }
}

/// Target health checker.
pub struct TargetHealthChecker {
    reports: HashMap<String, HealthReport>,
}

impl TargetHealthChecker {
    pub fn new() -> Self {
        Self {
            reports: HashMap::new(),
        }
    }

    /// Record the outcome of a health check.
    pub fn record(
        &mut self,
        target_id: &str,
        path: PathBuf,
        status: HealthStatus,
        detail: Option<String>,
    ) {
        let now = Utc::now();
        let existing = self.reports.get(target_id).cloned();
        let (last_ready, consecutive_failures) = match &existing {
            Some(prev) => {
                let failures = if status == HealthStatus::Ready {
                    0
                } else {
                    prev.consecutive_failures + 1
                };
                let last_ready = if status == HealthStatus::Ready {
                    Some(now)
                } else {
                    prev.last_ready
                };
                (last_ready, failures)
            }
            None => {
                let last_ready = if status == HealthStatus::Ready {
                    Some(now)
                } else {
                    None
                };
                (
                    last_ready,
                    if status == HealthStatus::Ready { 0 } else { 1 },
                )
            }
        };

        self.reports.insert(
            target_id.into(),
            HealthReport {
                target_id: target_id.into(),
                path,
                status,
                checked_at: now,
                last_ready,
                consecutive_failures,
                detail,
            },
        );
    }

    /// Get health report for a specific target.
    pub fn get(&self, target_id: &str) -> Option<&HealthReport> {
        self.reports.get(target_id)
    }

    /// All ready targets.
    pub fn ready(&self) -> Vec<&HealthReport> {
        self.reports.values().filter(|r| r.is_ready()).collect()
    }

    /// All unhealthy targets.
    pub fn unhealthy(&self) -> Vec<&HealthReport> {
        self.reports.values().filter(|r| !r.is_ready()).collect()
    }

    /// Targets that are retryable (temporary failure).
    pub fn retryable(&self) -> Vec<&HealthReport> {
        self.reports.values().filter(|r| r.is_retryable()).collect()
    }

    /// Targets with permanent failures.
    pub fn permanent_failures(&self) -> Vec<&HealthReport> {
        self.reports
            .values()
            .filter(|r| r.is_permanent_failure())
            .collect()
    }

    /// Targets with N or more consecutive failures.
    pub fn chronic_failures(&self, min_failures: u32) -> Vec<&HealthReport> {
        self.reports
            .values()
            .filter(|r| r.consecutive_failures >= min_failures)
            .collect()
    }

    /// Status distribution.
    pub fn status_counts(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for r in self.reports.values() {
            *map.entry(format!("{:?}", r.status)).or_insert(0) += 1;
        }
        map
    }

    pub fn target_count(&self) -> usize {
        self.reports.len()
    }
}

impl Default for TargetHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_ready() {
        let mut c = TargetHealthChecker::new();
        c.record(
            "firefox",
            "/home/user/.mozilla/firefox/profile/places.sqlite".into(),
            HealthStatus::Ready,
            None,
        );
        let r = c.get("firefox").unwrap();
        assert!(r.is_ready());
        assert!(r.last_ready.is_some());
    }

    #[test]
    fn test_consecutive_failures() {
        let mut c = TargetHealthChecker::new();
        c.record("firefox", PathBuf::from("/x"), HealthStatus::Locked, None);
        c.record("firefox", PathBuf::from("/x"), HealthStatus::Locked, None);
        c.record("firefox", PathBuf::from("/x"), HealthStatus::Locked, None);
        let r = c.get("firefox").unwrap();
        assert_eq!(r.consecutive_failures, 3);
    }

    #[test]
    fn test_failure_reset_on_success() {
        let mut c = TargetHealthChecker::new();
        c.record("firefox", PathBuf::from("/x"), HealthStatus::Locked, None);
        c.record("firefox", PathBuf::from("/x"), HealthStatus::Ready, None);
        let r = c.get("firefox").unwrap();
        assert_eq!(r.consecutive_failures, 0);
    }

    #[test]
    fn test_is_retryable() {
        let r = HealthReport {
            target_id: "t".into(),
            path: "/x".into(),
            status: HealthStatus::Locked,
            checked_at: Utc::now(),
            last_ready: None,
            consecutive_failures: 1,
            detail: None,
        };
        assert!(r.is_retryable());
    }

    #[test]
    fn test_is_permanent_failure() {
        let r = HealthReport {
            target_id: "t".into(),
            path: "/x".into(),
            status: HealthStatus::Missing,
            checked_at: Utc::now(),
            last_ready: None,
            consecutive_failures: 1,
            detail: None,
        };
        assert!(r.is_permanent_failure());
    }

    #[test]
    fn test_ready_filter() {
        let mut c = TargetHealthChecker::new();
        c.record("a", PathBuf::from("/a"), HealthStatus::Ready, None);
        c.record("b", PathBuf::from("/b"), HealthStatus::Locked, None);
        assert_eq!(c.ready().len(), 1);
        assert_eq!(c.unhealthy().len(), 1);
    }

    #[test]
    fn test_chronic_failures() {
        let mut c = TargetHealthChecker::new();
        for _ in 0..5 {
            c.record("a", PathBuf::from("/a"), HealthStatus::Locked, None);
        }
        c.record("b", PathBuf::from("/b"), HealthStatus::Locked, None);
        let chronic = c.chronic_failures(3);
        assert_eq!(chronic.len(), 1);
        assert_eq!(chronic[0].target_id, "a");
    }

    #[test]
    fn test_status_counts() {
        let mut c = TargetHealthChecker::new();
        c.record("a", PathBuf::from("/a"), HealthStatus::Ready, None);
        c.record("b", PathBuf::from("/b"), HealthStatus::Ready, None);
        c.record("c", PathBuf::from("/c"), HealthStatus::Locked, None);
        let counts = c.status_counts();
        assert_eq!(*counts.get("Ready").unwrap(), 2);
        assert_eq!(*counts.get("Locked").unwrap(), 1);
    }

    #[test]
    fn test_permanent_failures_list() {
        let mut c = TargetHealthChecker::new();
        c.record("a", PathBuf::from("/a"), HealthStatus::Missing, None);
        c.record("b", PathBuf::from("/b"), HealthStatus::Locked, None);
        assert_eq!(c.permanent_failures().len(), 1);
        assert_eq!(c.retryable().len(), 1);
    }
}
