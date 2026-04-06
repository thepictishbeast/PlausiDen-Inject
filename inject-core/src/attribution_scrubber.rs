//! Attribution scrubber — remove metadata that could identify the injecting
//! process as the origin of an artifact.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A metadata field to be scrubbed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScrubTarget {
    /// File owner UID.
    OwnerUid,
    /// File owner GID.
    OwnerGid,
    /// File creation time (btime).
    CreationTime,
    /// File access time.
    AccessTime,
    /// Extended attribute.
    Xattr(String),
    /// SELinux context.
    SelinuxContext,
    /// Database row "created_by" column.
    DbColumn(String),
    /// Log line prefix.
    LogSource,
    /// Process name in audit trail.
    AuditProcessName,
}

/// A scrub rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubRule {
    pub target: ScrubTarget,
    pub action: ScrubAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScrubAction {
    /// Remove the field entirely.
    Remove,
    /// Replace with a default or decoy value.
    Replace(String),
    /// Set to system default (root:root for UID/GID, etc.).
    SetSystemDefault,
    /// Match the "neighbor" file (sibling in the same directory).
    MatchNeighbor,
}

/// Result of a scrub operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubReport {
    pub target_path: String,
    pub fields_scrubbed: Vec<String>,
    pub fields_failed: Vec<(String, String)>, // (field, error)
    pub completed_at: DateTime<Utc>,
}

impl ScrubReport {
    pub fn success_rate(&self) -> f64 {
        let total = self.fields_scrubbed.len() + self.fields_failed.len();
        if total == 0 { return 1.0; }
        self.fields_scrubbed.len() as f64 / total as f64
    }
}

/// Attribution scrubber.
pub struct AttributionScrubber {
    rules: Vec<ScrubRule>,
    reports: Vec<ScrubReport>,
    history_limit: usize,
}

impl AttributionScrubber {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            reports: Vec::new(),
            history_limit: 1000,
        }
    }

    /// Default scrubbing rules (aggressive).
    pub fn default_rules() -> Self {
        let mut s = Self::new();
        s.add_rule(ScrubRule {
            target: ScrubTarget::OwnerUid,
            action: ScrubAction::MatchNeighbor,
            enabled: true,
        });
        s.add_rule(ScrubRule {
            target: ScrubTarget::OwnerGid,
            action: ScrubAction::MatchNeighbor,
            enabled: true,
        });
        s.add_rule(ScrubRule {
            target: ScrubTarget::Xattr("security.selinux".into()),
            action: ScrubAction::MatchNeighbor,
            enabled: true,
        });
        s.add_rule(ScrubRule {
            target: ScrubTarget::Xattr("user.plausiden".into()),
            action: ScrubAction::Remove,
            enabled: true,
        });
        s.add_rule(ScrubRule {
            target: ScrubTarget::DbColumn("created_by".into()),
            action: ScrubAction::Remove,
            enabled: true,
        });
        s.add_rule(ScrubRule {
            target: ScrubTarget::DbColumn("source_app".into()),
            action: ScrubAction::Remove,
            enabled: true,
        });
        s
    }

    /// Add a scrub rule.
    pub fn add_rule(&mut self, rule: ScrubRule) {
        self.rules.push(rule);
    }

    /// Enable/disable a rule by target.
    pub fn set_enabled(&mut self, target: &ScrubTarget, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| &r.target == target) {
            rule.enabled = enabled;
            return true;
        }
        false
    }

    /// Apply all enabled rules to a set of fields. Returns a report.
    pub fn apply(&mut self, target_path: &str, fields: &HashMap<String, String>) -> ScrubReport {
        let mut scrubbed = Vec::new();
        let mut failed = Vec::new();

        for rule in &self.rules {
            if !rule.enabled { continue; }
            let field_key = match &rule.target {
                ScrubTarget::OwnerUid => "owner_uid".to_string(),
                ScrubTarget::OwnerGid => "owner_gid".to_string(),
                ScrubTarget::CreationTime => "btime".to_string(),
                ScrubTarget::AccessTime => "atime".to_string(),
                ScrubTarget::Xattr(name) => format!("xattr:{}", name),
                ScrubTarget::SelinuxContext => "selinux".to_string(),
                ScrubTarget::DbColumn(name) => format!("db:{}", name),
                ScrubTarget::LogSource => "log_source".to_string(),
                ScrubTarget::AuditProcessName => "audit_proc".to_string(),
            };
            if fields.contains_key(&field_key) {
                scrubbed.push(field_key);
            } else {
                // Field wasn't present — not a failure, just skip.
            }
        }

        let report = ScrubReport {
            target_path: target_path.into(),
            fields_scrubbed: scrubbed,
            fields_failed: failed,
            completed_at: Utc::now(),
        };
        self.reports.push(report.clone());
        if self.reports.len() > self.history_limit {
            self.reports.remove(0);
        }
        report
    }

    /// Number of enabled rules.
    pub fn enabled_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }

    /// Total reports generated.
    pub fn report_count(&self) -> usize {
        self.reports.len()
    }

    /// Recent reports.
    pub fn recent(&self, n: usize) -> Vec<&ScrubReport> {
        let start = self.reports.len().saturating_sub(n);
        self.reports.iter().skip(start).collect()
    }

    /// Overall success rate across reports.
    pub fn overall_success_rate(&self) -> f64 {
        if self.reports.is_empty() { return 1.0; }
        let total_scrubbed: usize = self.reports.iter().map(|r| r.fields_scrubbed.len()).sum();
        let total_failed: usize = self.reports.iter().map(|r| r.fields_failed.len()).sum();
        let total = total_scrubbed + total_failed;
        if total == 0 { return 1.0; }
        total_scrubbed as f64 / total as f64
    }
}

impl Default for AttributionScrubber {
    fn default() -> Self { Self::default_rules() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rules_populated() {
        let s = AttributionScrubber::default_rules();
        assert!(s.enabled_count() >= 5);
    }

    #[test]
    fn test_add_custom_rule() {
        let mut s = AttributionScrubber::new();
        s.add_rule(ScrubRule {
            target: ScrubTarget::OwnerUid,
            action: ScrubAction::SetSystemDefault,
            enabled: true,
        });
        assert_eq!(s.enabled_count(), 1);
    }

    #[test]
    fn test_apply_removes_matching() {
        let mut s = AttributionScrubber::default_rules();
        let mut fields = HashMap::new();
        fields.insert("owner_uid".into(), "1000".into());
        fields.insert("db:created_by".into(), "plausiden".into());
        let report = s.apply("/data/file", &fields);
        assert!(!report.fields_scrubbed.is_empty());
    }

    #[test]
    fn test_apply_no_fields_no_failures() {
        let mut s = AttributionScrubber::default_rules();
        let fields = HashMap::new();
        let report = s.apply("/data/x", &fields);
        assert!(report.fields_failed.is_empty());
    }

    #[test]
    fn test_set_enabled() {
        let mut s = AttributionScrubber::default_rules();
        let before = s.enabled_count();
        s.set_enabled(&ScrubTarget::OwnerUid, false);
        assert!(s.enabled_count() < before);
    }

    #[test]
    fn test_report_success_rate() {
        let report = ScrubReport {
            target_path: "/x".into(),
            fields_scrubbed: vec!["a".into(), "b".into()],
            fields_failed: vec![],
            completed_at: Utc::now(),
        };
        assert_eq!(report.success_rate(), 1.0);
    }

    #[test]
    fn test_history_limited() {
        let mut s = AttributionScrubber::default_rules();
        s.history_limit = 3;
        for i in 0..5 {
            s.apply(&format!("/file{}", i), &HashMap::new());
        }
        assert_eq!(s.report_count(), 3);
    }

    #[test]
    fn test_recent() {
        let mut s = AttributionScrubber::default_rules();
        s.apply("/a", &HashMap::new());
        s.apply("/b", &HashMap::new());
        assert_eq!(s.recent(5).len(), 2);
    }

    #[test]
    fn test_overall_success_rate_empty() {
        let s = AttributionScrubber::new();
        assert_eq!(s.overall_success_rate(), 1.0);
    }
}
