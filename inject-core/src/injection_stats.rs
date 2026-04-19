//! Injection statistics — aggregate metrics across injection runs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single injection attempt record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionRecord {
    pub target: String,
    pub strategy: String,
    pub artifact_count: u32,
    pub bytes_written: u64,
    pub duration_ms: u64,
    pub success: bool,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Aggregate injection statistics.
pub struct InjectionStats {
    records: Vec<InjectionRecord>,
    history_limit: usize,
}

impl InjectionStats {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            history_limit: 10_000,
        }
    }

    pub fn with_limit(limit: usize) -> Self {
        Self {
            records: Vec::new(),
            history_limit: limit,
        }
    }

    /// Record a new injection attempt.
    pub fn record(&mut self, record: InjectionRecord) {
        self.records.push(record);
        if self.records.len() > self.history_limit {
            self.records.remove(0);
        }
    }

    /// Total injection attempts.
    pub fn total_attempts(&self) -> usize {
        self.records.len()
    }

    /// Successful injections.
    pub fn successful(&self) -> usize {
        self.records.iter().filter(|r| r.success).count()
    }

    /// Failed injections.
    pub fn failed(&self) -> usize {
        self.records.iter().filter(|r| !r.success).count()
    }

    /// Overall success rate.
    pub fn success_rate(&self) -> f64 {
        if self.records.is_empty() {
            return 1.0;
        }
        self.successful() as f64 / self.records.len() as f64
    }

    /// Total artifacts injected across all runs.
    pub fn total_artifacts(&self) -> u64 {
        self.records
            .iter()
            .filter(|r| r.success)
            .map(|r| r.artifact_count as u64)
            .sum()
    }

    /// Total bytes written across all runs.
    pub fn total_bytes(&self) -> u64 {
        self.records
            .iter()
            .filter(|r| r.success)
            .map(|r| r.bytes_written)
            .sum()
    }

    /// Average duration in milliseconds for successful runs.
    pub fn avg_duration_ms(&self) -> Option<f64> {
        let durations: Vec<u64> = self
            .records
            .iter()
            .filter(|r| r.success)
            .map(|r| r.duration_ms)
            .collect();
        if durations.is_empty() {
            None
        } else {
            Some(durations.iter().sum::<u64>() as f64 / durations.len() as f64)
        }
    }

    /// Per-target success counts.
    pub fn by_target(&self) -> HashMap<String, (usize, usize)> {
        let mut map: HashMap<String, (usize, usize)> = HashMap::new();
        for r in &self.records {
            let entry = map.entry(r.target.clone()).or_insert((0, 0));
            if r.success {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
        map
    }

    /// Per-strategy success counts.
    pub fn by_strategy(&self) -> HashMap<String, (usize, usize)> {
        let mut map: HashMap<String, (usize, usize)> = HashMap::new();
        for r in &self.records {
            let entry = map.entry(r.strategy.clone()).or_insert((0, 0));
            if r.success {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
        map
    }

    /// Targets with at least one failure.
    pub fn problem_targets(&self) -> Vec<String> {
        let mut problem = std::collections::HashSet::new();
        for r in &self.records {
            if !r.success {
                problem.insert(r.target.clone());
            }
        }
        let mut out: Vec<String> = problem.into_iter().collect();
        out.sort();
        out
    }

    /// Most common error message.
    pub fn top_errors(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for r in &self.records {
            if let Some(err) = &r.error {
                *counts.entry(err.clone()).or_insert(0) += 1;
            }
        }
        let mut ranked: Vec<_> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        ranked.truncate(n);
        ranked
    }

    /// Recent records (last N).
    pub fn recent(&self, n: usize) -> Vec<&InjectionRecord> {
        let start = self.records.len().saturating_sub(n);
        self.records.iter().skip(start).collect()
    }
}

impl Default for InjectionStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(target: &str, strategy: &str, success: bool, error: Option<&str>) -> InjectionRecord {
        InjectionRecord {
            target: target.into(),
            strategy: strategy.into(),
            artifact_count: 10,
            bytes_written: 1024,
            duration_ms: 50,
            success,
            error: error.map(|s| s.into()),
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_record_and_count() {
        let mut s = InjectionStats::new();
        s.record(mk("firefox", "direct", true, None));
        s.record(mk("chrome", "direct", false, Some("locked")));
        assert_eq!(s.total_attempts(), 2);
        assert_eq!(s.successful(), 1);
        assert_eq!(s.failed(), 1);
    }

    #[test]
    fn test_success_rate() {
        let mut s = InjectionStats::new();
        for _ in 0..3 {
            s.record(mk("a", "d", true, None));
        }
        s.record(mk("a", "d", false, Some("e")));
        assert_eq!(s.success_rate(), 0.75);
    }

    #[test]
    fn test_by_target() {
        let mut s = InjectionStats::new();
        s.record(mk("firefox", "d", true, None));
        s.record(mk("firefox", "d", true, None));
        s.record(mk("chrome", "d", false, Some("e")));
        let by = s.by_target();
        assert_eq!(by.get("firefox"), Some(&(2, 0)));
        assert_eq!(by.get("chrome"), Some(&(0, 1)));
    }

    #[test]
    fn test_by_strategy() {
        let mut s = InjectionStats::new();
        s.record(mk("t", "direct", true, None));
        s.record(mk("t", "translator", true, None));
        s.record(mk("t", "direct", false, Some("e")));
        let by = s.by_strategy();
        assert_eq!(by.get("direct"), Some(&(1, 1)));
    }

    #[test]
    fn test_problem_targets() {
        let mut s = InjectionStats::new();
        s.record(mk("firefox", "d", true, None));
        s.record(mk("chrome", "d", false, Some("e")));
        s.record(mk("edge", "d", false, Some("e")));
        let problems = s.problem_targets();
        assert_eq!(problems.len(), 2);
        assert!(problems.contains(&"chrome".to_string()));
    }

    #[test]
    fn test_top_errors() {
        let mut s = InjectionStats::new();
        for _ in 0..5 {
            s.record(mk("t", "d", false, Some("database locked")));
        }
        for _ in 0..2 {
            s.record(mk("t", "d", false, Some("permission denied")));
        }
        let top = s.top_errors(5);
        assert_eq!(top[0], ("database locked".to_string(), 5));
    }

    #[test]
    fn test_total_artifacts() {
        let mut s = InjectionStats::new();
        s.record(mk("t", "d", true, None));
        s.record(mk("t", "d", true, None));
        s.record(mk("t", "d", false, Some("e"))); // failures don't count
        assert_eq!(s.total_artifacts(), 20);
    }

    #[test]
    fn test_avg_duration() {
        let mut s = InjectionStats::new();
        s.record(mk("t", "d", true, None)); // 50ms
        s.record(mk("t", "d", true, None));
        assert_eq!(s.avg_duration_ms(), Some(50.0));
    }

    #[test]
    fn test_recent() {
        let mut s = InjectionStats::new();
        for i in 0..5 {
            s.record(mk(&format!("t{}", i), "d", true, None));
        }
        let recent = s.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].target, "t3");
    }

    #[test]
    fn test_history_limit() {
        let mut s = InjectionStats::with_limit(3);
        for i in 0..5 {
            s.record(mk(&format!("t{}", i), "d", true, None));
        }
        assert_eq!(s.total_attempts(), 3);
    }
}
