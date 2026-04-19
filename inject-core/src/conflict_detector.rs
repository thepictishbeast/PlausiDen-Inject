//! Conflict detector — identify competing injection attempts on the same target.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A claim on an injection target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetClaim {
    pub claim_id: String,
    pub target_id: String,
    pub holder: String,
    pub kind: ClaimKind,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimKind {
    /// Exclusive write claim.
    ExclusiveWrite,
    /// Shared read claim.
    SharedRead,
    /// Advisory marker — other writes should defer.
    Advisory,
}

/// A conflict found between two claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub target_id: String,
    pub claim1_id: String,
    pub claim2_id: String,
    pub reason: ConflictReason,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictReason {
    ExclusiveVsExclusive,
    ExclusiveVsShared,
    OverlappingWrites,
}

impl TargetClaim {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// Conflict detector.
pub struct ConflictDetector {
    claims: HashMap<String, TargetClaim>,
    conflicts: Vec<Conflict>,
    history_limit: usize,
}

impl ConflictDetector {
    pub fn new() -> Self {
        Self {
            claims: HashMap::new(),
            conflicts: Vec::new(),
            history_limit: 1000,
        }
    }

    /// Attempt to acquire a claim. Returns conflicts if denied.
    pub fn acquire(&mut self, claim: TargetClaim) -> Result<(), Vec<Conflict>> {
        let mut conflicts = Vec::new();
        let now = Utc::now();

        // Check active claims on the same target.
        for existing in self.claims.values() {
            if existing.is_expired() {
                continue;
            }
            if existing.target_id != claim.target_id {
                continue;
            }

            let conflicting = match (&existing.kind, &claim.kind) {
                (ClaimKind::ExclusiveWrite, ClaimKind::ExclusiveWrite) => {
                    Some(ConflictReason::ExclusiveVsExclusive)
                }
                (ClaimKind::ExclusiveWrite, _) | (_, ClaimKind::ExclusiveWrite) => {
                    Some(ConflictReason::ExclusiveVsShared)
                }
                (ClaimKind::Advisory, ClaimKind::Advisory) => None,
                (ClaimKind::SharedRead, ClaimKind::SharedRead) => None,
                _ => None,
            };

            if let Some(reason) = conflicting {
                conflicts.push(Conflict {
                    target_id: claim.target_id.clone(),
                    claim1_id: existing.claim_id.clone(),
                    claim2_id: claim.claim_id.clone(),
                    reason,
                    detected_at: now,
                });
            }
        }

        if !conflicts.is_empty() {
            self.conflicts.extend(conflicts.clone());
            self.trim_history();
            return Err(conflicts);
        }

        self.claims.insert(claim.claim_id.clone(), claim);
        Ok(())
    }

    /// Release a claim.
    pub fn release(&mut self, claim_id: &str) -> bool {
        self.claims.remove(claim_id).is_some()
    }

    /// Sweep expired claims.
    pub fn sweep_expired(&mut self) -> usize {
        let expired: Vec<String> = self
            .claims
            .iter()
            .filter(|(_, c)| c.is_expired())
            .map(|(id, _)| id.clone())
            .collect();
        let count = expired.len();
        for id in expired {
            self.claims.remove(&id);
        }
        count
    }

    /// Active claims on a target.
    pub fn active_claims_on(&self, target_id: &str) -> Vec<&TargetClaim> {
        self.claims
            .values()
            .filter(|c| c.target_id == target_id && !c.is_expired())
            .collect()
    }

    /// Claims held by a specific holder.
    pub fn held_by(&self, holder: &str) -> Vec<&TargetClaim> {
        self.claims
            .values()
            .filter(|c| c.holder == holder)
            .collect()
    }

    /// Conflicts for a target.
    pub fn conflicts_on(&self, target_id: &str) -> Vec<&Conflict> {
        self.conflicts
            .iter()
            .filter(|c| c.target_id == target_id)
            .collect()
    }

    fn trim_history(&mut self) {
        if self.conflicts.len() > self.history_limit {
            let excess = self.conflicts.len() - self.history_limit;
            self.conflicts.drain(0..excess);
        }
    }

    pub fn active_count(&self) -> usize {
        self.claims.values().filter(|c| !c.is_expired()).count()
    }

    pub fn conflict_count(&self) -> usize {
        self.conflicts.len()
    }
}

impl Default for ConflictDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(id: &str, target: &str, holder: &str, kind: ClaimKind) -> TargetClaim {
        TargetClaim {
            claim_id: id.into(),
            target_id: target.into(),
            holder: holder.into(),
            kind,
            acquired_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
        }
    }

    #[test]
    fn test_acquire_first_claim_ok() {
        let mut d = ConflictDetector::new();
        assert!(
            d.acquire(claim("c1", "firefox", "h1", ClaimKind::ExclusiveWrite))
                .is_ok()
        );
    }

    #[test]
    fn test_exclusive_vs_exclusive_conflicts() {
        let mut d = ConflictDetector::new();
        d.acquire(claim("c1", "firefox", "h1", ClaimKind::ExclusiveWrite))
            .unwrap();
        let result = d.acquire(claim("c2", "firefox", "h2", ClaimKind::ExclusiveWrite));
        assert!(result.is_err());
    }

    #[test]
    fn test_exclusive_vs_shared_conflicts() {
        let mut d = ConflictDetector::new();
        d.acquire(claim("c1", "firefox", "h1", ClaimKind::ExclusiveWrite))
            .unwrap();
        let result = d.acquire(claim("c2", "firefox", "h2", ClaimKind::SharedRead));
        assert!(result.is_err());
    }

    #[test]
    fn test_shared_vs_shared_ok() {
        let mut d = ConflictDetector::new();
        d.acquire(claim("c1", "firefox", "h1", ClaimKind::SharedRead))
            .unwrap();
        assert!(
            d.acquire(claim("c2", "firefox", "h2", ClaimKind::SharedRead))
                .is_ok()
        );
    }

    #[test]
    fn test_different_targets_ok() {
        let mut d = ConflictDetector::new();
        d.acquire(claim("c1", "firefox", "h1", ClaimKind::ExclusiveWrite))
            .unwrap();
        assert!(
            d.acquire(claim("c2", "chrome", "h1", ClaimKind::ExclusiveWrite))
                .is_ok()
        );
    }

    #[test]
    fn test_release() {
        let mut d = ConflictDetector::new();
        d.acquire(claim("c1", "firefox", "h1", ClaimKind::ExclusiveWrite))
            .unwrap();
        d.release("c1");
        assert!(
            d.acquire(claim("c2", "firefox", "h2", ClaimKind::ExclusiveWrite))
                .is_ok()
        );
    }

    #[test]
    fn test_sweep_expired() {
        let mut d = ConflictDetector::new();
        let mut c = claim("c1", "firefox", "h1", ClaimKind::ExclusiveWrite);
        c.expires_at = Utc::now() - chrono::Duration::seconds(1);
        d.claims.insert(c.claim_id.clone(), c);
        assert_eq!(d.sweep_expired(), 1);
    }

    #[test]
    fn test_active_claims_on() {
        let mut d = ConflictDetector::new();
        d.acquire(claim("c1", "firefox", "h1", ClaimKind::SharedRead))
            .unwrap();
        d.acquire(claim("c2", "firefox", "h2", ClaimKind::SharedRead))
            .unwrap();
        assert_eq!(d.active_claims_on("firefox").len(), 2);
    }

    #[test]
    fn test_held_by() {
        let mut d = ConflictDetector::new();
        d.acquire(claim("c1", "firefox", "h1", ClaimKind::ExclusiveWrite))
            .unwrap();
        d.acquire(claim("c2", "chrome", "h1", ClaimKind::ExclusiveWrite))
            .unwrap();
        assert_eq!(d.held_by("h1").len(), 2);
    }
}
