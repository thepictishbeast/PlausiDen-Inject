//! Transaction manager — group related injection operations atomically.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A transaction of injection operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionTransaction {
    pub id: String,
    pub target_id: String,
    pub operations: Vec<TxOperation>,
    pub state: TxState,
    pub started_at: DateTime<Utc>,
    pub committed_at: Option<DateTime<Utc>>,
    pub aborted_at: Option<DateTime<Utc>>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOperation {
    pub index: usize,
    pub description: String,
    pub status: OpStatus,
    pub executed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpStatus {
    Pending,
    Executing,
    Success,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxState {
    Open,
    Committed,
    Aborted,
    PartiallyCommitted,
}

impl InjectionTransaction {
    /// Counts of operations by status.
    pub fn op_counts(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for op in &self.operations {
            *map.entry(format!("{:?}", op.status)).or_insert(0) += 1;
        }
        map
    }

    pub fn total_ops(&self) -> usize {
        self.operations.len()
    }

    pub fn successful_ops(&self) -> usize {
        self.operations
            .iter()
            .filter(|o| o.status == OpStatus::Success)
            .count()
    }

    pub fn failed_ops(&self) -> usize {
        self.operations
            .iter()
            .filter(|o| o.status == OpStatus::Failed)
            .count()
    }
}

/// Transaction manager.
pub struct TransactionManager {
    transactions: HashMap<String, InjectionTransaction>,
    history_limit: usize,
}

impl TransactionManager {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            history_limit: 1000,
        }
    }

    /// Begin a new transaction. Prunes the oldest closed transactions
    /// (committed/aborted/partially-committed) when total exceeds
    /// `history_limit`. Open transactions are never pruned.
    pub fn begin(&mut self, id: &str, target_id: &str, labels: Vec<String>) -> bool {
        if self.transactions.contains_key(id) {
            return false;
        }
        self.prune_closed();
        self.transactions.insert(
            id.into(),
            InjectionTransaction {
                id: id.into(),
                target_id: target_id.into(),
                operations: Vec::new(),
                state: TxState::Open,
                started_at: Utc::now(),
                committed_at: None,
                aborted_at: None,
                labels,
            },
        );
        true
    }

    /// Add a pending operation to a transaction.
    pub fn add_operation(&mut self, tx_id: &str, description: &str) -> Option<usize> {
        let tx = self.transactions.get_mut(tx_id)?;
        if tx.state != TxState::Open {
            return None;
        }
        let index = tx.operations.len();
        tx.operations.push(TxOperation {
            index,
            description: description.into(),
            status: OpStatus::Pending,
            executed_at: None,
            error: None,
        });
        Some(index)
    }

    /// Mark an operation as succeeded.
    pub fn mark_success(&mut self, tx_id: &str, op_index: usize) -> bool {
        if let Some(tx) = self.transactions.get_mut(tx_id) {
            if let Some(op) = tx.operations.get_mut(op_index) {
                op.status = OpStatus::Success;
                op.executed_at = Some(Utc::now());
                return true;
            }
        }
        false
    }

    /// Mark an operation as failed.
    pub fn mark_failed(&mut self, tx_id: &str, op_index: usize, error: &str) -> bool {
        if let Some(tx) = self.transactions.get_mut(tx_id) {
            if let Some(op) = tx.operations.get_mut(op_index) {
                op.status = OpStatus::Failed;
                op.executed_at = Some(Utc::now());
                op.error = Some(error.into());
                return true;
            }
        }
        false
    }

    /// Commit a transaction (all-or-nothing).
    pub fn commit(&mut self, tx_id: &str) -> Result<(), String> {
        if let Some(tx) = self.transactions.get_mut(tx_id) {
            if tx.state != TxState::Open {
                return Err("transaction not open".into());
            }
            let failed = tx
                .operations
                .iter()
                .filter(|o| o.status == OpStatus::Failed)
                .count();
            if failed > 0 {
                tx.state = TxState::PartiallyCommitted;
                return Err(format!("{} operations failed", failed));
            }
            tx.state = TxState::Committed;
            tx.committed_at = Some(Utc::now());
            Ok(())
        } else {
            Err("transaction not found".into())
        }
    }

    /// Abort a transaction.
    pub fn abort(&mut self, tx_id: &str) -> bool {
        if let Some(tx) = self.transactions.get_mut(tx_id) {
            tx.state = TxState::Aborted;
            tx.aborted_at = Some(Utc::now());
            return true;
        }
        false
    }

    pub fn get(&self, tx_id: &str) -> Option<&InjectionTransaction> {
        self.transactions.get(tx_id)
    }

    /// All open transactions.
    pub fn open(&self) -> Vec<&InjectionTransaction> {
        self.transactions
            .values()
            .filter(|t| t.state == TxState::Open)
            .collect()
    }

    /// All committed transactions.
    pub fn committed(&self) -> Vec<&InjectionTransaction> {
        self.transactions
            .values()
            .filter(|t| t.state == TxState::Committed)
            .collect()
    }

    /// Partially committed transactions (need rollback).
    pub fn partially_committed(&self) -> Vec<&InjectionTransaction> {
        self.transactions
            .values()
            .filter(|t| t.state == TxState::PartiallyCommitted)
            .collect()
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// REGRESSION-GUARD: closed-transaction accumulation. Without this,
    /// a long-running process leaks one entry per begin(). Open
    /// transactions are sacred — never pruned.
    fn prune_closed(&mut self) {
        if self.transactions.len() < self.history_limit {
            return;
        }
        let mut closed: Vec<(String, chrono::DateTime<Utc>)> = self
            .transactions
            .iter()
            .filter(|(_, t)| t.state != TxState::Open)
            .map(|(id, t)| {
                let stamp = t.committed_at.or(t.aborted_at).unwrap_or(t.started_at);
                (id.clone(), stamp)
            })
            .collect();
        closed.sort_by_key(|(_, stamp)| *stamp);
        let to_remove = self.transactions.len().saturating_sub(self.history_limit) + 1;
        for (id, _) in closed.into_iter().take(to_remove) {
            self.transactions.remove(&id);
        }
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_begin_transaction() {
        let mut m = TransactionManager::new();
        assert!(m.begin("tx1", "firefox", vec![]));
        assert_eq!(m.transaction_count(), 1);
    }

    #[test]
    fn test_duplicate_begin_fails() {
        let mut m = TransactionManager::new();
        m.begin("tx1", "firefox", vec![]);
        assert!(!m.begin("tx1", "firefox", vec![]));
    }

    #[test]
    fn test_add_operation() {
        let mut m = TransactionManager::new();
        m.begin("tx1", "firefox", vec![]);
        let idx = m.add_operation("tx1", "insert history").unwrap();
        assert_eq!(idx, 0);
    }

    #[test]
    fn test_commit_all_success() {
        let mut m = TransactionManager::new();
        m.begin("tx1", "firefox", vec![]);
        let idx = m.add_operation("tx1", "x").unwrap();
        m.mark_success("tx1", idx);
        assert!(m.commit("tx1").is_ok());
    }

    #[test]
    fn test_commit_with_failure() {
        let mut m = TransactionManager::new();
        m.begin("tx1", "firefox", vec![]);
        let idx = m.add_operation("tx1", "x").unwrap();
        m.mark_failed("tx1", idx, "db locked");
        let result = m.commit("tx1");
        assert!(result.is_err());
        assert_eq!(m.get("tx1").unwrap().state, TxState::PartiallyCommitted);
    }

    #[test]
    fn test_abort() {
        let mut m = TransactionManager::new();
        m.begin("tx1", "firefox", vec![]);
        assert!(m.abort("tx1"));
        assert_eq!(m.get("tx1").unwrap().state, TxState::Aborted);
    }

    #[test]
    fn test_cannot_add_to_closed() {
        let mut m = TransactionManager::new();
        m.begin("tx1", "firefox", vec![]);
        m.abort("tx1");
        assert!(m.add_operation("tx1", "x").is_none());
    }

    #[test]
    fn test_op_counts() {
        let mut m = TransactionManager::new();
        m.begin("tx1", "firefox", vec![]);
        let a = m.add_operation("tx1", "a").unwrap();
        let b = m.add_operation("tx1", "b").unwrap();
        m.mark_success("tx1", a);
        m.mark_failed("tx1", b, "err");
        let tx = m.get("tx1").unwrap();
        assert_eq!(tx.successful_ops(), 1);
        assert_eq!(tx.failed_ops(), 1);
        assert_eq!(tx.total_ops(), 2);
    }

    #[test]
    fn test_open_and_committed_lists() {
        let mut m = TransactionManager::new();
        m.begin("tx1", "a", vec![]);
        m.begin("tx2", "b", vec![]);
        let idx = m.add_operation("tx2", "x").unwrap();
        m.mark_success("tx2", idx);
        m.commit("tx2").unwrap();
        assert_eq!(m.open().len(), 1);
        assert_eq!(m.committed().len(), 1);
    }

    #[test]
    fn test_partially_committed_list() {
        let mut m = TransactionManager::new();
        m.begin("tx1", "firefox", vec![]);
        let idx = m.add_operation("tx1", "x").unwrap();
        m.mark_failed("tx1", idx, "err");
        let _ = m.commit("tx1");
        assert_eq!(m.partially_committed().len(), 1);
    }
}
