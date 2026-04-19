//! Schema check — validate target database schemas before injection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Expected schema column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedColumn {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub primary_key: bool,
}

/// Expected schema for a table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedSchema {
    pub table: String,
    pub columns: Vec<ExpectedColumn>,
    pub min_version: Option<u32>,
    pub max_version: Option<u32>,
}

/// Result of a schema validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaCheckResult {
    pub table: String,
    pub valid: bool,
    pub missing_columns: Vec<String>,
    pub type_mismatches: Vec<(String, String, String)>, // col, expected, actual
    pub extra_columns: Vec<String>,
    pub version_ok: bool,
    pub checked_at: DateTime<Utc>,
}

impl SchemaCheckResult {
    pub fn is_clean(&self) -> bool {
        self.valid
            && self.missing_columns.is_empty()
            && self.type_mismatches.is_empty()
            && self.version_ok
    }

    pub fn has_breaking_changes(&self) -> bool {
        !self.missing_columns.is_empty() || !self.type_mismatches.is_empty()
    }
}

/// Actual column observed in the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActualColumn {
    pub name: String,
    pub data_type: String,
}

/// Schema checker.
pub struct SchemaChecker {
    expected: HashMap<String, ExpectedSchema>,
    history: Vec<SchemaCheckResult>,
}

impl SchemaChecker {
    pub fn new() -> Self {
        Self {
            expected: HashMap::new(),
            history: Vec::new(),
        }
    }

    /// Register an expected schema.
    pub fn register(&mut self, schema: ExpectedSchema) {
        self.expected.insert(schema.table.clone(), schema);
    }

    /// Check an actual table schema against the expected schema.
    pub fn check(
        &mut self,
        table: &str,
        actual: &[ActualColumn],
        actual_version: Option<u32>,
    ) -> SchemaCheckResult {
        let expected = match self.expected.get(table) {
            Some(s) => s,
            None => {
                let result = SchemaCheckResult {
                    table: table.into(),
                    valid: false,
                    missing_columns: Vec::new(),
                    type_mismatches: Vec::new(),
                    extra_columns: actual.iter().map(|c| c.name.clone()).collect(),
                    version_ok: true,
                    checked_at: Utc::now(),
                };
                self.history.push(result.clone());
                return result;
            }
        };

        let mut missing = Vec::new();
        let mut mismatches = Vec::new();

        for expected_col in &expected.columns {
            match actual.iter().find(|c| c.name == expected_col.name) {
                None => missing.push(expected_col.name.clone()),
                Some(actual_col) => {
                    if actual_col.data_type.to_lowercase() != expected_col.data_type.to_lowercase()
                    {
                        mismatches.push((
                            expected_col.name.clone(),
                            expected_col.data_type.clone(),
                            actual_col.data_type.clone(),
                        ));
                    }
                }
            }
        }

        let expected_names: std::collections::HashSet<&String> =
            expected.columns.iter().map(|c| &c.name).collect();
        let extra: Vec<String> = actual
            .iter()
            .filter(|c| !expected_names.contains(&c.name))
            .map(|c| c.name.clone())
            .collect();

        let version_ok = match (actual_version, expected.min_version, expected.max_version) {
            (Some(v), Some(min), Some(max)) => v >= min && v <= max,
            (Some(v), Some(min), None) => v >= min,
            (Some(v), None, Some(max)) => v <= max,
            _ => true,
        };

        let valid = missing.is_empty() && mismatches.is_empty() && version_ok;

        let result = SchemaCheckResult {
            table: table.into(),
            valid,
            missing_columns: missing,
            type_mismatches: mismatches,
            extra_columns: extra,
            version_ok,
            checked_at: Utc::now(),
        };
        self.history.push(result.clone());
        result
    }

    /// History of all checks performed.
    pub fn history(&self) -> &[SchemaCheckResult] {
        &self.history
    }

    /// Count of tables with breaking changes.
    pub fn breaking_tables(&self) -> usize {
        self.history
            .iter()
            .filter(|r| r.has_breaking_changes())
            .count()
    }

    /// Registered expected schemas.
    pub fn registered(&self) -> Vec<&String> {
        self.expected.keys().collect()
    }
}

impl Default for SchemaChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(name: &str, ty: &str) -> ExpectedColumn {
        ExpectedColumn {
            name: name.into(),
            data_type: ty.into(),
            nullable: true,
            primary_key: false,
        }
    }

    fn actual(name: &str, ty: &str) -> ActualColumn {
        ActualColumn {
            name: name.into(),
            data_type: ty.into(),
        }
    }

    fn expected_schema() -> ExpectedSchema {
        ExpectedSchema {
            table: "moz_places".into(),
            columns: vec![
                col("id", "INTEGER"),
                col("url", "TEXT"),
                col("title", "TEXT"),
                col("visit_count", "INTEGER"),
            ],
            min_version: Some(30),
            max_version: Some(60),
        }
    }

    #[test]
    fn test_clean_schema() {
        let mut c = SchemaChecker::new();
        c.register(expected_schema());
        let actual_cols = vec![
            actual("id", "INTEGER"),
            actual("url", "TEXT"),
            actual("title", "TEXT"),
            actual("visit_count", "INTEGER"),
        ];
        let result = c.check("moz_places", &actual_cols, Some(45));
        assert!(result.is_clean());
    }

    #[test]
    fn test_missing_column() {
        let mut c = SchemaChecker::new();
        c.register(expected_schema());
        let actual_cols = vec![actual("id", "INTEGER"), actual("url", "TEXT")];
        let result = c.check("moz_places", &actual_cols, Some(45));
        assert_eq!(result.missing_columns.len(), 2);
    }

    #[test]
    fn test_type_mismatch() {
        let mut c = SchemaChecker::new();
        c.register(expected_schema());
        let actual_cols = vec![
            actual("id", "TEXT"), // wrong type
            actual("url", "TEXT"),
            actual("title", "TEXT"),
            actual("visit_count", "INTEGER"),
        ];
        let result = c.check("moz_places", &actual_cols, Some(45));
        assert_eq!(result.type_mismatches.len(), 1);
    }

    #[test]
    fn test_extra_columns_allowed() {
        let mut c = SchemaChecker::new();
        c.register(expected_schema());
        let actual_cols = vec![
            actual("id", "INTEGER"),
            actual("url", "TEXT"),
            actual("title", "TEXT"),
            actual("visit_count", "INTEGER"),
            actual("new_future_col", "BLOB"),
        ];
        let result = c.check("moz_places", &actual_cols, Some(45));
        assert!(result.is_clean());
        assert_eq!(result.extra_columns.len(), 1);
    }

    #[test]
    fn test_version_below_min() {
        let mut c = SchemaChecker::new();
        c.register(expected_schema());
        let actual_cols = vec![
            actual("id", "INTEGER"),
            actual("url", "TEXT"),
            actual("title", "TEXT"),
            actual("visit_count", "INTEGER"),
        ];
        let result = c.check("moz_places", &actual_cols, Some(10));
        assert!(!result.version_ok);
    }

    #[test]
    fn test_unknown_table() {
        let mut c = SchemaChecker::new();
        let result = c.check("unknown", &[], None);
        assert!(!result.valid);
    }

    #[test]
    fn test_has_breaking_changes() {
        let mut c = SchemaChecker::new();
        c.register(expected_schema());
        let actual_cols = vec![actual("id", "INTEGER")];
        let result = c.check("moz_places", &actual_cols, Some(45));
        assert!(result.has_breaking_changes());
    }

    #[test]
    fn test_history_accumulates() {
        let mut c = SchemaChecker::new();
        c.register(expected_schema());
        c.check("moz_places", &[], Some(45));
        c.check("moz_places", &[], Some(45));
        assert_eq!(c.history().len(), 2);
    }

    #[test]
    fn test_case_insensitive_type_match() {
        let mut c = SchemaChecker::new();
        c.register(expected_schema());
        let actual_cols = vec![
            actual("id", "integer"),
            actual("url", "text"),
            actual("title", "text"),
            actual("visit_count", "integer"),
        ];
        let result = c.check("moz_places", &actual_cols, Some(45));
        assert!(result.is_clean());
    }
}
