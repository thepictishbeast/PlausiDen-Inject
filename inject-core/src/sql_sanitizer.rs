//! SQL sanitizer — validate and escape values before they touch database
//! injection points. Defensive: we never want to corrupt target databases.

use serde::{Deserialize, Serialize};

/// A sanitization result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SanitizeResult {
    Safe(String),
    Quoted(String),
    Rejected(RejectReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    ContainsNullByte,
    ContainsControlChar,
    TooLong(usize),
    InvalidUtf8,
    LooksLikeInjection,
}

/// SQL sanitizer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerConfig {
    pub max_length: usize,
    pub allow_multiline: bool,
    pub reject_control_chars: bool,
    pub detect_injection_patterns: bool,
}

impl Default for SanitizerConfig {
    fn default() -> Self {
        Self {
            max_length: 4096,
            allow_multiline: false,
            reject_control_chars: true,
            detect_injection_patterns: true,
        }
    }
}

/// SQL sanitizer.
pub struct SqlSanitizer {
    config: SanitizerConfig,
    rejected_count: u64,
    sanitized_count: u64,
}

impl SqlSanitizer {
    pub fn new(config: SanitizerConfig) -> Self {
        Self { config, rejected_count: 0, sanitized_count: 0 }
    }

    /// Sanitize a value for safe insertion as a SQLite string literal.
    pub fn sanitize_string(&mut self, input: &str) -> SanitizeResult {
        if input.len() > self.config.max_length {
            self.rejected_count += 1;
            return SanitizeResult::Rejected(RejectReason::TooLong(input.len()));
        }

        if input.contains('\0') {
            self.rejected_count += 1;
            return SanitizeResult::Rejected(RejectReason::ContainsNullByte);
        }

        if self.config.reject_control_chars {
            for c in input.chars() {
                if c.is_control() && !(self.config.allow_multiline && (c == '\n' || c == '\r' || c == '\t')) {
                    self.rejected_count += 1;
                    return SanitizeResult::Rejected(RejectReason::ContainsControlChar);
                }
            }
        }

        if self.config.detect_injection_patterns && looks_like_injection(input) {
            self.rejected_count += 1;
            return SanitizeResult::Rejected(RejectReason::LooksLikeInjection);
        }

        self.sanitized_count += 1;
        // Escape single quotes by doubling (SQLite convention).
        let escaped = input.replace('\'', "''");
        SanitizeResult::Quoted(format!("'{}'", escaped))
    }

    /// Sanitize an integer value.
    pub fn sanitize_int(&mut self, input: &str) -> SanitizeResult {
        match input.parse::<i64>() {
            Ok(n) => {
                self.sanitized_count += 1;
                SanitizeResult::Safe(n.to_string())
            }
            Err(_) => {
                self.rejected_count += 1;
                SanitizeResult::Rejected(RejectReason::LooksLikeInjection)
            }
        }
    }

    /// Sanitize a floating-point value.
    pub fn sanitize_float(&mut self, input: &str) -> SanitizeResult {
        match input.parse::<f64>() {
            Ok(n) if n.is_finite() => {
                self.sanitized_count += 1;
                SanitizeResult::Safe(format!("{}", n))
            }
            _ => {
                self.rejected_count += 1;
                SanitizeResult::Rejected(RejectReason::LooksLikeInjection)
            }
        }
    }

    /// Validate a column or table name (identifier).
    pub fn validate_identifier(&mut self, input: &str) -> SanitizeResult {
        if input.is_empty() || input.len() > 64 {
            self.rejected_count += 1;
            return SanitizeResult::Rejected(RejectReason::TooLong(input.len()));
        }
        // Only [A-Za-z_][A-Za-z0-9_]*.
        let mut chars = input.chars();
        let first = chars.next().unwrap(); // SAFETY: input.is_empty() returned false on line 116, so at least one char exists
        if !(first.is_ascii_alphabetic() || first == '_') {
            self.rejected_count += 1;
            return SanitizeResult::Rejected(RejectReason::LooksLikeInjection);
        }
        for c in chars {
            if !(c.is_ascii_alphanumeric() || c == '_') {
                self.rejected_count += 1;
                return SanitizeResult::Rejected(RejectReason::LooksLikeInjection);
            }
        }
        self.sanitized_count += 1;
        SanitizeResult::Safe(input.into())
    }

    pub fn rejected_count(&self) -> u64 { self.rejected_count }
    pub fn sanitized_count(&self) -> u64 { self.sanitized_count }
}

impl Default for SqlSanitizer {
    fn default() -> Self { Self::new(SanitizerConfig::default()) }
}

fn looks_like_injection(s: &str) -> bool {
    let lower = s.to_lowercase();
    let patterns = [
        "' or '1'='1",
        "' or 1=1",
        "'; drop table",
        "/*",
        "*/",
        "xp_cmdshell",
        "union select",
        "-- ",
        "';drop",
    ];
    patterns.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_clean_string() {
        let mut s = SqlSanitizer::default();
        let result = s.sanitize_string("hello world");
        assert_eq!(result, SanitizeResult::Quoted("'hello world'".into()));
    }

    #[test]
    fn test_escape_single_quote() {
        let mut s = SqlSanitizer::default();
        let result = s.sanitize_string("it's working");
        assert_eq!(result, SanitizeResult::Quoted("'it''s working'".into()));
    }

    #[test]
    fn test_reject_null_byte() {
        let mut s = SqlSanitizer::default();
        let result = s.sanitize_string("hello\0world");
        assert!(matches!(result, SanitizeResult::Rejected(RejectReason::ContainsNullByte)));
    }

    #[test]
    fn test_reject_control_char() {
        let mut s = SqlSanitizer::default();
        let result = s.sanitize_string("hello\x01world");
        assert!(matches!(result, SanitizeResult::Rejected(RejectReason::ContainsControlChar)));
    }

    #[test]
    fn test_reject_too_long() {
        let mut s = SqlSanitizer::default();
        let result = s.sanitize_string(&"a".repeat(10_000));
        assert!(matches!(result, SanitizeResult::Rejected(RejectReason::TooLong(_))));
    }

    #[test]
    fn test_reject_injection_pattern() {
        let mut s = SqlSanitizer::default();
        let result = s.sanitize_string("' or '1'='1");
        assert!(matches!(result, SanitizeResult::Rejected(RejectReason::LooksLikeInjection)));
    }

    #[test]
    fn test_sanitize_int() {
        let mut s = SqlSanitizer::default();
        assert_eq!(s.sanitize_int("42"), SanitizeResult::Safe("42".into()));
    }

    #[test]
    fn test_reject_int_injection() {
        let mut s = SqlSanitizer::default();
        let result = s.sanitize_int("42; DROP TABLE x");
        assert!(matches!(result, SanitizeResult::Rejected(_)));
    }

    #[test]
    fn test_sanitize_float() {
        let mut s = SqlSanitizer::default();
        assert_eq!(s.sanitize_float("3.14"), SanitizeResult::Safe("3.14".into()));
    }

    #[test]
    fn test_reject_infinity() {
        let mut s = SqlSanitizer::default();
        let result = s.sanitize_float("inf");
        assert!(matches!(result, SanitizeResult::Rejected(_)));
    }

    #[test]
    fn test_validate_identifier_ok() {
        let mut s = SqlSanitizer::default();
        assert_eq!(s.validate_identifier("moz_places"), SanitizeResult::Safe("moz_places".into()));
    }

    #[test]
    fn test_validate_identifier_invalid_start() {
        let mut s = SqlSanitizer::default();
        let result = s.validate_identifier("1table");
        assert!(matches!(result, SanitizeResult::Rejected(_)));
    }

    #[test]
    fn test_validate_identifier_with_dash() {
        let mut s = SqlSanitizer::default();
        let result = s.validate_identifier("bad-name");
        assert!(matches!(result, SanitizeResult::Rejected(_)));
    }

    #[test]
    fn test_counters() {
        let mut s = SqlSanitizer::default();
        s.sanitize_string("ok");
        s.sanitize_string("\0");
        assert_eq!(s.sanitized_count(), 1);
        assert_eq!(s.rejected_count(), 1);
    }
}
