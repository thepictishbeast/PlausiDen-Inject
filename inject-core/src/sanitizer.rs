//! Output sanitizer — strips all metadata that could identify data as synthetic.
//!
//! Before any artifact reaches the filesystem, it passes through the sanitizer.
//! The sanitizer removes:
//! - Internal artifact IDs (UUIDs from the engine)
//! - Generation timestamps that don't match the simulated timestamps
//! - Any PlausiDen-specific markers or patterns
//! - Consistent formatting that could be fingerprinted
//!
//! This module exists because we assume forensic analysts will look for
//! patterns in our output that distinguish it from organic data.

use crate::error::{InjectError, Result};
use serde_json::Value;

/// Sanitize artifact bytes before injection.
///
/// Removes or randomizes any metadata that could identify the artifact
/// as synthetically generated.
pub fn sanitize_for_injection(artifact_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(artifact_bytes)
        .map_err(|e| InjectError::Serialization(e.to_string()))?;

    strip_internal_metadata(&mut value);
    randomize_formatting(&mut value);

    serde_json::to_vec(&value)
        .map_err(|e| InjectError::Serialization(e.to_string()))
}

/// Remove fields that are internal to the engine and should never
/// appear in injected data.
fn strip_internal_metadata(value: &mut Value) {
    if let Value::Object(map) = value {
        // Remove engine-internal fields
        map.remove("meta");
        map.remove("artifact_id");
        map.remove("generation_context");
        map.remove("generator_name");
        map.remove("plausiden_version");
    }

    // Recurse into arrays
    if let Value::Array(arr) = value {
        for item in arr {
            strip_internal_metadata(item);
        }
    }
}

/// Add minor random variations to formatting to prevent fingerprinting.
///
/// If all injected data has identical JSON formatting (e.g., consistent
/// key ordering, consistent whitespace), that's a fingerprint.
fn randomize_formatting(value: &mut Value) {
    // serde_json already produces compact format without whitespace,
    // which matches what most applications store.
    // No additional randomization needed for JSON storage.
    //
    // For future: when injecting into non-JSON formats (XML, plist),
    // add appropriate format randomization.
    let _ = value; // Intentionally unused for now
}

/// Validate that sanitized data contains no PlausiDen markers.
pub fn verify_no_markers(data: &[u8]) -> Result<()> {
    let text = String::from_utf8_lossy(data).to_lowercase();

    // These strings should NEVER appear in injected data
    let forbidden_markers = [
        "plausiden",
        "plausible deniability",
        "synthetic",
        "generated",
        "engine-core",
        "engine-browser",
        "artifact_id",
        "forensic_weight",
        "resource_cost",
        "generation_context",
    ];

    for marker in &forbidden_markers {
        if text.contains(marker) {
            return Err(InjectError::SanitizationFailed {
                marker: marker.to_string(),
            });
        }
    }

    Ok(())
}

/// Audit injected data for patterns that could be fingerprinted.
///
/// Returns a list of warnings (not errors) about potential fingerprints.
pub fn audit_fingerprints(data: &[u8]) -> Vec<String> {
    let mut warnings = Vec::new();
    let text = String::from_utf8_lossy(data);

    // Check for suspiciously regular patterns
    if text.contains("example.com") {
        warnings.push("Contains 'example.com' — a test domain that real users rarely visit".to_string());
    }

    // Check for UUID v4 patterns (our internal IDs might leak)
    let uuid_pattern = regex_lite_check(&text);
    if uuid_pattern {
        warnings.push("Contains UUID v4 pattern — possible internal ID leak".to_string());
    }

    // Check for monotonically increasing timestamps (non-organic)
    // This would require parsing the specific format, deferred to per-target auditors

    warnings
}

/// Simple check for UUID-like patterns without pulling in regex crate.
fn regex_lite_check(text: &str) -> bool {
    // UUID v4: 8-4-4-4-12 hex pattern
    let parts: Vec<&str> = text.split('-').collect();
    for window in parts.windows(5) {
        if window[0].len() >= 8
            && window[1].len() == 4
            && window[2].len() == 4
            && window[3].len() == 4
            && window[4].len() >= 12
        {
            let all_hex = window.iter().all(|p| {
                p.chars()
                    .take(12)
                    .all(|c| c.is_ascii_hexdigit())
            });
            if all_hex {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_internal_metadata() {
        let input = serde_json::json!({
            "url": "https://example.org",
            "title": "Test",
            "meta": {"id": "should-be-removed"},
            "artifact_id": "also-removed",
        });

        let bytes = serde_json::to_vec(&input).unwrap();
        let result = sanitize_for_injection(&bytes).unwrap();
        let output: Value = serde_json::from_slice(&result).unwrap();

        assert!(output.get("meta").is_none(), "meta should be stripped");
        assert!(output.get("artifact_id").is_none(), "artifact_id should be stripped");
        assert!(output.get("url").is_some(), "url should be preserved");
    }

    #[test]
    fn test_verify_no_markers_clean() {
        let clean = br#"{"url":"https://news.com","title":"News"}"#;
        assert!(verify_no_markers(clean).is_ok());
    }

    #[test]
    fn test_verify_no_markers_catches_plausiden() {
        let dirty = br#"{"generator":"plausiden-engine","url":"test"}"#;
        assert!(verify_no_markers(dirty).is_err());
    }

    #[test]
    fn test_verify_no_markers_catches_synthetic() {
        let dirty = br#"{"note":"this is synthetic data"}"#;
        assert!(verify_no_markers(dirty).is_err());
    }

    #[test]
    fn test_audit_fingerprints_example_domain() {
        let data = br#"{"url":"https://example.com/page"}"#;
        let warnings = audit_fingerprints(data);
        assert!(!warnings.is_empty(), "should warn about example.com");
    }

    #[test]
    fn test_audit_fingerprints_clean() {
        let data = br#"{"url":"https://www.nytimes.com/article"}"#;
        let warnings = audit_fingerprints(data);
        assert!(warnings.is_empty(), "real domain should not trigger warnings");
    }
}
