//! Android SharedPreferences XML injection.
//!
//! SharedPreferences are key-value stores persisted as XML files under
//! `/data/data/<package>/shared_prefs/`.  This injector writes
//! well-formed SharedPreferences XML files that can be pushed into an
//! extracted filesystem image.

use chrono::Utc;
use inject_core::error::{InjectError, Result};
use inject_core::{InjectionResult, InjectionStrategy, Injector, Target, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Represents a single SharedPreferences file with its key-value entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPrefsRecord {
    /// Package that owns these prefs (e.g. `com.example.app`).
    pub package_name: String,
    /// Preferences filename without extension (e.g. `app_settings`).
    pub prefs_name: String,
    /// Key-value entries.  Values are stored as tagged unions.
    pub entries: Vec<SharedPrefsEntry>,
}

/// A single entry in a SharedPreferences file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPrefsEntry {
    pub key: String,
    pub value: SharedPrefsValue,
}

/// Value types supported by Android SharedPreferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum SharedPrefsValue {
    StringVal(String),
    IntVal(i32),
    LongVal(i64),
    FloatVal(f32),
    BoolVal(bool),
}

impl SharedPrefsRecord {
    /// Generate the XML filename: `<prefs_name>.xml`.
    pub fn filename(&self) -> String {
        format!("{}_{}.xml", self.package_name, self.prefs_name)
    }

    /// Render this record as Android SharedPreferences XML.
    pub fn to_xml(&self) -> String {
        let mut xml =
            String::from("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n");
        for entry in &self.entries {
            match &entry.value {
                SharedPrefsValue::StringVal(v) => {
                    xml.push_str(&format!(
                        "    <string name=\"{}\">{}</string>\n",
                        entry.key, v
                    ));
                }
                SharedPrefsValue::IntVal(v) => {
                    xml.push_str(&format!(
                        "    <int name=\"{}\" value=\"{v}\" />\n",
                        entry.key
                    ));
                }
                SharedPrefsValue::LongVal(v) => {
                    xml.push_str(&format!(
                        "    <long name=\"{}\" value=\"{v}\" />\n",
                        entry.key
                    ));
                }
                SharedPrefsValue::FloatVal(v) => {
                    xml.push_str(&format!(
                        "    <float name=\"{}\" value=\"{v}\" />\n",
                        entry.key
                    ));
                }
                SharedPrefsValue::BoolVal(v) => {
                    xml.push_str(&format!(
                        "    <boolean name=\"{}\" value=\"{v}\" />\n",
                        entry.key
                    ));
                }
            }
        }
        xml.push_str("</map>\n");
        xml
    }
}

pub struct SharedPrefsInjector {
    output_dir: PathBuf,
}

impl SharedPrefsInjector {
    pub fn new(output_dir: PathBuf) -> Self {
        Self { output_dir }
    }
}

impl Injector for SharedPrefsInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        _target: &Target,
        _strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        let records: Vec<SharedPrefsRecord> = serde_json::from_slice(artifact_bytes)?;
        if records.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }

        std::fs::create_dir_all(&self.output_dir).map_err(InjectError::Io)?;

        let run_id = Uuid::new_v4();
        let mut injected_ids = Vec::new();

        for record in &records {
            let path = self.output_dir.join(record.filename());
            let xml = record.to_xml();
            std::fs::write(&path, xml.as_bytes()).map_err(InjectError::Io)?;
            injected_ids.push(path.to_string_lossy().to_string());
        }

        Ok(InjectionResult {
            run_id,
            target: Target::Filesystem {
                path: self.output_dir.clone(),
            },
            strategy: InjectionStrategy::DirectInjection,
            records_injected: records.len(),
            backup_path: None,
            timestamp: Utc::now(),
            injected_ids,
        })
    }

    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        let mut present = 0;
        for path in &result.injected_ids {
            if std::path::Path::new(path).exists() {
                present += 1;
            }
        }
        if present == result.injected_ids.len() {
            Ok(VerificationStatus::AllPresent { checked: present })
        } else if present > 0 {
            Ok(VerificationStatus::PartiallyPresent {
                present,
                missing: result.injected_ids.len() - present,
                missing_ids: vec![],
            })
        } else {
            Ok(VerificationStatus::NonePresent {
                expected: result.injected_ids.len(),
            })
        }
    }

    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        for path in &result.injected_ids {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        vec![Target::Filesystem {
            path: self.output_dir.clone(),
        }]
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        vec![InjectionStrategy::DirectInjection]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_records() -> Vec<SharedPrefsRecord> {
        vec![SharedPrefsRecord {
            package_name: "com.example.app".into(),
            prefs_name: "user_settings".into(),
            entries: vec![
                SharedPrefsEntry {
                    key: "username".into(),
                    value: SharedPrefsValue::StringVal("demo_user".into()),
                },
                SharedPrefsEntry {
                    key: "login_count".into(),
                    value: SharedPrefsValue::IntVal(42),
                },
                SharedPrefsEntry {
                    key: "dark_mode".into(),
                    value: SharedPrefsValue::BoolVal(true),
                },
            ],
        }]
    }

    #[test]
    fn test_inject_and_verify_shared_prefs() {
        let dir = TempDir::new().unwrap();
        let injector = SharedPrefsInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector
            .inject(
                &bytes,
                &Target::Filesystem {
                    path: dir.path().into(),
                },
                InjectionStrategy::DirectInjection,
            )
            .unwrap();
        assert_eq!(result.records_injected, 1);
        // Verify the output is valid XML
        let content =
            std::fs::read_to_string(dir.path().join("com.example.app_user_settings.xml")).unwrap();
        assert!(content.contains("<map>"));
        assert!(content.contains("username"));
        assert!(matches!(
            injector.verify(&result).unwrap(),
            VerificationStatus::AllPresent { .. }
        ));
    }

    #[test]
    fn test_rollback_shared_prefs() {
        let dir = TempDir::new().unwrap();
        let injector = SharedPrefsInjector::new(dir.path().to_path_buf());
        let bytes = serde_json::to_vec(&sample_records()).unwrap();
        let result = injector
            .inject(
                &bytes,
                &Target::Filesystem {
                    path: dir.path().into(),
                },
                InjectionStrategy::DirectInjection,
            )
            .unwrap();
        injector.rollback(&result).unwrap();
        assert!(matches!(
            injector.verify(&result).unwrap(),
            VerificationStatus::NonePresent { .. }
        ));
    }
}
