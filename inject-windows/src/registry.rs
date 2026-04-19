//! Windows Registry hive injection.
//!
//! Since PlausiDen runs on Linux, this module generates registry data
//! structures that can be exported as `.reg` files (Windows Registry Editor
//! 5.00 format).  These files can be imported via `reg.exe /import` on a
//! live Windows system or applied to a mounted hive with offline tooling.
//!
//! Forensic-relevant registry locations covered:
//!
//! - **MRU lists** (`MRUListEx` / `MRUList`) -- most-recently-used file
//!   and command lists that reveal user activity.
//! - **UserAssist** -- ROT13-encoded program execution records under
//!   `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`.
//! - **ShellBags** -- folder view settings that prove a user navigated to
//!   a directory, even after deletion.
//! - **RecentDocs** -- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
//!   tracks recently opened documents by extension.

use chrono::Utc;
use inject_core::error::{InjectError, Result};
use inject_core::{
    InjectionResult, InjectionStrategy, InjectionStrategy::DirectInjection, Injector, Target,
    VerificationStatus,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Registry value types
// ---------------------------------------------------------------------------

/// Windows registry value types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegistryValueType {
    /// String value (`REG_SZ`).
    RegSz,
    /// Expandable string with environment variables (`REG_EXPAND_SZ`).
    RegExpandSz,
    /// 32-bit unsigned integer (`REG_DWORD`).
    RegDword,
    /// 64-bit unsigned integer (`REG_QWORD`).
    RegQword,
    /// Raw binary data (`REG_BINARY`).
    RegBinary,
    /// Multi-string value (`REG_MULTI_SZ`).
    RegMultiSz,
    /// No value type (`REG_NONE`).
    RegNone,
}

impl fmt::Display for RegistryValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegSz => write!(f, "REG_SZ"),
            Self::RegExpandSz => write!(f, "REG_EXPAND_SZ"),
            Self::RegDword => write!(f, "REG_DWORD"),
            Self::RegQword => write!(f, "REG_QWORD"),
            Self::RegBinary => write!(f, "REG_BINARY"),
            Self::RegMultiSz => write!(f, "REG_MULTI_SZ"),
            Self::RegNone => write!(f, "REG_NONE"),
        }
    }
}

// ---------------------------------------------------------------------------
// Registry value data
// ---------------------------------------------------------------------------

/// Typed payload for a registry value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryValueData {
    /// UTF-16 string value.
    String(String),
    /// 32-bit unsigned integer.
    Dword(u32),
    /// 64-bit unsigned integer.
    Qword(u64),
    /// Raw bytes.
    Binary(Vec<u8>),
    /// Ordered list of strings (REG_MULTI_SZ).
    MultiString(Vec<String>),
    /// No data (REG_NONE).
    None,
}

// ---------------------------------------------------------------------------
// Registry entry
// ---------------------------------------------------------------------------

/// A single Windows registry key/value pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// Full registry key path (e.g. `HKEY_CURRENT_USER\Software\...`).
    pub key_path: String,
    /// Value name within the key.  An empty string represents the key's
    /// default value (`@` in `.reg` file syntax).
    pub value_name: String,
    /// Value type.
    pub value_type: RegistryValueType,
    /// Typed value data.
    pub value_data: RegistryValueData,
}

impl RegistryEntry {
    /// Format this entry's value in `.reg` file syntax.
    fn format_value(&self) -> String {
        let name_part = if self.value_name.is_empty() {
            "@".to_string()
        } else {
            format!("\"{}\"", escape_reg_string(&self.value_name))
        };

        match &self.value_data {
            RegistryValueData::String(s) => {
                format!("{}=\"{}\"", name_part, escape_reg_string(s))
            }
            RegistryValueData::Dword(v) => {
                format!("{}=dword:{:08x}", name_part, v)
            }
            RegistryValueData::Qword(v) => {
                // REG_QWORD is encoded as hex(b): with bytes in little-endian.
                let bytes = v.to_le_bytes();
                let hex_str = bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{}=hex(b):{}", name_part, hex_str)
            }
            RegistryValueData::Binary(bytes) => {
                let hex_str = bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{}=hex:{}", name_part, hex_str)
            }
            RegistryValueData::MultiString(strings) => {
                // REG_MULTI_SZ: each string is UTF-16LE null-terminated,
                // followed by an extra null terminator.
                let mut payload: Vec<u8> = Vec::new();
                for s in strings {
                    for code_unit in s.encode_utf16() {
                        payload.extend_from_slice(&code_unit.to_le_bytes());
                    }
                    // Null terminator for this string.
                    payload.extend_from_slice(&[0x00, 0x00]);
                }
                // Final null terminator for the list.
                payload.extend_from_slice(&[0x00, 0x00]);

                let hex_str = payload
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{}=hex(7):{}", name_part, hex_str)
            }
            RegistryValueData::None => {
                format!("{}=hex(0):", name_part)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// .reg file generation
// ---------------------------------------------------------------------------

/// Generate a complete `.reg` file from a slice of registry entries.
///
/// Output conforms to the "Windows Registry Editor Version 5.00" format
/// that `regedit.exe` and `reg.exe /import` accept.
pub fn generate_reg_file(entries: &[RegistryEntry]) -> String {
    let mut output = String::from("Windows Registry Editor Version 5.00\r\n");

    // Group entries by key path to produce well-formed blocks.
    let mut keys_in_order: Vec<&str> = Vec::new();
    let mut by_key: std::collections::HashMap<&str, Vec<&RegistryEntry>> =
        std::collections::HashMap::new();

    for entry in entries {
        let key = entry.key_path.as_str();
        by_key.entry(key).or_default().push(entry);
        if !keys_in_order.contains(&key) {
            keys_in_order.push(key);
        }
    }

    for key in keys_in_order {
        output.push_str("\r\n");
        output.push_str(&format!("[{}]\r\n", key));
        for entry in &by_key[key] {
            output.push_str(&entry.format_value());
            output.push_str("\r\n");
        }
    }

    output
}

// ---------------------------------------------------------------------------
// Forensic-relevant entry generators
// ---------------------------------------------------------------------------

/// Create MRU (Most Recently Used) list entries under
/// `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU`.
///
/// Each MRU entry stores a file path and the MRUListEx value tracks the
/// access order.
pub fn create_mru_entries(extension: &str, file_paths: &[String]) -> Vec<RegistryEntry> {
    let base_key = format!(
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\{}",
        extension,
    );

    let mut entries = Vec::with_capacity(file_paths.len() + 1);

    // Individual MRU slots (0, 1, 2, ...) as binary data.
    for (idx, path) in file_paths.iter().enumerate() {
        let path_bytes: Vec<u8> = path
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .chain([0x00, 0x00]) // null terminator
            .collect();

        entries.push(RegistryEntry {
            key_path: base_key.clone(),
            value_name: idx.to_string(),
            value_type: RegistryValueType::RegBinary,
            value_data: RegistryValueData::Binary(path_bytes),
        });
    }

    // MRUListEx: ordered list of DWORD indices, terminated by 0xFFFFFFFF.
    let mut mru_list_data: Vec<u8> = Vec::new();
    for idx in 0..file_paths.len() {
        mru_list_data.extend_from_slice(&(idx as u32).to_le_bytes());
    }
    mru_list_data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    entries.push(RegistryEntry {
        key_path: base_key,
        value_name: "MRUListEx".to_string(),
        value_type: RegistryValueType::RegBinary,
        value_data: RegistryValueData::Binary(mru_list_data),
    });

    entries
}

/// Create UserAssist entries that record program execution counts and
/// timestamps.
///
/// UserAssist values are stored with ROT13-encoded paths under
/// `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`.
pub fn create_userassist_entries(programs: &[(String, u32)]) -> Vec<RegistryEntry> {
    // CEBFF5CD is the GUID for executable file execution tracking.
    let base_key = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";

    let mut entries = Vec::with_capacity(programs.len());

    for (path, run_count) in programs {
        let rot13_path = rot13(path);

        // UserAssist data structure (16 bytes minimum):
        //   offset 0:  session (u32) = 0
        //   offset 4:  run_count (u32)
        //   offset 8:  focus_count (u32) = run_count
        //   offset 12: focus_time_ms (u32) = 0
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&0u32.to_le_bytes()); // session
        data.extend_from_slice(&run_count.to_le_bytes()); // run count
        data.extend_from_slice(&run_count.to_le_bytes()); // focus count
        data.extend_from_slice(&0u32.to_le_bytes()); // focus time

        entries.push(RegistryEntry {
            key_path: base_key.to_string(),
            value_name: rot13_path,
            value_type: RegistryValueType::RegBinary,
            value_data: RegistryValueData::Binary(data),
        });
    }

    entries
}

/// Create ShellBag entries recording folder navigation.
///
/// ShellBags are stored under
/// `HKCU\Software\Microsoft\Windows\Shell\BagMRU` as nested binary
/// node IDs, and `HKCU\Software\Microsoft\Windows\Shell\Bags\<n>\Shell`
/// for view settings.
pub fn create_shellbag_entries(folder_paths: &[String]) -> Vec<RegistryEntry> {
    let bags_key = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags";
    let bagmru_key = r"HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\BagMRU";

    let mut entries = Vec::with_capacity(folder_paths.len() * 2);

    for (idx, folder) in folder_paths.iter().enumerate() {
        let bag_id = idx + 1;

        // BagMRU node: store the folder path as binary PIDL-like data.
        let path_bytes: Vec<u8> = folder
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .chain([0x00, 0x00])
            .collect();

        entries.push(RegistryEntry {
            key_path: format!(r"{}\{}", bagmru_key, idx),
            value_name: "MRUListEx".to_string(),
            value_type: RegistryValueType::RegBinary,
            value_data: RegistryValueData::Binary(vec![
                0x00, 0x00, 0x00, 0x00, // index 0
                0xFF, 0xFF, 0xFF, 0xFF, // terminator
            ]),
        });

        entries.push(RegistryEntry {
            key_path: format!(r"{}\{}", bagmru_key, idx),
            value_name: "0".to_string(),
            value_type: RegistryValueType::RegBinary,
            value_data: RegistryValueData::Binary(path_bytes),
        });

        // Bags\<n>\Shell: view mode settings.
        entries.push(RegistryEntry {
            key_path: format!(r"{}\{}\Shell", bags_key, bag_id),
            value_name: "KnownFolderDerivedFolderType".to_string(),
            value_type: RegistryValueType::RegSz,
            value_data: RegistryValueData::String("{57807898-8C4F-4462-BB63-71042380B109}".into()),
        });
    }

    entries
}

/// Create RecentDocs entries that track recently opened documents.
///
/// Stored under
/// `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`.
pub fn create_recentdocs_entries(filenames: &[String]) -> Vec<RegistryEntry> {
    let base_key =
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";

    let mut entries = Vec::with_capacity(filenames.len() + 1);

    for (idx, filename) in filenames.iter().enumerate() {
        // Each entry is a binary blob containing the UTF-16LE filename.
        let name_bytes: Vec<u8> = filename
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .chain([0x00, 0x00]) // null terminator
            .collect();

        entries.push(RegistryEntry {
            key_path: base_key.to_string(),
            value_name: idx.to_string(),
            value_type: RegistryValueType::RegBinary,
            value_data: RegistryValueData::Binary(name_bytes),
        });
    }

    // MRUListEx for ordering.
    let mut mru_data: Vec<u8> = Vec::new();
    for idx in 0..filenames.len() {
        mru_data.extend_from_slice(&(idx as u32).to_le_bytes());
    }
    mru_data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    entries.push(RegistryEntry {
        key_path: base_key.to_string(),
        value_name: "MRUListEx".to_string(),
        value_type: RegistryValueType::RegBinary,
        value_data: RegistryValueData::Binary(mru_data),
    });

    entries
}

// ---------------------------------------------------------------------------
// ROT13 helper (for UserAssist encoding)
// ---------------------------------------------------------------------------

/// Apply ROT13 to ASCII letters, leaving other characters unchanged.
fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => char::from(c as u8 + 13),
            'n'..='z' | 'N'..='Z' => char::from(c as u8 - 13),
            other => other,
        })
        .collect()
}

/// Escape special characters for .reg file string values.
fn escape_reg_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------------------------------------------------------------------------
// Injector implementation
// ---------------------------------------------------------------------------

/// Registry injector for Windows targets.
///
/// On Linux this writes `.reg` files to the hive path specified in the
/// [`Target::WindowsRegistry`] variant.  On a live Windows system (or
/// mounted partition) the generated file can be imported via `reg.exe`.
pub struct RegistryInjector {
    /// Override output path for testing; if `None`, use target hive_path.
    output_path: Option<PathBuf>,
}

impl RegistryInjector {
    /// Create a new registry injector.
    pub fn new() -> Self {
        Self { output_path: None }
    }

    /// Create a registry injector that writes to a specific output path
    /// (useful for testing).
    pub fn with_output_path(path: PathBuf) -> Self {
        Self {
            output_path: Some(path),
        }
    }

    /// Resolve the output file path for the `.reg` file.
    fn resolve_output(&self, target: &Target) -> Result<PathBuf> {
        if let Some(path) = &self.output_path {
            return Ok(path.clone());
        }
        match target {
            Target::WindowsRegistry { hive_path } => {
                let reg_file = hive_path.with_extension("reg");
                Ok(reg_file)
            }
            other => Err(InjectError::UnsupportedTarget {
                description: format!("RegistryInjector does not handle {other}"),
            }),
        }
    }
}

impl Default for RegistryInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl Injector for RegistryInjector {
    fn inject(
        &self,
        artifact_bytes: &[u8],
        target: &Target,
        strategy: InjectionStrategy,
    ) -> Result<InjectionResult> {
        if strategy != DirectInjection {
            return Err(InjectError::UnsupportedStrategy {
                strategy: strategy.to_string(),
                target: target.to_string(),
            });
        }

        let entries: Vec<RegistryEntry> = serde_json::from_slice(artifact_bytes)?;
        if entries.is_empty() {
            return Err(InjectError::EmptyArtifact);
        }

        let output_path = self.resolve_output(target)?;
        let reg_content = generate_reg_file(&entries);

        // Back up existing .reg file if it exists.
        let backup_path = if output_path.exists() {
            let ts = Utc::now().format("%Y%m%d%H%M%S");
            let backup = output_path.with_extension(format!("reg.plausiden-backup.{ts}"));
            std::fs::copy(&output_path, &backup).map_err(|e| InjectError::BackupFailed {
                path: output_path.clone(),
                reason: e.to_string(),
            })?;
            Some(backup)
        } else {
            None
        };

        std::fs::write(&output_path, &reg_content)?;

        let run_id = Uuid::new_v4();
        let injected_ids: Vec<String> = entries
            .iter()
            .enumerate()
            .map(|(i, e)| format!("{}\\{} [{}]", e.key_path, e.value_name, i))
            .collect();

        tracing::info!(
            output = %output_path.display(),
            entries = entries.len(),
            "registry injection complete"
        );

        Ok(InjectionResult {
            run_id,
            target: target.clone(),
            strategy: DirectInjection,
            records_injected: entries.len(),
            backup_path,
            timestamp: Utc::now(),
            injected_ids,
        })
    }

    fn verify(&self, result: &InjectionResult) -> Result<VerificationStatus> {
        // For .reg file output we verify by reading the file back and
        // checking that all key/value pairs are present.
        let output_path = match &result.target {
            Target::WindowsRegistry { hive_path } => hive_path.with_extension("reg"),
            _ => {
                return Err(InjectError::UnsupportedTarget {
                    description: "verification requires WindowsRegistry target".into(),
                });
            }
        };

        if !output_path.exists() {
            return Ok(VerificationStatus::NonePresent {
                expected: result.injected_ids.len(),
            });
        }

        let content = std::fs::read_to_string(&output_path)?;
        let mut present = 0usize;
        let mut missing_ids = Vec::new();

        for id in &result.injected_ids {
            // Extract the key path from the id (format: "key\value [idx]").
            let key_part = id.split(" [").next().unwrap_or(id);
            if let Some((_key, value_name)) = key_part.rsplit_once('\\') {
                // Check if the value name appears in the content.
                let search = if value_name.is_empty() {
                    "@=".to_string()
                } else {
                    format!("\"{}\"=", value_name)
                };
                if content.contains(&search) {
                    present += 1;
                } else {
                    missing_ids.push(id.clone());
                }
            } else {
                missing_ids.push(id.clone());
            }
        }

        let total = result.injected_ids.len();
        if present == total {
            Ok(VerificationStatus::AllPresent { checked: total })
        } else if present == 0 {
            Ok(VerificationStatus::NonePresent { expected: total })
        } else {
            Ok(VerificationStatus::PartiallyPresent {
                present,
                missing: total - present,
                missing_ids,
            })
        }
    }

    fn rollback(&self, result: &InjectionResult) -> Result<()> {
        // Restore from backup if available; otherwise delete the .reg file.
        if let Some(backup) = &result.backup_path {
            let dest = match &result.target {
                Target::WindowsRegistry { hive_path } => hive_path.with_extension("reg"),
                _ => {
                    return Err(InjectError::RollbackFailed {
                        reason: "unexpected target type".into(),
                    });
                }
            };
            std::fs::copy(backup, &dest).map_err(|e| InjectError::RollbackFailed {
                reason: format!(
                    "failed to restore backup {} -> {}: {e}",
                    backup.display(),
                    dest.display()
                ),
            })?;
        } else {
            let dest = match &result.target {
                Target::WindowsRegistry { hive_path } => hive_path.with_extension("reg"),
                _ => {
                    return Err(InjectError::RollbackFailed {
                        reason: "unexpected target type".into(),
                    });
                }
            };
            if dest.exists() {
                std::fs::remove_file(&dest).map_err(|e| InjectError::RollbackFailed {
                    reason: format!("failed to remove {}: {e}", dest.display()),
                })?;
            }
        }

        tracing::info!(target = %result.target, "registry rollback complete");
        Ok(())
    }

    fn available_targets(&self) -> Vec<Target> {
        // On Linux we cannot auto-discover mounted Windows hives, so
        // return an empty list.  Callers must provide explicit paths.
        Vec::new()
    }

    fn supported_strategies(&self) -> Vec<InjectionStrategy> {
        vec![DirectInjection]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test 1: generate valid .reg format ---------------------------------

    #[test]
    fn generate_valid_reg_format() {
        let entries = vec![
            RegistryEntry {
                key_path: r"HKEY_CURRENT_USER\Software\TestApp".into(),
                value_name: "InstallPath".into(),
                value_type: RegistryValueType::RegSz,
                value_data: RegistryValueData::String(r"C:\Program Files\TestApp".into()),
            },
            RegistryEntry {
                key_path: r"HKEY_CURRENT_USER\Software\TestApp".into(),
                value_name: "Version".into(),
                value_type: RegistryValueType::RegDword,
                value_data: RegistryValueData::Dword(42),
            },
        ];

        let output = generate_reg_file(&entries);

        // Must start with the magic header.
        assert!(
            output.starts_with("Windows Registry Editor Version 5.00\r\n"),
            "missing .reg header"
        );

        // Must contain the key path in square brackets.
        assert!(
            output.contains(r"[HKEY_CURRENT_USER\Software\TestApp]"),
            "missing key block"
        );

        // String value must be quoted.
        assert!(
            output.contains(r#""InstallPath"="C:\\Program Files\\TestApp""#),
            "bad string value format"
        );

        // DWORD must be lowercase hex with 8 digits.
        assert!(
            output.contains(r#""Version"=dword:0000002a"#),
            "bad dword format"
        );

        // Lines must use CRLF.
        assert!(
            !output.contains('\n') || output.contains("\r\n"),
            "should use CRLF line endings"
        );
    }

    // -- Test 2: different value types --------------------------------------

    #[test]
    fn different_value_types() {
        let entries = vec![
            RegistryEntry {
                key_path: r"HKEY_LOCAL_MACHINE\Software\Types".into(),
                value_name: "".into(), // default value
                value_type: RegistryValueType::RegSz,
                value_data: RegistryValueData::String("default".into()),
            },
            RegistryEntry {
                key_path: r"HKEY_LOCAL_MACHINE\Software\Types".into(),
                value_name: "ExpandStr".into(),
                value_type: RegistryValueType::RegExpandSz,
                value_data: RegistryValueData::String("%USERPROFILE%".into()),
            },
            RegistryEntry {
                key_path: r"HKEY_LOCAL_MACHINE\Software\Types".into(),
                value_name: "Counter64".into(),
                value_type: RegistryValueType::RegQword,
                value_data: RegistryValueData::Qword(0x0102030405060708),
            },
            RegistryEntry {
                key_path: r"HKEY_LOCAL_MACHINE\Software\Types".into(),
                value_name: "Blob".into(),
                value_type: RegistryValueType::RegBinary,
                value_data: RegistryValueData::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            },
            RegistryEntry {
                key_path: r"HKEY_LOCAL_MACHINE\Software\Types".into(),
                value_name: "Multi".into(),
                value_type: RegistryValueType::RegMultiSz,
                value_data: RegistryValueData::MultiString(vec!["one".into(), "two".into()]),
            },
            RegistryEntry {
                key_path: r"HKEY_LOCAL_MACHINE\Software\Types".into(),
                value_name: "Empty".into(),
                value_type: RegistryValueType::RegNone,
                value_data: RegistryValueData::None,
            },
        ];

        let output = generate_reg_file(&entries);

        // Default value uses @ sigil.
        assert!(
            output.contains("@=\"default\""),
            "default value should use @"
        );

        // QWORD: little-endian hex bytes.
        assert!(
            output.contains("hex(b):08,07,06,05,04,03,02,01"),
            "QWORD should be LE hex: got {output}"
        );

        // Binary hex.
        assert!(
            output.contains("hex:de,ad,be,ef"),
            "binary should be hex bytes"
        );

        // Multi-string uses hex(7).
        assert!(output.contains("hex(7):"), "multi-string should use hex(7)");

        // REG_NONE uses hex(0).
        assert!(output.contains("hex(0):"), "REG_NONE should use hex(0)");
    }

    // -- Test 3: MRU list entries -------------------------------------------

    #[test]
    fn mru_list_entries() {
        let files = vec![
            r"C:\Users\admin\Documents\report.docx".to_string(),
            r"C:\Users\admin\Desktop\notes.txt".to_string(),
        ];
        let entries = create_mru_entries("docx", &files);

        // Should have 2 file entries + 1 MRUListEx entry.
        assert_eq!(entries.len(), 3, "expected 3 entries (2 files + MRUListEx)");

        // Verify MRUListEx is present and terminates with 0xFFFFFFFF.
        let mru_entry = entries
            .iter()
            .find(|e| e.value_name == "MRUListEx")
            .expect("MRUListEx entry missing");

        if let RegistryValueData::Binary(data) = &mru_entry.value_data {
            // 2 indices (0, 1) as u32 LE + 0xFFFFFFFF terminator = 12 bytes.
            assert_eq!(data.len(), 12, "MRUListEx should be 12 bytes");
            // Terminator is the last 4 bytes.
            assert_eq!(
                &data[8..12],
                &[0xFF, 0xFF, 0xFF, 0xFF],
                "MRUListEx must end with 0xFFFFFFFF"
            );
        } else {
            panic!("MRUListEx should be Binary data");
        }

        // Verify the key path contains the extension.
        assert!(
            entries[0].key_path.contains("docx"),
            "key path should include extension"
        );

        // Generate .reg output and verify it's valid.
        let output = generate_reg_file(&entries);
        assert!(output.starts_with("Windows Registry Editor Version 5.00\r\n"));
    }

    // -- Test 4: round-trip serialization -----------------------------------

    #[test]
    fn round_trip_serialization() {
        let entries = vec![
            RegistryEntry {
                key_path: r"HKEY_CURRENT_USER\Software\RoundTrip".into(),
                value_name: "Name".into(),
                value_type: RegistryValueType::RegSz,
                value_data: RegistryValueData::String("hello".into()),
            },
            RegistryEntry {
                key_path: r"HKEY_CURRENT_USER\Software\RoundTrip".into(),
                value_name: "Count".into(),
                value_type: RegistryValueType::RegDword,
                value_data: RegistryValueData::Dword(99),
            },
            RegistryEntry {
                key_path: r"HKEY_CURRENT_USER\Software\RoundTrip".into(),
                value_name: "Data".into(),
                value_type: RegistryValueType::RegBinary,
                value_data: RegistryValueData::Binary(vec![1, 2, 3, 4]),
            },
            RegistryEntry {
                key_path: r"HKEY_CURRENT_USER\Software\RoundTrip".into(),
                value_name: "Big".into(),
                value_type: RegistryValueType::RegQword,
                value_data: RegistryValueData::Qword(u64::MAX),
            },
        ];

        // Serialize to JSON.
        let json = serde_json::to_string(&entries).expect("serialization failed");

        // Deserialize back.
        let restored: Vec<RegistryEntry> =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(entries, restored, "round-trip should preserve entries");

        // Also verify the injector can accept the JSON bytes.
        let tmp = std::env::temp_dir().join("plausiden-reg-test-roundtrip.reg");
        let injector = RegistryInjector::with_output_path(tmp.clone());

        let target = Target::WindowsRegistry {
            hive_path: tmp.clone(),
        };
        let result = injector.inject(json.as_bytes(), &target, DirectInjection);
        assert!(result.is_ok(), "injection should succeed: {:?}", result);

        let result = result.unwrap();
        assert_eq!(result.records_injected, 4);

        // Clean up.
        let _ = std::fs::remove_file(&tmp);
    }

    // -- Test 5: ROT13 encoding for UserAssist ------------------------------

    #[test]
    fn rot13_encoding() {
        assert_eq!(rot13("ABC"), "NOP");
        assert_eq!(rot13("abc"), "nop");
        assert_eq!(rot13("Hello World!"), "Uryyb Jbeyq!");
        // Double ROT13 is identity.
        let original = r"C:\Windows\notepad.exe";
        assert_eq!(rot13(&rot13(original)), original);
    }

    // -- Test 6: UserAssist entry creation ----------------------------------

    #[test]
    fn userassist_entries() {
        let programs = vec![
            (r"C:\Windows\notepad.exe".to_string(), 5u32),
            (r"C:\Windows\calc.exe".to_string(), 3u32),
        ];

        let entries = create_userassist_entries(&programs);
        assert_eq!(entries.len(), 2);

        // Value names should be ROT13-encoded.
        let expected_name = rot13(r"C:\Windows\notepad.exe");
        assert_eq!(entries[0].value_name, expected_name);

        // Data should be 16 bytes with the run count at offset 4.
        if let RegistryValueData::Binary(data) = &entries[0].value_data {
            assert_eq!(data.len(), 16);
            let run_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            assert_eq!(run_count, 5, "run count should be 5");
        } else {
            panic!("UserAssist data should be Binary");
        }
    }
}
