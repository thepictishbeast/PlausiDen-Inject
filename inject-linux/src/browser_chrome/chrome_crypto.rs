//! Chrome cookie value encryption for Linux.
//!
//! Chrome on Linux encrypts cookie values stored in the `encrypted_value`
//! column using AES-128-CBC.  The encryption key is derived via PBKDF2 from
//! a password obtained from the system keyring (GNOME Keyring / KWallet).
//! When no keyring is available Chrome falls back to the hardcoded password
//! `"peanuts"`.
//!
//! Key derivation parameters (from Chromium source `os_crypt_linux.cc`):
//! - Password: `"peanuts"` (fallback; keyring-based password used when available)
//! - Salt: `"saltysalt"`
//! - Iterations: 1
//! - Key length: 16 bytes (AES-128)
//! - PRF: HMAC-SHA1
//!
//! Encryption:
//! - Algorithm: AES-128-CBC with PKCS#7 padding
//! - IV: 16 bytes of `0x20` (space character)
//! - The ciphertext is prefixed with `b"v10"` before storage.

use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use inject_core::error::{InjectError, Result};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;

/// Chrome's Linux fallback password when no keyring is available.
const CHROME_PASSWORD: &[u8] = b"peanuts";

/// Fixed salt used by Chromium's os_crypt on Linux.
const CHROME_SALT: &[u8] = b"saltysalt";

/// PBKDF2 iteration count.
const CHROME_ITERATIONS: u32 = 1;

/// AES-128 key length in bytes.
const KEY_LEN: usize = 16;

/// IV used by Chrome on Linux: 16 bytes of 0x20 (space).
const CHROME_IV: [u8; 16] = [0x20; 16];

/// Version prefix prepended to encrypted cookie values on Linux.
const VERSION_PREFIX: &[u8] = b"v10";

/// Derive the Chrome cookie encryption key using PBKDF2-HMAC-SHA1.
fn derive_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(CHROME_PASSWORD, CHROME_SALT, CHROME_ITERATIONS, &mut key);
    key
}

/// Encrypt a plaintext cookie value the same way Chrome does on Linux.
///
/// Returns bytes suitable for the `encrypted_value` BLOB column:
/// `b"v10" || AES-128-CBC(PKCS7(plaintext))`.
pub fn encrypt_cookie_value(plaintext: &str) -> Result<Vec<u8>> {
    let key = derive_key();

    // AES-128-CBC with PKCS7 padding.  The output buffer must be large
    // enough for plaintext + up to one block of padding.
    let pt_bytes = plaintext.as_bytes();
    let block_size = 16;
    let padded_len = ((pt_bytes.len() / block_size) + 1) * block_size;
    let mut buf = vec![0u8; padded_len];
    buf[..pt_bytes.len()].copy_from_slice(pt_bytes);

    let ciphertext = Aes128CbcEnc::new(&key.into(), &CHROME_IV.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_bytes.len())
        .map_err(|e| InjectError::Other(format!("AES-CBC encryption failed: {e}")))?;

    // Prepend the version prefix.
    let mut result = Vec::with_capacity(VERSION_PREFIX.len() + ciphertext.len());
    result.extend_from_slice(VERSION_PREFIX);
    result.extend_from_slice(ciphertext);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_value_differs_from_plaintext() {
        let plaintext = "my_session_token_abc123";
        let encrypted = encrypt_cookie_value(plaintext).unwrap();

        // The encrypted output must NOT contain the plaintext verbatim.
        let plaintext_bytes = plaintext.as_bytes();
        assert_ne!(
            &encrypted[VERSION_PREFIX.len()..],
            plaintext_bytes,
            "ciphertext must differ from plaintext"
        );

        // And the full output (with v10 prefix) must differ too.
        assert_ne!(
            encrypted.as_slice(),
            plaintext_bytes,
            "encrypted output must differ from plaintext"
        );
    }

    #[test]
    fn encrypted_value_is_block_aligned() {
        // AES block size is 16 bytes. With PKCS7 padding, the ciphertext
        // (excluding the "v10" prefix) must be a multiple of 16.
        for input in &["", "x", "short", "exactly16chars!!", "a]longer value that spans multiple blocks!"] {
            let encrypted = encrypt_cookie_value(input).unwrap();
            let ciphertext_len = encrypted.len() - VERSION_PREFIX.len();
            assert_eq!(
                ciphertext_len % 16,
                0,
                "ciphertext length {ciphertext_len} for input {input:?} is not block-aligned"
            );
            // Must be at least one block (PKCS7 always adds padding).
            assert!(
                ciphertext_len >= 16,
                "ciphertext must be at least one AES block"
            );
        }
    }

    #[test]
    fn different_values_produce_different_ciphertexts() {
        let enc_a = encrypt_cookie_value("value_alpha").unwrap();
        let enc_b = encrypt_cookie_value("value_bravo").unwrap();
        let enc_c = encrypt_cookie_value("value_charlie").unwrap();

        assert_ne!(enc_a, enc_b, "different inputs must produce different ciphertexts");
        assert_ne!(enc_b, enc_c, "different inputs must produce different ciphertexts");
        assert_ne!(enc_a, enc_c, "different inputs must produce different ciphertexts");
    }

    #[test]
    fn encrypted_value_has_v10_prefix() {
        let encrypted = encrypt_cookie_value("test_cookie").unwrap();
        assert!(
            encrypted.starts_with(VERSION_PREFIX),
            "encrypted cookie must start with v10 prefix"
        );
    }

    #[test]
    fn encryption_is_deterministic() {
        // Same plaintext with same key + IV must produce identical ciphertext.
        let enc1 = encrypt_cookie_value("determinism_check").unwrap();
        let enc2 = encrypt_cookie_value("determinism_check").unwrap();
        assert_eq!(enc1, enc2, "encryption of same value must be deterministic (fixed key + IV)");
    }

    #[test]
    fn key_derivation_is_stable() {
        // Verify PBKDF2 derivation produces a known-stable key.
        let key1 = derive_key();
        let key2 = derive_key();
        assert_eq!(key1, key2);
        // Key must not be all zeros.
        assert_ne!(key1, [0u8; KEY_LEN]);
    }
}
