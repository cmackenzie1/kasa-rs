//! XOR autokey cipher for the legacy TP-Link Smart Home Protocol.
//!
//! The legacy protocol uses a simple XOR autokey cipher with a starting key of 171.
//! This is used for TCP communication on port 9999.

/// Initial key for the XOR autokey cipher.
const INITIAL_KEY: u8 = 171;

/// Encrypts a plaintext string using the TP-Link Smart Home Protocol.
///
/// The encryption uses an XOR autokey cipher with a starting key of 171.
/// The result includes a 4-byte big-endian length prefix followed by the
/// encrypted payload.
///
/// # Arguments
///
/// * `plaintext` - The JSON command string to encrypt
///
/// # Returns
///
/// A byte vector containing the length prefix and encrypted payload,
/// ready to be sent over TCP.
///
/// # Example
///
/// ```
/// use kasa_core::crypto::xor::encrypt;
///
/// let command = r#"{"system":{"get_sysinfo":{}}}"#;
/// let encrypted = encrypt(command);
///
/// // First 4 bytes are the length header
/// assert_eq!(encrypted.len(), 4 + command.len());
/// ```
pub fn encrypt(plaintext: &str) -> Vec<u8> {
    let mut key: u8 = INITIAL_KEY;
    let bytes = plaintext.as_bytes();
    let len = bytes.len() as u32;

    let mut result = Vec::with_capacity(4 + bytes.len());
    result.extend_from_slice(&len.to_be_bytes());

    for &byte in bytes {
        let encrypted = key ^ byte;
        key = encrypted;
        result.push(encrypted);
    }

    result
}

/// Encrypts for UDP broadcast (no length prefix).
///
/// UDP discovery uses the same XOR cipher but without the 4-byte length header.
///
/// # Arguments
///
/// * `plaintext` - The JSON command string to encrypt
///
/// # Returns
///
/// A byte vector containing only the encrypted payload (no length header).
///
/// # Example
///
/// ```
/// use kasa_core::crypto::xor::encrypt_udp;
///
/// let command = r#"{"system":{"get_sysinfo":{}}}"#;
/// let encrypted = encrypt_udp(command);
///
/// // No length header for UDP
/// assert_eq!(encrypted.len(), command.len());
/// ```
pub fn encrypt_udp(plaintext: &str) -> Vec<u8> {
    let mut key: u8 = INITIAL_KEY;
    let bytes = plaintext.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());

    for &byte in bytes {
        let encrypted = key ^ byte;
        key = encrypted;
        result.push(encrypted);
    }

    result
}

/// Decrypts ciphertext using the TP-Link Smart Home Protocol.
///
/// The decryption uses an XOR autokey cipher with a starting key of 171.
/// This function expects the raw encrypted payload **without** the 4-byte
/// length prefix.
///
/// # Arguments
///
/// * `ciphertext` - The encrypted payload bytes (excluding length header)
///
/// # Returns
///
/// The decrypted string. Invalid UTF-8 sequences are replaced with the
/// Unicode replacement character.
///
/// # Example
///
/// ```
/// use kasa_core::crypto::xor::{encrypt, decrypt};
///
/// let original = r#"{"system":{"get_sysinfo":{}}}"#;
/// let encrypted = encrypt(original);
///
/// // Decrypt, skipping the 4-byte length header
/// let decrypted = decrypt(&encrypted[4..]);
/// assert_eq!(original, decrypted);
/// ```
pub fn decrypt(ciphertext: &[u8]) -> String {
    let mut key: u8 = INITIAL_KEY;
    let mut result = Vec::with_capacity(ciphertext.len());

    for &byte in ciphertext {
        let decrypted = key ^ byte;
        key = byte;
        result.push(decrypted);
    }

    String::from_utf8_lossy(&result).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = r#"{"system":{"get_sysinfo":{}}}"#;
        let encrypted = encrypt(original);
        // Skip the 4-byte length header for decryption
        let decrypted = decrypt(&encrypted[4..]);
        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_encrypt_has_length_header() {
        let input = "test";
        let encrypted = encrypt(input);
        // First 4 bytes should be the length in big-endian
        let len = u32::from_be_bytes([encrypted[0], encrypted[1], encrypted[2], encrypted[3]]);
        assert_eq!(len as usize, input.len());
    }

    #[test]
    fn test_decrypt_empty() {
        let result = decrypt(&[]);
        assert_eq!(result, "");
    }

    #[test]
    fn test_encrypt_produces_correct_length() {
        let input = "hello world";
        let encrypted = encrypt(input);
        assert_eq!(encrypted.len(), 4 + input.len());
    }

    #[test]
    fn test_encrypt_udp_no_length_header() {
        let input = "test";
        let encrypted = encrypt_udp(input);
        // UDP encryption has no length header
        assert_eq!(encrypted.len(), input.len());
    }

    #[test]
    fn test_encrypt_udp_decrypt_roundtrip() {
        let original = r#"{"system":{"get_sysinfo":{}}}"#;
        let encrypted = encrypt_udp(original);
        let decrypted = decrypt(&encrypted);
        assert_eq!(original, decrypted);
    }
}
