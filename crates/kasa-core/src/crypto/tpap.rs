//! TPAP session cipher for encrypted communication.
//!
//! After SPAKE2+ authentication, the shared key is used to derive session
//! encryption keys. TPAP supports multiple AEAD ciphers:
//!
//! - `aes_128_ccm`: AES-128 in CCM mode
//! - `aes_256_ccm`: AES-256 in CCM mode
//! - `chacha20_poly1305`: ChaCha20-Poly1305
//!
//! Session keys and nonces are derived using HKDF with cipher-specific labels.

use aes::Aes128;
use ccm::{
    Ccm,
    aead::{Aead, KeyInit},
    consts::{U12, U16},
};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::{Sha256, Sha512};

/// TPAP cipher type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TpapCipherType {
    /// AES-128-CCM with 16-byte tag
    #[default]
    Aes128Ccm,
    /// AES-256-CCM with 16-byte tag
    Aes256Ccm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

impl TpapCipherType {
    /// Parse cipher type from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().replace("-", "_").as_str() {
            "aes_128_ccm" => Some(Self::Aes128Ccm),
            "aes_256_ccm" => Some(Self::Aes256Ccm),
            "chacha20_poly1305" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    /// Returns the key length in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Ccm => 16,
            Self::Aes256Ccm | Self::ChaCha20Poly1305 => 32,
        }
    }

    /// Returns the cipher name for negotiation.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Aes128Ccm => "aes_128_ccm",
            Self::Aes256Ccm => "aes_256_ccm",
            Self::ChaCha20Poly1305 => "chacha20_poly1305",
        }
    }
}

/// Labels used for HKDF key derivation.
struct CipherLabels {
    key_salt: &'static [u8],
    key_info: &'static [u8],
    nonce_salt: &'static [u8],
    nonce_info: &'static [u8],
}

impl TpapCipherType {
    fn labels(&self) -> CipherLabels {
        match self {
            Self::Aes128Ccm => CipherLabels {
                key_salt: b"tp-kdf-salt-aes128-key",
                key_info: b"tp-kdf-info-aes128-key",
                nonce_salt: b"tp-kdf-salt-aes128-iv",
                nonce_info: b"tp-kdf-info-aes128-iv",
            },
            Self::Aes256Ccm => CipherLabels {
                key_salt: b"tp-kdf-salt-aes256-key",
                key_info: b"tp-kdf-info-aes256-key",
                nonce_salt: b"tp-kdf-salt-aes256-iv",
                nonce_info: b"tp-kdf-info-aes256-iv",
            },
            Self::ChaCha20Poly1305 => CipherLabels {
                key_salt: b"tp-kdf-salt-chacha20-key",
                key_info: b"tp-kdf-info-chacha20-key",
                nonce_salt: b"tp-kdf-salt-chacha20-iv",
                nonce_info: b"tp-kdf-info-chacha20-iv",
            },
        }
    }
}

/// AEAD session cipher for TPAP encrypted communication.
#[derive(Clone)]
pub struct TpapSessionCipher {
    cipher_type: TpapCipherType,
    key: Vec<u8>,
    base_nonce: [u8; 12],
}

/// Tag length for all ciphers.
const TAG_LEN: usize = 16;

/// Nonce length.
const NONCE_LEN: usize = 12;

impl TpapSessionCipher {
    /// Create a session cipher from the SPAKE2+ shared key.
    ///
    /// # Arguments
    ///
    /// * `cipher_type` - The AEAD cipher to use
    /// * `shared_key` - The shared key from SPAKE2+
    /// * `use_sha512` - Use SHA-512 for HKDF (true for cipher suites 2, 4, 5, 7, 9)
    pub fn from_shared_key(
        cipher_type: TpapCipherType,
        shared_key: &[u8],
        use_sha512: bool,
    ) -> Self {
        let labels = cipher_type.labels();
        let key_len = cipher_type.key_len();

        let (key, base_nonce_vec) = if use_sha512 {
            let key = hkdf_derive_sha512(shared_key, labels.key_salt, labels.key_info, key_len);
            let nonce =
                hkdf_derive_sha512(shared_key, labels.nonce_salt, labels.nonce_info, NONCE_LEN);
            (key, nonce)
        } else {
            let key = hkdf_derive_sha256(shared_key, labels.key_salt, labels.key_info, key_len);
            let nonce =
                hkdf_derive_sha256(shared_key, labels.nonce_salt, labels.nonce_info, NONCE_LEN);
            (key, nonce)
        };

        let mut base_nonce_arr = [0u8; NONCE_LEN];
        base_nonce_arr.copy_from_slice(&base_nonce_vec);

        Self {
            cipher_type,
            key,
            base_nonce: base_nonce_arr,
        }
    }

    /// Encrypt plaintext with the given sequence number.
    ///
    /// Returns ciphertext with appended authentication tag.
    pub fn encrypt(&self, plaintext: &[u8], seq: u32) -> Result<Vec<u8>, TpapCipherError> {
        let nonce = self.nonce_for_seq(seq);

        match self.cipher_type {
            TpapCipherType::Aes128Ccm => {
                type Aes128Ccm = Ccm<Aes128, U16, U12>;
                let key: [u8; 16] = self.key[..16]
                    .try_into()
                    .map_err(|_| TpapCipherError::InvalidKey)?;
                let cipher = Aes128Ccm::new(&key.into());
                cipher
                    .encrypt(&nonce.into(), plaintext)
                    .map_err(|_| TpapCipherError::EncryptionFailed)
            }
            TpapCipherType::Aes256Ccm => {
                // aes-256-ccm requires Aes256
                use aes::Aes256;
                type Aes256Ccm = Ccm<Aes256, U16, U12>;
                let key: [u8; 32] = self.key[..32]
                    .try_into()
                    .map_err(|_| TpapCipherError::InvalidKey)?;
                let cipher = Aes256Ccm::new(&key.into());
                cipher
                    .encrypt(&nonce.into(), plaintext)
                    .map_err(|_| TpapCipherError::EncryptionFailed)
            }
            TpapCipherType::ChaCha20Poly1305 => {
                let key: [u8; 32] = self.key[..32]
                    .try_into()
                    .map_err(|_| TpapCipherError::InvalidKey)?;
                let cipher = ChaCha20Poly1305::new(&key.into());
                cipher
                    .encrypt(&nonce.into(), plaintext)
                    .map_err(|_| TpapCipherError::EncryptionFailed)
            }
        }
    }

    /// Decrypt ciphertext (with tag) using the given sequence number.
    pub fn decrypt(&self, ciphertext: &[u8], seq: u32) -> Result<Vec<u8>, TpapCipherError> {
        if ciphertext.len() < TAG_LEN {
            return Err(TpapCipherError::CiphertextTooShort);
        }

        let nonce = self.nonce_for_seq(seq);

        match self.cipher_type {
            TpapCipherType::Aes128Ccm => {
                type Aes128Ccm = Ccm<Aes128, U16, U12>;
                let key: [u8; 16] = self.key[..16]
                    .try_into()
                    .map_err(|_| TpapCipherError::InvalidKey)?;
                let cipher = Aes128Ccm::new(&key.into());
                cipher
                    .decrypt(&nonce.into(), ciphertext)
                    .map_err(|_| TpapCipherError::DecryptionFailed)
            }
            TpapCipherType::Aes256Ccm => {
                use aes::Aes256;
                type Aes256Ccm = Ccm<Aes256, U16, U12>;
                let key: [u8; 32] = self.key[..32]
                    .try_into()
                    .map_err(|_| TpapCipherError::InvalidKey)?;
                let cipher = Aes256Ccm::new(&key.into());
                cipher
                    .decrypt(&nonce.into(), ciphertext)
                    .map_err(|_| TpapCipherError::DecryptionFailed)
            }
            TpapCipherType::ChaCha20Poly1305 => {
                let key: [u8; 32] = self.key[..32]
                    .try_into()
                    .map_err(|_| TpapCipherError::InvalidKey)?;
                let cipher = ChaCha20Poly1305::new(&key.into());
                cipher
                    .decrypt(&nonce.into(), ciphertext)
                    .map_err(|_| TpapCipherError::DecryptionFailed)
            }
        }
    }

    /// Encrypt with separate ciphertext and tag output.
    ///
    /// This is used during SPAKE2+ proof exchange where tag is sent separately.
    pub fn encrypt_with_tag(
        &self,
        plaintext: &[u8],
        seq: u32,
    ) -> Result<(Vec<u8>, Vec<u8>), TpapCipherError> {
        let combined = self.encrypt(plaintext, seq)?;
        if combined.len() < TAG_LEN {
            return Err(TpapCipherError::EncryptionFailed);
        }
        let ct_len = combined.len() - TAG_LEN;
        let ciphertext = combined[..ct_len].to_vec();
        let tag = combined[ct_len..].to_vec();
        Ok((ciphertext, tag))
    }

    /// Decrypt with separate ciphertext and tag.
    pub fn decrypt_with_tag(
        &self,
        ciphertext: &[u8],
        tag: &[u8],
        seq: u32,
    ) -> Result<Vec<u8>, TpapCipherError> {
        let mut combined = ciphertext.to_vec();
        combined.extend_from_slice(tag);
        self.decrypt(&combined, seq)
    }

    /// Compute nonce for a given sequence number.
    fn nonce_for_seq(&self, seq: u32) -> [u8; NONCE_LEN] {
        let mut nonce = self.base_nonce;
        // Replace last 4 bytes with big-endian sequence number
        nonce[8..12].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    /// Returns the cipher type.
    pub fn cipher_type(&self) -> TpapCipherType {
        self.cipher_type
    }
}

impl std::fmt::Debug for TpapSessionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpapSessionCipher")
            .field("cipher_type", &self.cipher_type)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Error type for TPAP cipher operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpapCipherError {
    /// Invalid key for cipher.
    InvalidKey,
    /// Ciphertext too short.
    CiphertextTooShort,
    /// Encryption failed.
    EncryptionFailed,
    /// Decryption or authentication failed.
    DecryptionFailed,
}

impl std::fmt::Display for TpapCipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid key"),
            Self::CiphertextTooShort => write!(f, "ciphertext too short"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption or authentication failed"),
        }
    }
}

impl std::error::Error for TpapCipherError {}

// =============================================================================
// HKDF helpers
// =============================================================================

fn hkdf_derive_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = vec![0u8; length];
    hkdf.expand(info, &mut output).expect("valid HKDF length");
    output
}

fn hkdf_derive_sha512(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hkdf = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut output = vec![0u8; length];
    hkdf.expand(info, &mut output).expect("valid HKDF length");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_type_parse() {
        assert_eq!(
            TpapCipherType::parse("aes_128_ccm"),
            Some(TpapCipherType::Aes128Ccm)
        );
        assert_eq!(
            TpapCipherType::parse("aes-128-ccm"),
            Some(TpapCipherType::Aes128Ccm)
        );
        assert_eq!(
            TpapCipherType::parse("chacha20_poly1305"),
            Some(TpapCipherType::ChaCha20Poly1305)
        );
        assert_eq!(TpapCipherType::parse("unknown"), None);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let shared_key = [0x42u8; 32];
        let cipher =
            TpapSessionCipher::from_shared_key(TpapCipherType::Aes128Ccm, &shared_key, false);

        let plaintext = b"Hello, TPAP!";
        let seq = 1;

        let ciphertext = cipher.encrypt(plaintext, seq).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, seq).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_chacha() {
        let shared_key = [0x42u8; 32];
        let cipher = TpapSessionCipher::from_shared_key(
            TpapCipherType::ChaCha20Poly1305,
            &shared_key,
            false,
        );

        let plaintext = b"Hello, ChaCha!";
        let seq = 1;

        let ciphertext = cipher.encrypt(plaintext, seq).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, seq).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_seq_different_ciphertext() {
        let shared_key = [0x42u8; 32];
        let cipher =
            TpapSessionCipher::from_shared_key(TpapCipherType::Aes128Ccm, &shared_key, false);

        let plaintext = b"test";
        let ct1 = cipher.encrypt(plaintext, 1).unwrap();
        let ct2 = cipher.encrypt(plaintext, 2).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_encrypt_with_tag() {
        let shared_key = [0x42u8; 32];
        let cipher =
            TpapSessionCipher::from_shared_key(TpapCipherType::Aes128Ccm, &shared_key, false);

        let plaintext = b"test message";
        let seq = 1;

        let (ct, tag) = cipher.encrypt_with_tag(plaintext, seq).unwrap();
        assert_eq!(tag.len(), TAG_LEN);

        let decrypted = cipher.decrypt_with_tag(&ct, &tag, seq).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
