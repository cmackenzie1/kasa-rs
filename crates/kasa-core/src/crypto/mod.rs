//! Cryptographic utilities for TP-Link Kasa device communication.
//!
//! This module provides encryption and decryption functions for the various
//! protocols used by TP-Link devices:
//!
//! - [`xor`]: Legacy XOR cipher for older devices
//! - [`klap`]: KLAP (Kasa Local Authentication Protocol) for newer firmware
//! - [`tpap`]: TPAP session cipher for SPAKE2+ authenticated sessions
//! - [`spake2plus`]: SPAKE2+ password-authenticated key exchange

pub mod klap;
pub mod spake2plus;
pub mod tpap;
pub mod xor;

pub use klap::{KlapEncryptionSession, generate_auth_hash, generate_owner_hash};
pub use spake2plus::{Spake2PlusCipherSuite, Spake2PlusError, Spake2PlusProver};
pub use tpap::{TpapCipherError, TpapCipherType, TpapSessionCipher};
pub use xor::{decrypt as xor_decrypt, encrypt as xor_encrypt, encrypt_udp as xor_encrypt_udp};
