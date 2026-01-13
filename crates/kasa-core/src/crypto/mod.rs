//! Cryptographic utilities for TP-Link Kasa device communication.
//!
//! This module provides encryption and decryption functions for both the
//! legacy XOR protocol and the newer KLAP protocol.

pub mod klap;
pub mod xor;

pub use klap::{KlapEncryptionSession, generate_auth_hash, generate_owner_hash};
pub use xor::{decrypt as xor_decrypt, encrypt as xor_encrypt, encrypt_udp as xor_encrypt_udp};
