use anyhow::Result;
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::header::{KdfParams, NONCE_LEN};

const KEY_LEN: usize = 32;

/// Derives a 256-bit key from a password and salt using Argon2id.
pub fn derive_key(password: &[u8], salt: &[u8], kdf: &KdfParams) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("argon2 params error: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?;

    Ok(key)
}

/// Derives a per-chunk nonce by XORing the chunk index into the base nonce.
/// This is the same technique used by TLS 1.3 for per-record nonce derivation.
pub fn derive_nonce(base: &[u8; NONCE_LEN], chunk_index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *base;
    let idx = chunk_index.to_le_bytes();
    // XOR into the last 8 bytes so the first 4 random bytes remain untouched,
    // giving maximum entropy spread across the nonce space.
    for i in 0..8 {
        nonce[4 + i] ^= idx[i];
    }
    nonce
}

/// Zeroize a key after use.
pub fn zeroize_key(key: &mut [u8; KEY_LEN]) {
    key.zeroize();
}
