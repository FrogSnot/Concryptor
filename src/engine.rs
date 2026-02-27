use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rand::RngCore;
use rayon::prelude::*;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::crypto::{derive_key, derive_nonce, zeroize_key};
use crate::header::{CipherType, Header, HEADER_SIZE, NONCE_LEN, SALT_LEN, TAG_SIZE};

pub const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB

/// AAD size: 52-byte header + 8-byte chunk index + 1-byte final flag.
const AAD_SIZE: usize = HEADER_SIZE + 9;

/// Builds the per-chunk AAD: full serialized header || chunk_index (LE) || is_final.
///
/// This binds every chunk to the exact file header (cipher, chunk size, original
/// size, salt, nonce) and marks the final chunk, implementing STREAM-style
/// commit-or-abort semantics that prevent truncation and append attacks.
fn build_aad(header_bytes: &[u8], chunk_index: u64, is_final: bool) -> [u8; AAD_SIZE] {
    debug_assert_eq!(header_bytes.len(), HEADER_SIZE);
    let mut aad = [0u8; AAD_SIZE];
    aad[..HEADER_SIZE].copy_from_slice(header_bytes);
    aad[HEADER_SIZE..HEADER_SIZE + 8].copy_from_slice(&chunk_index.to_le_bytes());
    aad[HEADER_SIZE + 8] = u8::from(is_final);
    aad
}

/// Opaque cipher handle wrapping a `ring` AEAD key.
/// Uses assembly-optimized AES-GCM or ChaCha20-Poly1305 from `ring`.
pub struct Cipher(LessSafeKey);

impl Cipher {
    fn encrypt_chunk(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_SIZE]> {
        let n = Nonce::assume_unique_for_key(*nonce);
        let tag = self.0.seal_in_place_separate_tag(n, Aad::from(aad), buf)
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        let mut t = [0u8; TAG_SIZE];
        t.copy_from_slice(tag.as_ref());
        Ok(t)
    }

    /// Decrypt in-place. `buf` must contain ciphertext || tag.
    /// After success, plaintext is in `buf[..buf.len() - TAG_SIZE]`.
    fn decrypt_chunk(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut [u8]) -> Result<()> {
        let n = Nonce::assume_unique_for_key(*nonce);
        self.0.open_in_place(n, Aad::from(aad), buf)
            .map_err(|_| anyhow::anyhow!("decryption failed: wrong password or tampered data"))?;
        Ok(())
    }
}

pub fn build_cipher(cipher_type: CipherType, key: &[u8; 32]) -> Result<Cipher> {
    let alg: &'static aead::Algorithm = match cipher_type {
        CipherType::Aes256Gcm => &aead::AES_256_GCM,
        CipherType::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
    };
    let unbound = UnboundKey::new(alg, key)
        .map_err(|_| anyhow::anyhow!("failed to initialize cipher key"))?;
    Ok(Cipher(LessSafeKey::new(unbound)))
}

fn make_progress_bar(total: u64, action: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&format!("{{spinner:.cyan}} {action} [{{bar:40.green/dim}}] {{pos}}/{{len}} chunks ({{eta}} remaining)"))
            .expect("invalid progress bar template")
            .progress_chars("=>-"),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(16));
    pb
}

/// Returns the plaintext byte count for a given chunk index.
fn chunk_pt_len(chunk_index: u64, chunk_size: u64, total_size: u64) -> usize {
    let start = chunk_index * chunk_size;
    (total_size.min(start + chunk_size) - start) as usize
}

pub fn encrypt(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
    cipher_type: CipherType,
    chunk_size: Option<u32>,
) -> Result<()> {
    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    if chunk_size == 0 {
        bail!("chunk size must be > 0");
    }

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut base_nonce);

    eprintln!("Deriving key with Argon2id (this may take a moment)...");
    let mut key = derive_key(password, &salt)?;
    let cipher = build_cipher(cipher_type, &key)?;
    zeroize_key(&mut key);

    let input_len = std::fs::metadata(input_path)
        .with_context(|| format!("cannot stat input: {}", input_path.display()))?
        .len();
    let num_chunks = Header::num_chunks(input_len, chunk_size);

    encrypt_with_cipher(input_path, output_path, &cipher, cipher_type, chunk_size, salt, base_nonce)?;

    eprintln!(
        "Encrypted {} → {} ({} chunks, {})",
        input_path.display(),
        output_path.display(),
        num_chunks,
        humanize_bytes(input_len),
    );
    Ok(())
}

/// Encrypt using a pre-built cipher. Skips Argon2 key derivation.
/// Each chunk is processed independently via pread/pwrite for fully
/// parallel I/O without memory-mapping.
pub fn encrypt_with_cipher(
    input_path: &Path,
    output_path: &Path,
    cipher: &Cipher,
    cipher_type: CipherType,
    chunk_size: u32,
    salt: [u8; SALT_LEN],
    base_nonce: [u8; NONCE_LEN],
) -> Result<()> {
    if chunk_size == 0 {
        bail!("chunk size must be > 0");
    }

    let input_file = File::open(input_path)
        .with_context(|| format!("cannot open input: {}", input_path.display()))?;
    let input_len = input_file.metadata()?.len();

    let cs = chunk_size as u64;
    let num_chunks = Header::num_chunks(input_len, chunk_size) as usize;
    let output_size = Header::output_size(input_len, chunk_size);
    let last_chunk_idx = (num_chunks - 1) as u64;
    let chunk_enc_size = cs + TAG_SIZE as u64;

    let header = Header::new(cipher_type, chunk_size, input_len, salt, base_nonce);
    let mut header_bytes = [0u8; HEADER_SIZE];
    header.serialize(&mut header_bytes);

    let output_file = OpenOptions::new()
        .read(true).write(true).create(true).truncate(true)
        .open(output_path)
        .with_context(|| format!("cannot create output: {}", output_path.display()))?;
    output_file.set_len(output_size)?;
    output_file.write_all_at(&header_bytes, 0)?;

    let pb = make_progress_bar(num_chunks as u64, "Encrypting");
    let failed = AtomicBool::new(false);

    (0..num_chunks).into_par_iter().for_each(|i| {
        if failed.load(Ordering::Relaxed) { return; }

        let global_i = i as u64;
        let pt_len = chunk_pt_len(global_i, cs, input_len);
        let mut buf = vec![0u8; pt_len + TAG_SIZE];

        // pread plaintext chunk from input
        if pt_len > 0 {
            let input_offset = global_i * cs;
            if input_file.read_exact_at(&mut buf[..pt_len], input_offset).is_err() {
                failed.store(true, Ordering::Relaxed);
                return;
            }
        }

        // Encrypt in-place, get detached tag
        let nonce_bytes = derive_nonce(&base_nonce, global_i);
        let is_final = global_i == last_chunk_idx;
        let aad = build_aad(&header_bytes, global_i, is_final);

        match cipher.encrypt_chunk(&nonce_bytes, &aad, &mut buf[..pt_len]) {
            Ok(tag) => buf[pt_len..pt_len + TAG_SIZE].copy_from_slice(&tag),
            Err(_) => { failed.store(true, Ordering::Relaxed); return; }
        }

        // pwrite ciphertext + tag to output
        let output_offset = HEADER_SIZE as u64 + global_i * chunk_enc_size;
        if output_file.write_all_at(&buf[..pt_len + TAG_SIZE], output_offset).is_err() {
            failed.store(true, Ordering::Relaxed);
        }

        pb.inc(1);
    });

    pb.finish_with_message("done");

    if failed.load(Ordering::Relaxed) {
        bail!("encryption failed on one or more chunks");
    }

    Ok(())
}

pub fn decrypt(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<()> {
    let input_file = File::open(input_path)
        .with_context(|| format!("cannot open input: {}", input_path.display()))?;
    let input_len = input_file.metadata()?.len();

    if input_len < HEADER_SIZE as u64 {
        bail!("file too small to be a valid Concryptor file");
    }

    let mut header_bytes = [0u8; HEADER_SIZE];
    input_file.read_exact_at(&mut header_bytes, 0)?;
    let header = Header::deserialize(&header_bytes)?;

    let expected = Header::output_size(header.original_size, header.chunk_size);
    if input_len != expected {
        bail!(
            "file size mismatch: expected {expected} bytes but got {input_len} \
             (file may be corrupted or truncated)"
        );
    }

    eprintln!("Deriving key with Argon2id (this may take a moment)...");
    let mut key = derive_key(password, &header.salt)?;
    let cipher = build_cipher(header.cipher, &key)?;
    zeroize_key(&mut key);

    let num_chunks = Header::num_chunks(header.original_size, header.chunk_size);

    decrypt_with_cipher(input_path, output_path, &cipher)?;

    eprintln!(
        "Decrypted {} → {} ({} chunks, {})",
        input_path.display(),
        output_path.display(),
        num_chunks,
        humanize_bytes(header.original_size),
    );
    Ok(())
}

/// Decrypt using a pre-built cipher. Skips Argon2 key derivation.
/// Reads header from the encrypted file to determine chunk layout,
/// then processes in batches with parallel decryption per batch.
pub fn decrypt_with_cipher(
    input_path: &Path,
    output_path: &Path,
    cipher: &Cipher,
) -> Result<()> {
    let input_file = File::open(input_path)
        .with_context(|| format!("cannot open input: {}", input_path.display()))?;
    let input_len = input_file.metadata()?.len();

    if input_len < HEADER_SIZE as u64 {
        bail!("file too small to be a valid Concryptor file");
    }

    // Read header via standard read (only 52 bytes)
    let mut header_bytes = [0u8; HEADER_SIZE];
    input_file.read_exact_at(&mut header_bytes, 0)?;
    let header = Header::deserialize(&header_bytes)?;

    let expected = Header::output_size(header.original_size, header.chunk_size);
    if input_len != expected {
        bail!(
            "file size mismatch: expected {expected} bytes but got {input_len} \
             (file may be corrupted or truncated)"
        );
    }

    let cs = header.chunk_size as u64;
    let num_chunks = Header::num_chunks(header.original_size, header.chunk_size) as usize;
    let last_chunk_idx = (num_chunks - 1) as u64;
    let chunk_enc_size = cs + TAG_SIZE as u64;

    let output_file = OpenOptions::new()
        .read(true).write(true).create(true).truncate(true)
        .open(output_path)
        .with_context(|| format!("cannot create output: {}", output_path.display()))?;
    output_file.set_len(header.original_size)?;

    let pb = make_progress_bar(num_chunks as u64, "Decrypting");
    let failed = AtomicBool::new(false);

    (0..num_chunks).into_par_iter().for_each(|i| {
        if failed.load(Ordering::Relaxed) { return; }

        let global_i = i as u64;
        let pt_len = chunk_pt_len(global_i, cs, header.original_size);
        let enc_len = pt_len + TAG_SIZE;
        let mut buf = vec![0u8; enc_len];

        // pread encrypted chunk (ciphertext || tag) from input
        let input_offset = HEADER_SIZE as u64 + global_i * chunk_enc_size;
        if input_file.read_exact_at(&mut buf, input_offset).is_err() {
            failed.store(true, Ordering::Relaxed);
            return;
        }

        // Decrypt in-place (ring expects ciphertext || tag)
        let nonce_bytes = derive_nonce(&header.base_nonce, global_i);
        let is_final = global_i == last_chunk_idx;
        let aad = build_aad(&header_bytes, global_i, is_final);

        if cipher.decrypt_chunk(&nonce_bytes, &aad, &mut buf).is_err() {
            failed.store(true, Ordering::Relaxed);
            return;
        }

        // pwrite plaintext to output (strip the tag)
        if pt_len > 0 {
            let output_offset = global_i * cs;
            if output_file.write_all_at(&buf[..pt_len], output_offset).is_err() {
                failed.store(true, Ordering::Relaxed);
            }
        }

        pb.inc(1);
    });

    pb.finish_with_message("done");

    if failed.load(Ordering::Relaxed) {
        bail!(
            "decryption failed: authentication error on one or more chunks. \
             Wrong password, or file has been tampered with."
        );
    }

    Ok(())
}

fn humanize_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return format!("{size:.1} {unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.1} PiB")
}
