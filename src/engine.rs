use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use io_uring::{IoUring, opcode, types};
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

/// Maximum buffer memory per io_uring batch (256 MiB).
const MAX_BATCH_BYTES: u64 = 256 * 1024 * 1024;

/// Number of pipeline stages for triple-buffering.
const PIPELINE_DEPTH: usize = 3;

fn compute_batch_cap(num_chunks: usize, chunk_size: u64) -> usize {
    let by_mem = (MAX_BATCH_BYTES / chunk_size.max(1)).max(1) as usize;
    // Ensure at least PIPELINE_DEPTH batches so the triple-buffer can overlap.
    let by_pipeline = (num_chunks + PIPELINE_DEPTH - 1) / PIPELINE_DEPTH;
    num_chunks.min(by_mem).min(by_pipeline).min(4096).max(1)
}

/// Drain CQEs, routing completions to per-slot counters via user_data tags.
/// Each SQE is tagged as `(TAG_READ|TAG_WRITE) | slot_index`.
/// Waits until `pending[target_slot]` reaches zero.
const TAG_READ: u64 = 0;
const TAG_WRITE: u64 = 1 << 32;
const TAG_MASK: u64 = 1 << 32;

fn drain_slot(
    ring: &mut IoUring,
    pending: &mut [usize; PIPELINE_DEPTH],
    target_slot: usize,
) -> Result<()> {
    while pending[target_slot] > 0 {
        ring.submit_and_wait(1)?;
        for cqe in ring.completion() {
            if cqe.result() < 0 {
                bail!(
                    "io_uring I/O error: {}",
                    std::io::Error::from_raw_os_error(-cqe.result())
                );
            }
            let slot = (cqe.user_data() & !TAG_MASK) as usize;
            if slot < PIPELINE_DEPTH {
                pending[slot] = pending[slot].saturating_sub(1);
            }
        }
    }
    Ok(())
}

/// Pre-allocated reusable buffer pool for one pipeline slot.
/// Each slot holds `batch_cap` chunk buffers of `buf_size` bytes each.
struct SlotPool {
    bufs: Vec<Vec<u8>>,
    count: usize,
}

impl SlotPool {
    fn new(count: usize, buf_size: usize) -> Self {
        let bufs = (0..count).map(|_| vec![0u8; buf_size]).collect();
        Self { bufs, count }
    }

    /// Reclaim all buffers for the next batch without reallocating.
    /// Only needed if the new batch has fewer chunks (the last batch).
    fn prepare(&mut self, needed: usize) {
        debug_assert!(needed <= self.count);
        // No alloc, no zeroing: we'll overwrite with io_uring reads anyway.
        let _ = needed;
    }
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
/// Uses a triple-buffered pipeline: while batch N's writes are in-flight
/// and batch N+2's reads are in-flight, batch N+1 is being encrypted by Rayon.
/// Buffers are pre-allocated once and reused across all batches.
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

    let mut output_file = OpenOptions::new()
        .read(true).write(true).create(true).truncate(true)
        .open(output_path)
        .with_context(|| format!("cannot create output: {}", output_path.display()))?;
    output_file.set_len(output_size)?;
    output_file.write_all(&header_bytes)?;

    let input_fd = types::Fd(input_file.as_raw_fd());
    let output_fd = types::Fd(output_file.as_raw_fd());
    let batch_cap = compute_batch_cap(num_chunks, cs);
    let buf_size = cs as usize + TAG_SIZE;

    // Pre-allocate buffer pools BEFORE the ring so they outlive it (no UAF).
    let mut slots: Vec<SlotPool> = (0..PIPELINE_DEPTH)
        .map(|_| SlotPool::new(batch_cap, buf_size))
        .collect();
    let mut ring = IoUring::new((batch_cap * 2) as u32)
        .context("failed to create io_uring instance")?;

    let pb = make_progress_bar(num_chunks as u64, "Encrypting");
    let num_batches = (num_chunks + batch_cap - 1) / batch_cap;

    // Per-slot pending CQE counters, routed via user_data tags.
    let mut pending: [usize; PIPELINE_DEPTH] = [0; PIPELINE_DEPTH];

    for step in 0..num_batches + 2 {
        let write_slot = step % PIPELINE_DEPTH;
        let crypto_slot = (step + 1) % PIPELINE_DEPTH;
        let read_slot = (step + 2) % PIPELINE_DEPTH;
        let read_batch = step;
        let crypto_batch = step.wrapping_sub(1);
        let write_batch = step.wrapping_sub(2);

        // 1. Wait for previous writes on write_slot to complete.
        if step >= 2 && write_batch < num_batches {
            drain_slot(&mut ring, &mut pending, write_slot)?;
            let ws = write_batch * batch_cap;
            let we = (ws + batch_cap).min(num_chunks);
            pb.inc((we - ws) as u64);
        }

        // 2. Submit reads for read_batch into read_slot.
        if read_batch < num_batches {
            let rs = read_batch * batch_cap;
            let re = (rs + batch_cap).min(num_chunks);
            slots[read_slot].prepare(re - rs);

            {
                let mut sq = ring.submission();
                for (j, i) in (rs..re).enumerate() {
                    let pt_len = chunk_pt_len(i as u64, cs, input_len);
                    if pt_len > 0 {
                        let sqe = opcode::Read::new(
                            input_fd,
                            slots[read_slot].bufs[j].as_mut_ptr(),
                            pt_len as u32,
                        )
                        .offset(i as u64 * cs)
                        .build()
                        .user_data(TAG_READ | read_slot as u64);
                        unsafe { sq.push(&sqe).expect("SQ full"); }
                        pending[read_slot] += 1;
                    }
                }
            }
            if pending[read_slot] > 0 {
                ring.submit()?;
            }
        }

        // 3. Wait for reads on crypto_slot, then encrypt in parallel.
        if step >= 1 && crypto_batch < num_batches {
            drain_slot(&mut ring, &mut pending, crypto_slot)?;

            let cs_start = crypto_batch * batch_cap;
            let cs_end = (cs_start + batch_cap).min(num_chunks);
            let batch_len = cs_end - cs_start;

            slots[crypto_slot].bufs[..batch_len]
                .par_iter_mut()
                .enumerate()
                .try_for_each(|(j, buf)| -> Result<()> {
                    let i = (cs_start + j) as u64;
                    let pt_len = chunk_pt_len(i, cs, input_len);
                    let nonce = derive_nonce(&base_nonce, i);
                    let is_final = i == last_chunk_idx;
                    let aad = build_aad(&header_bytes, i, is_final);
                    let tag = cipher.encrypt_chunk(&nonce, &aad, &mut buf[..pt_len])?;
                    buf[pt_len..pt_len + TAG_SIZE].copy_from_slice(&tag);
                    Ok(())
                })?;

            // Submit writes for the just-encrypted batch.
            {
                let mut sq = ring.submission();
                for (j, i) in (cs_start..cs_end).enumerate() {
                    let write_len = (chunk_pt_len(i as u64, cs, input_len) + TAG_SIZE) as u32;
                    let out_off = HEADER_SIZE as u64 + i as u64 * chunk_enc_size;
                    let sqe = opcode::Write::new(
                        output_fd,
                        slots[crypto_slot].bufs[j].as_ptr(),
                        write_len,
                    )
                    .offset(out_off)
                    .build()
                    .user_data(TAG_WRITE | crypto_slot as u64);
                    unsafe { sq.push(&sqe).expect("SQ full"); }
                    pending[crypto_slot] += 1;
                }
            }
            ring.submit()?;
        }
    }

    pb.finish_with_message("done");
    drop(ring);
    drop(slots);
    Ok(())
}

pub fn decrypt(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<()> {
    let mut input_file = File::open(input_path)
        .with_context(|| format!("cannot open input: {}", input_path.display()))?;
    let input_len = input_file.metadata()?.len();

    if input_len < HEADER_SIZE as u64 {
        bail!("file too small to be a valid Concryptor file");
    }

    let mut header_bytes = [0u8; HEADER_SIZE];
    input_file.read_exact(&mut header_bytes)?;
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
/// Uses a triple-buffered pipeline: overlapped io_uring reads/writes
/// with parallel Rayon decryption. Buffers pre-allocated once.
pub fn decrypt_with_cipher(
    input_path: &Path,
    output_path: &Path,
    cipher: &Cipher,
) -> Result<()> {
    let mut input_file = File::open(input_path)
        .with_context(|| format!("cannot open input: {}", input_path.display()))?;
    let input_len = input_file.metadata()?.len();

    if input_len < HEADER_SIZE as u64 {
        bail!("file too small to be a valid Concryptor file");
    }

    let mut header_bytes = [0u8; HEADER_SIZE];
    input_file.read_exact(&mut header_bytes)?;
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

    let input_fd = types::Fd(input_file.as_raw_fd());
    let output_fd = types::Fd(output_file.as_raw_fd());
    let batch_cap = compute_batch_cap(num_chunks, cs);
    let buf_size = cs as usize + TAG_SIZE;

    let mut slots: Vec<SlotPool> = (0..PIPELINE_DEPTH)
        .map(|_| SlotPool::new(batch_cap, buf_size))
        .collect();
    let mut ring = IoUring::new((batch_cap * 2) as u32)
        .context("failed to create io_uring instance")?;

    let pb = make_progress_bar(num_chunks as u64, "Decrypting");
    let num_batches = (num_chunks + batch_cap - 1) / batch_cap;

    let mut pending: [usize; PIPELINE_DEPTH] = [0; PIPELINE_DEPTH];

    for step in 0..num_batches + 2 {
        let write_slot = step % PIPELINE_DEPTH;
        let crypto_slot = (step + 1) % PIPELINE_DEPTH;
        let read_slot = (step + 2) % PIPELINE_DEPTH;
        let read_batch = step;
        let crypto_batch = step.wrapping_sub(1);
        let write_batch = step.wrapping_sub(2);

        // 1. Drain writes from the oldest slot.
        if step >= 2 && write_batch < num_batches {
            drain_slot(&mut ring, &mut pending, write_slot)?;
            let ws = write_batch * batch_cap;
            let we = (ws + batch_cap).min(num_chunks);
            pb.inc((we - ws) as u64);
        }

        // 2. Submit reads for read_batch into read_slot.
        if read_batch < num_batches {
            let rs = read_batch * batch_cap;
            let re = (rs + batch_cap).min(num_chunks);
            slots[read_slot].prepare(re - rs);

            {
                let mut sq = ring.submission();
                for (j, i) in (rs..re).enumerate() {
                    let enc_len = (chunk_pt_len(i as u64, cs, header.original_size) + TAG_SIZE) as u32;
                    let in_off = HEADER_SIZE as u64 + i as u64 * chunk_enc_size;
                    let sqe = opcode::Read::new(
                        input_fd,
                        slots[read_slot].bufs[j].as_mut_ptr(),
                        enc_len,
                    )
                    .offset(in_off)
                    .build()
                    .user_data(TAG_READ | read_slot as u64);
                    unsafe { sq.push(&sqe).expect("SQ full"); }
                    pending[read_slot] += 1;
                }
            }
            ring.submit()?;
        }

        // 3. Wait for reads on crypto_slot, decrypt, submit writes.
        if step >= 1 && crypto_batch < num_batches {
            drain_slot(&mut ring, &mut pending, crypto_slot)?;

            let cs_start = crypto_batch * batch_cap;
            let cs_end = (cs_start + batch_cap).min(num_chunks);
            let batch_len = cs_end - cs_start;

            slots[crypto_slot].bufs[..batch_len]
                .par_iter_mut()
                .enumerate()
                .try_for_each(|(j, buf)| {
                    let i = (cs_start + j) as u64;
                    let pt_len = chunk_pt_len(i, cs, header.original_size);
                    let nonce = derive_nonce(&header.base_nonce, i);
                    let is_final = i == last_chunk_idx;
                    let aad = build_aad(&header_bytes, i, is_final);
                    cipher.decrypt_chunk(&nonce, &aad, &mut buf[..pt_len + TAG_SIZE])
                })?;

            // Submit writes for plaintext.
            {
                let mut sq = ring.submission();
                for (j, i) in (cs_start..cs_end).enumerate() {
                    let pt_len = chunk_pt_len(i as u64, cs, header.original_size);
                    if pt_len > 0 {
                        let out_off = i as u64 * cs;
                        let sqe = opcode::Write::new(
                            output_fd,
                            slots[crypto_slot].bufs[j].as_ptr(),
                            pt_len as u32,
                        )
                        .offset(out_off)
                        .build()
                        .user_data(TAG_WRITE | crypto_slot as u64);
                        unsafe { sq.push(&sqe).expect("SQ full"); }
                        pending[crypto_slot] += 1;
                    }
                }
            }
            if pending[crypto_slot] > 0 {
                ring.submit()?;
            }
        }
    }

    pb.finish_with_message("done");
    drop(ring);
    drop(slots);
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
