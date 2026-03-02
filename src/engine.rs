use std::alloc;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use anyhow::{bail, Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use io_uring::{IoUring, opcode, types};
use rand::RngCore;
use rayon::prelude::*;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

use crate::crypto::{derive_key, derive_nonce, zeroize_key};
use crate::header::{
    aligned_chunk_disk_size, CipherType, Header, KdfParams, ALIGNED_HEADER_SIZE, HEADER_SIZE,
    NONCE_LEN, SALT_LEN, SECTOR_SIZE, TAG_SIZE,
};

pub const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024; // 4 MiB

/// Builds the per-chunk AAD: header || chunk_index (8 LE) || is_final (1).
///
/// v4+: the full 4 KiB aligned header is included, authenticating core fields,
/// KDF parameters, and reserved padding in every chunk's tag.
/// v3 (legacy): only the 52-byte core header was included.
fn build_aad(header_bytes: &[u8], chunk_index: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header_bytes.len() + 9);
    aad.extend_from_slice(header_bytes);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.push(u8::from(is_final));
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
/// Each SQE's user_data is packed as: bits[1:0]=slot, bit[2]=read/write tag,
/// bits[63:3]=expected byte count. This lets us detect short reads/writes.
const SLOT_MASK: u64 = 0b11;
const TAG_BIT: u64 = 1 << 2;
const SIZE_SHIFT: u32 = 3;

/// Pack slot index, read/write tag, and expected byte count into user_data.
#[inline]
fn pack_user_data(slot: usize, is_write: bool, expected_bytes: u32) -> u64 {
    (slot as u64 & SLOT_MASK)
        | if is_write { TAG_BIT } else { 0 }
        | ((expected_bytes as u64) << SIZE_SHIFT)
}

/// Unpack slot index and expected byte count from user_data.
#[inline]
fn unpack_user_data(ud: u64) -> (usize, u32) {
    let slot = (ud & SLOT_MASK) as usize;
    let expected = (ud >> SIZE_SHIFT) as u32;
    (slot, expected)
}

fn drain_slot(
    ring: &mut IoUring,
    pending: &mut [usize; PIPELINE_DEPTH],
    target_slot: usize,
) -> Result<()> {
    while pending[target_slot] > 0 {
        ring.submit_and_wait(1)?;
        for cqe in ring.completion() {
            let result = cqe.result();
            if result < 0 {
                bail!(
                    "io_uring I/O error: {}",
                    std::io::Error::from_raw_os_error(-result)
                );
            }
            let (slot, expected) = unpack_user_data(cqe.user_data());
            if (result as u32) != expected {
                bail!(
                    "io_uring short I/O: expected {expected} bytes, got {result} \
                     (possible hardware error or unsupported filesystem)"
                );
            }
            if slot < PIPELINE_DEPTH {
                pending[slot] = pending[slot].saturating_sub(1);
            }
        }
    }
    Ok(())
}

/// 4096-byte aligned buffer for O_DIRECT I/O.
/// Allocated via `std::alloc` with `Layout::from_size_align(len, SECTOR_SIZE)`.
struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
    layout: alloc::Layout,
}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        assert!(len > 0 && len % SECTOR_SIZE == 0);
        let layout = alloc::Layout::from_size_align(len, SECTOR_SIZE).unwrap();
        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }
        Self { ptr, len, layout }
    }

    fn as_mut_ptr(&self) -> *mut u8 { self.ptr }
    fn as_ptr(&self) -> *const u8 { self.ptr }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        unsafe { alloc::dealloc(self.ptr, self.layout); }
    }
}

impl std::ops::Deref for AlignedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl std::ops::DerefMut for AlignedBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

// SAFETY: raw memory with no interior references; access synchronized via io_uring CQE drain.
unsafe impl Send for AlignedBuf {}
unsafe impl Sync for AlignedBuf {}

fn pwrite_aligned(fd: i32, buf: &[u8], offset: i64) -> Result<()> {
    let n = unsafe { libc::pwrite(fd, buf.as_ptr().cast(), buf.len(), offset) };
    if n < 0 {
        bail!("pwrite: {}", std::io::Error::last_os_error());
    }
    if n as usize != buf.len() {
        bail!("short pwrite: {} of {} bytes", n, buf.len());
    }
    Ok(())
}

fn pread_aligned(fd: i32, buf: &mut [u8], offset: i64) -> Result<()> {
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), buf.len(), offset) };
    if n < 0 {
        bail!("pread: {}", std::io::Error::last_os_error());
    }
    if n as usize != buf.len() {
        bail!("short pread: {} of {} bytes", n, buf.len());
    }
    Ok(())
}

/// Pre-allocated reusable buffer pool for one pipeline slot.
/// Each slot holds `batch_cap` chunk buffers of `buf_size` bytes each.
struct SlotPool {
    bufs: Vec<AlignedBuf>,
    count: usize,
}

impl SlotPool {
    fn new(count: usize, buf_size: usize) -> Self {
        let bufs = (0..count).map(|_| AlignedBuf::new(buf_size)).collect();
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
    kdf_params: &KdfParams,
) -> Result<()> {
    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    if chunk_size == 0 {
        bail!("chunk size must be > 0");
    }

    let mut salt = [0u8; SALT_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut base_nonce);

    eprintln!("Deriving key with Argon2id ({} MiB, {} iterations)...", kdf_params.m_cost / 1024, kdf_params.t_cost);
    let mut key = derive_key(password, &salt, kdf_params)?;
    let cipher = build_cipher(cipher_type, &key)?;
    zeroize_key(&mut key);

    let input_len = std::fs::metadata(input_path)
        .with_context(|| format!("cannot stat input: {}", input_path.display()))?
        .len();
    let num_chunks = Header::num_chunks(input_len, chunk_size);

    encrypt_with_cipher(input_path, output_path, &cipher, cipher_type, chunk_size, salt, base_nonce, kdf_params)?;

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
    kdf_params: &KdfParams,
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
    let disk_chunk = aligned_chunk_disk_size(chunk_size);

    let header = Header::new(cipher_type, chunk_size, input_len, salt, base_nonce);
    let mut header_bytes = [0u8; HEADER_SIZE];
    header.serialize(&mut header_bytes);

    let output_file = OpenOptions::new()
        .read(true).write(true).create(true).truncate(true)
        .custom_flags(libc::O_DIRECT)
        .mode(0o600)
        .open(output_path)
        .with_context(|| format!("cannot create output: {}", output_path.display()))?;
    output_file.set_len(output_size)?;
    // Write the 4 KiB aligned header (52 bytes data + KDF params + zero padding).
    let mut aligned_hdr = AlignedBuf::new(ALIGNED_HEADER_SIZE);
    aligned_hdr[..HEADER_SIZE].copy_from_slice(&header_bytes);
    kdf_params.write_to_aligned(&mut aligned_hdr);
    pwrite_aligned(output_file.as_raw_fd(), &aligned_hdr, 0)?;

    let input_fd = types::Fd(input_file.as_raw_fd());
    let output_fd = types::Fd(output_file.as_raw_fd());
    let batch_cap = compute_batch_cap(num_chunks, disk_chunk);
    let buf_size = disk_chunk as usize;

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
                        .user_data(pack_user_data(read_slot, false, pt_len as u32));
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
                    let aad = build_aad(&aligned_hdr[..], i, is_final);
                    let tag = cipher.encrypt_chunk(&nonce, &aad, &mut buf[..pt_len])?;
                    buf[pt_len..pt_len + TAG_SIZE].copy_from_slice(&tag);
                    // Zero padding for O_DIRECT sector alignment.
                    buf[pt_len + TAG_SIZE..].fill(0);
                    Ok(())
                })?;

            // Submit writes for the just-encrypted batch.
            {
                let mut sq = ring.submission();
                for (j, i) in (cs_start..cs_end).enumerate() {
                    let out_off = ALIGNED_HEADER_SIZE as u64 + i as u64 * disk_chunk;
                    let sqe = opcode::Write::new(
                        output_fd,
                        slots[crypto_slot].bufs[j].as_ptr(),
                        disk_chunk as u32,
                    )
                    .offset(out_off)
                    .build()
                    .user_data(pack_user_data(crypto_slot, true, disk_chunk as u32));
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
    let input_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(input_path)
        .with_context(|| format!("cannot open input: {}", input_path.display()))?;
    let input_len = input_file.metadata()?.len();

    if input_len < ALIGNED_HEADER_SIZE as u64 {
        bail!("file too small to be a valid Concryptor file");
    }

    let mut aligned_hdr = AlignedBuf::new(ALIGNED_HEADER_SIZE);
    pread_aligned(input_file.as_raw_fd(), &mut aligned_hdr, 0)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    header_bytes.copy_from_slice(&aligned_hdr[..HEADER_SIZE]);
    let header = Header::deserialize(&header_bytes)?;
    let kdf_params = KdfParams::read_from_aligned(&aligned_hdr);

    let expected = Header::output_size(header.original_size, header.chunk_size);
    if input_len != expected {
        bail!(
            "file size mismatch: expected {expected} bytes but got {input_len} \
             (file may be corrupted or truncated)"
        );
    }

    eprintln!("Deriving key with Argon2id ({} MiB, {} iterations)...", kdf_params.m_cost / 1024, kdf_params.t_cost);
    let mut key = derive_key(password, &header.salt, &kdf_params)?;
    let cipher = build_cipher(header.cipher, &key)?;
    zeroize_key(&mut key);

    let num_chunks = Header::num_chunks(header.original_size, header.chunk_size);

    let result = decrypt_with_cipher(input_path, output_path, &cipher);
    if result.is_err() {
        let _ = std::fs::remove_file(output_path);
    }
    result?;

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
    let input_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(input_path)
        .with_context(|| format!("cannot open input: {}", input_path.display()))?;
    let input_len = input_file.metadata()?.len();

    if input_len < ALIGNED_HEADER_SIZE as u64 {
        bail!("file too small to be a valid Concryptor file");
    }

    let mut aligned_hdr = AlignedBuf::new(ALIGNED_HEADER_SIZE);
    pread_aligned(input_file.as_raw_fd(), &mut aligned_hdr, 0)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    header_bytes.copy_from_slice(&aligned_hdr[..HEADER_SIZE]);
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
    let disk_chunk = aligned_chunk_disk_size(header.chunk_size);

    let output_file = OpenOptions::new()
        .read(true).write(true).create(true).truncate(true)
        .mode(0o600)
        .open(output_path)
        .with_context(|| format!("cannot create output: {}", output_path.display()))?;
    output_file.set_len(header.original_size)?;

    // v4: full 4 KiB header in AAD (authenticates all header bytes).
    // v3: only the 52-byte core header (legacy).
    let aad_header: &[u8] = if header.version >= 4 {
        &aligned_hdr[..]
    } else {
        &header_bytes[..]
    };

    let result = decrypt_pipeline(
        &input_file, &output_file, cipher, aad_header, &header, num_chunks,
        last_chunk_idx, cs, disk_chunk,
    );

    if result.is_err() {
        drop(output_file);
        let _ = std::fs::remove_file(output_path);
    }
    result
}

/// Inner pipeline for decryption, factored out so the caller can clean up on error.
fn decrypt_pipeline(
    input_file: &File,
    output_file: &File,
    cipher: &Cipher,
    aad_header: &[u8],
    header: &Header,
    num_chunks: usize,
    last_chunk_idx: u64,
    cs: u64,
    disk_chunk: u64,
) -> Result<()> {
    let input_fd = types::Fd(input_file.as_raw_fd());
    let output_fd = types::Fd(output_file.as_raw_fd());
    let batch_cap = compute_batch_cap(num_chunks, disk_chunk);
    let buf_size = disk_chunk as usize;

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
                    let in_off = ALIGNED_HEADER_SIZE as u64 + i as u64 * disk_chunk;
                    let sqe = opcode::Read::new(
                        input_fd,
                        slots[read_slot].bufs[j].as_mut_ptr(),
                        disk_chunk as u32,
                    )
                    .offset(in_off)
                    .build()
                    .user_data(pack_user_data(read_slot, false, disk_chunk as u32));
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
                    let aad = build_aad(aad_header, i, is_final);
                    cipher.decrypt_chunk(&nonce, &aad, &mut buf[..pt_len + TAG_SIZE])?;
                    // Verify sector-alignment padding is untampered.
                    if buf[pt_len + TAG_SIZE..].iter().any(|&b| b != 0) {
                        bail!("tampered padding in chunk {i}");
                    }
                    Ok(())
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
                        .user_data(pack_user_data(crypto_slot, true, pt_len as u32));
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
