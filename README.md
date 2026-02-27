# Concryptor

A multi-threaded AEAD encryption engine built in Rust. Encrypts and decrypts files at gigabyte-per-second throughput using a triple-buffered `io_uring` pipeline, parallel chunk processing via Rayon, and assembly-optimized ciphers via `ring`.

## Features

- **Dual cipher support**: AES-256-GCM (hardware AES-NI) and ChaCha20-Poly1305 via `ring` (assembly-optimized)
- **Parallel encryption**: Rayon-based multi-threaded chunk processing across all CPU cores
- **Triple-buffered io_uring pipeline**: Overlaps kernel I/O and CPU-side crypto using three rotating buffer pools — while one batch's writes are in-flight, the next batch is being encrypted by Rayon, and the third batch's reads are in-flight. No syscall-per-chunk overhead, no mmap limitations (no SIGBUS, no virtual address space exhaustion)
- **Argon2id key derivation**: Industry-standard password-to-key stretching (default 256 MiB memory, 3 iterations, configurable via `--memory`)
- **Self-describing KDF parameters**: Memory cost, iterations, and parallelism are stored in the encrypted file header so decryption uses exactly the parameters that were chosen at encryption time. Legacy files (all-zero sentinel) are handled transparently with the old 64 MiB defaults
- **Chunk-indexed nonces**: TLS 1.3-style XOR nonce derivation prevents chunk reordering attacks
- **Header-authenticated AAD**: The full serialized header is included in every chunk's AAD, preventing truncation and header-field manipulation attacks
- **STREAM-style final chunk**: A final-chunk flag in the AAD prevents truncation and append attacks (inspired by the STREAM construction)
- **Fresh randomness per file**: Cryptographically random 16-byte salt and 12-byte base nonce are generated for every encryption, stored in the header
- **In-place encryption**: `seal_in_place_separate_tag` / `open_in_place` via `ring` minimizes allocation in the hot loop
- **Password zeroization**: Keys and passwords are securely wiped from memory after use
- **O_DIRECT + sector-aligned format (v3)**: 4 KiB-aligned header and chunk slots enable `O_DIRECT` I/O, bypassing the kernel page cache for DMA-speed reads/writes on NVMe. Buffer pools use `std::alloc` with 4096-byte alignment
- **Self-describing file format (v3)**: Header stores cipher, chunk size, original file size, salt, base nonce, and Argon2id KDF parameters

## Performance

Benchmarked with `cargo bench` (Criterion, 10 samples per measurement). Key derivation is excluded - numbers reflect pure crypto throughput only.

**Hardware:**
- CPU: AMD Ryzen 5 5600X (6c/12t @ 3.7 GHz base)
- RAM: 2x 8 GiB DDR4-2666 (dual channel, 16 GiB total)
- OS: Linux

**Note on I/O:** Criterion writes temporary files to `/tmp`, which on this system is `tmpfs` (RAM-backed). With `O_DIRECT`, the kernel cannot use real asynchronous DMA on tmpfs, so these numbers reflect cipher throughput + io_uring overhead **without the DMA bypass benefit**. On a real Gen4 NVMe drive, `O_DIRECT` eliminates page-cache double-buffering and enables DMA straight into the aligned buffer pools, which should yield significantly higher throughput.

| File Size | AES-256-GCM Encrypt | ChaCha20 Encrypt | AES-256-GCM Decrypt | ChaCha20 Decrypt |
|-----------|--------------------:|------------------:|--------------------:|-----------------:|
| 64 KiB    |        244 MiB/s    |      233 MiB/s    |        233 MiB/s    |      234 MiB/s   |
| 1 MiB     |       1.08 GiB/s    |      882 MiB/s    |     1010 MiB/s      |      876 MiB/s   |
| 16 MiB    |       1.10 GiB/s    |      923 MiB/s    |       1.06 GiB/s    |      988 MiB/s   |
| 64 MiB    |        984 MiB/s    |      935 MiB/s    |        988 MiB/s    |      973 MiB/s   |
| 256 MiB   |       1.00 GiB/s    |     1015 MiB/s    |       1.01 GiB/s    |     1.02 GiB/s   |

Chunk size sweep (AES-256-GCM, 64 MiB file):

| Chunk Size | Throughput |
|------------|----------:|
| 64 KiB     | 1.01 GiB/s |
| 256 KiB    | 1.05 GiB/s |
| 1 MiB      | 1.07 GiB/s |
| 4 MiB      |  988 MiB/s |
| 8 MiB      |  988 MiB/s |
| 16 MiB     | 1.00 GiB/s |

### Performance characteristics

The engine uses `ring` (assembly-optimized AES-NI / NEON / ARMv8-CE) for cipher operations and a triple-buffered `io_uring` pipeline for I/O. Three pre-allocated buffer pools rotate through the pipeline: while pool A's writes are completing in the kernel, pool B is being encrypted by Rayon on the CPU, and pool C's reads are being submitted to the kernel. This overlaps I/O latency with crypto computation.

**Why AES-256-GCM is faster than ChaCha20-Poly1305 on small files:**
`ring`'s AES-GCM backend exploits AES-NI + CLMUL hardware instructions available on x86-64, giving it a hardware advantage over ChaCha20 (which is a software cipher). At larger sizes both ciphers converge to ~1.0 GiB/s, indicating the bottleneck shifts from cipher throughput to I/O submission overhead.

**Why peak throughput is at 1-16 MiB, not 256 MiB:**
Small files (1-16 MiB) have few chunks, so Rayon parallelism is efficient and the working set fits in cache. At 64-256 MiB, the io_uring pipeline is fully active (three batches in flight), but the per-SQE submission and CQE completion overhead scales with chunk count. The triple-buffer design ensures I/O and crypto overlap, partially hiding this cost.

**Why ~1.0 GiB/s and not 10+ GiB/s:**
Modern AES-NI can push 2-4 GiB/s *per core*. With 12 threads, raw cipher throughput could exceed 10 GiB/s. Three factors explain the gap:

1. **io_uring per-SQE overhead**: Each chunk requires a read SQE and a write SQE. With 256 chunks for a 256 MiB file, that's 512 SQEs submitted and 512 CQEs reaped. While io_uring avoids the per-syscall kernel transition cost of pread/pwrite, it still has ring-buffer and memory-barrier overhead per SQE.
2. **Pipeline depth**: With `PIPELINE_DEPTH=3`, only three batches rotate through the pipeline at any time. True steady-state overlap requires at least three batches; files that fit in one or two batches don't benefit from pipelining.
3. **Cache hierarchy effects**: The 5600X has 512 KiB L2 per core and 32 MiB shared L3. The default 4 MiB chunk exceeds L2, and a batch of ~21 chunks (84 MiB active working set) far exceeds L3. Smaller chunk sizes (64-256 KiB) show better throughput in the chunk sweep because more of the working set stays in cache.

**Buffer lifecycle and safety:**
Buffer pools are allocated once via `std::alloc::alloc_zeroed` with `Layout::from_size_align(size, 4096)` before the io_uring ring is created, and are reused across all pipeline iterations without reallocation. Each encrypted chunk is zero-padded to sector alignment before the O_DIRECT write. The ring is explicitly dropped before the buffer pools, ensuring the kernel never references freed memory (no UAF).

## Installation

```bash
git clone https://github.com/youruser/concryptor.git
cd concryptor
cargo build --release
```

The binary will be at `target/release/concryptor`.

## Usage

### Encrypt

```bash
# AES-256-GCM (default), output to myfile.dat.enc
concryptor encrypt myfile.dat

# ChaCha20-Poly1305, custom output path
concryptor encrypt myfile.dat --cipher chacha -o encrypted.enc

# Custom chunk size (in MiB)
concryptor encrypt largefile.iso --chunk-size 8

# Stronger KDF (512 MiB memory cost)
concryptor encrypt secrets.tar --memory 512
```

### Decrypt

```bash
# Auto-strips .enc extension
concryptor decrypt myfile.dat.enc

# Custom output path
concryptor decrypt encrypted.enc -o restored.dat
```

### Help

```bash
concryptor --help
concryptor encrypt --help
concryptor decrypt --help
```

## File Format (v3: Aligned)

All values are little-endian. The header occupies a full 4 KiB sector; each encrypted chunk slot is padded to the next 4 KiB boundary. This ensures every offset and I/O size is sector-aligned for `O_DIRECT`.

```
Offset  Size   Field
------  -----  ---------------------
0       10     Magic bytes "CONCRYPTOR"
10       1     Format version (3)
11       1     Cipher type (0 = AES-256-GCM, 1 = ChaCha20-Poly1305)
12       4     Chunk size (bytes, LE)
16       8     Original file size (bytes, LE)
24      16     Argon2 salt (cryptographically random, unique per file)
40      12     Base nonce (cryptographically random, unique per file)
52       4     Argon2 m_cost in KiB (LE, 0 = legacy 64 MiB)
56       4     Argon2 t_cost / iterations (LE, 0 = legacy 3)
60       4     Argon2 p_cost / parallelism (LE, 0 = legacy 4)
64    4032     Reserved (zero-padded to 4096 bytes)
4096    ...    [Chunk 0: ciphertext + 16-byte tag + zero padding to sector boundary]
               [Chunk 1: ciphertext + 16-byte tag + zero padding to sector boundary]
               ...
```

For 4 MiB chunks: each disk slot is `ceil((4194304 + 16) / 4096) * 4096 = 4198400` bytes (4080 bytes of padding per chunk). The 4032 reserved bytes in the header are available for future features (asymmetric key slots, metadata, etc.).

The salt and base nonce are generated fresh from `rand::thread_rng()` (backed by the OS CSPRNG) on every encryption. Reusing a password across files is safe because different salts produce different Argon2id keys, and different base nonces produce different per-chunk nonces.

## Security Design

- **Nonce derivation**: `chunk_nonce = base_nonce XOR chunk_index` (TLS 1.3 style). Swapping chunks causes decryption failure because the nonce at position N won't match the nonce used to encrypt the chunk originally at position M.
- **Header-authenticated AAD**: Every chunk's AEAD call uses `AAD = header_bytes (52) || chunk_index (8 LE) || is_final (1)` (61 bytes total). The full serialized header is bound into every chunk's authentication tag. Modifying *any* header field (cipher type, chunk size, original size, salt, nonce) invalidates all chunks. This prevents truncation attacks where an adversary edits `original_size` and removes trailing chunks.
- **STREAM-style final chunk indicator**: The last byte of the AAD is `0x01` for the final chunk and `0x00` for all others. This prevents two attacks:
  - **Truncation**: Removing the final chunk and promoting a non-final chunk to the end fails because the non-final chunk was encrypted with `is_final = 0x00` but decryption expects `0x01`.
  - **Extension**: Appending forged chunks fails because the attacker cannot produce a valid tag for `is_final = 0x01` without the key.
- **Fresh randomness per file**: A 16-byte salt and 12-byte base nonce are drawn from the OS CSPRNG (`rand::thread_rng()`) for every encryption. Two encryptions of the same file with the same password produce completely different ciphertext. Nonce reuse (which is catastrophic for AES-GCM) is avoided by construction.
- **Key derivation**: Argon2id with configurable memory cost (default 256 MiB, tunable via `--memory`), 3 time iterations, parallelism of 4. The 256 MiB default is 4× the OWASP minimum and expensive for GPU/FPGA/ASIC attackers. KDF parameters are stored in the file header (bytes 52-63), making files self-describing — decryption always uses the correct parameters regardless of current defaults. If bytes 52-63 are all zero (legacy pre-KDF-params files), the old 64 MiB / 3 / 4 defaults are applied.
- **Zeroization**: Encryption keys are zeroized immediately after cipher construction. Passwords are zeroized after use.

## Testing

```bash
# Run the full test suite (40 tests)
cargo test

# Run benchmarks (HTML reports in target/criterion/)
cargo bench

# Filter benchmarks
cargo bench -- "encrypt/AES"
cargo bench -- "chunk_sweep"
```

The test suite covers:
- Header serialization/deserialization roundtrips
- Key derivation determinism and sensitivity
- Nonce uniqueness and identity properties
- Encrypt/decrypt roundtrips for both ciphers across file sizes (empty, 1 byte, boundary cases, multi-chunk)
- Wrong password rejection
- Tamper detection (flipped ciphertext, corrupted tags, corrupted salt, truncated files)
- Chunk reorder attack detection
- Cipher type mismatch detection
- **Truncation attack detection** (modified `original_size` + removed chunks)
- **Header field manipulation detection** (modified `chunk_size`)
- Non-deterministic encryption verification
- Stress test with 256 small chunks

## Dependencies

| Crate | Purpose |
|-------|---------|
| `ring` | Assembly-optimized AES-256-GCM and ChaCha20-Poly1305 AEAD |
| `io-uring` | Linux io_uring interface for async read/write I/O |
| `libc` | O_DIRECT flag and aligned pread/pwrite for header I/O |
| `argon2` | Argon2id key derivation |
| `rayon` | Data-parallel chunk processing |
| `clap` | CLI argument parsing |
| `indicatif` | Terminal progress bar |
| `rand` | Cryptographic random number generation |
| `zeroize` | Secure memory wiping |
| `anyhow` | Error handling |
| `rpassword` | Hidden password input |

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
