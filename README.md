# Concryptor

A multi-threaded AEAD encryption engine built in Rust. Encrypts and decrypts files at gigabyte-per-second throughput using parallel chunk processing, `pread`/`pwrite` I/O, and assembly-optimized ciphers via `ring`.

## Features

- **Dual cipher support**: AES-256-GCM (hardware AES-NI) and ChaCha20-Poly1305 via `ring` (assembly-optimized)
- **Parallel encryption**: Rayon-based multi-threaded chunk processing across all CPU cores
- **Parallel I/O**: Each thread independently reads and writes at offsets via `pread`/`pwrite`, with no memory-mapping or mmap-related limitations (no SIGBUS, no virtual address space exhaustion for large files)
- **Argon2id key derivation**: Industry-standard password-to-key stretching (64 MiB memory, 3 iterations)
- **Chunk-indexed nonces**: TLS 1.3-style XOR nonce derivation prevents chunk reordering attacks
- **Header-authenticated AAD**: The full serialized header is included in every chunk's AAD, preventing truncation and header-field manipulation attacks
- **STREAM-style final chunk**: A final-chunk flag in the AAD prevents truncation and append attacks (inspired by the STREAM construction)
- **Fresh randomness per file**: Cryptographically random 16-byte salt and 12-byte base nonce are generated for every encryption, stored in the header
- **In-place encryption**: `seal_in_place_separate_tag` / `open_in_place` via `ring` minimizes allocation in the hot loop
- **Password zeroization**: Keys and passwords are securely wiped from memory after use
- **Self-describing file format (v2)**: Header stores cipher, chunk size, original file size, salt, and base nonce

## Performance

Benchmarked with `cargo bench` (Criterion, 10 samples per measurement). Key derivation is excluded - numbers reflect pure crypto throughput only.

**Hardware:**
- CPU: AMD Ryzen 5 5600X (6c/12t @ 3.7 GHz base)
- RAM: 2x 8 GiB DDR4-2666 (dual channel, 16 GiB total)
- OS: Linux

**Note on I/O:** Criterion writes temporary files to `/tmp`, which on this system is `tmpfs` (RAM-backed). Benchmark files never touch a physical disk, so results reflect cipher throughput + `pread`/`pwrite` syscall overhead, not storage bandwidth. DDR4-2666 dual-channel theoretical peak is ~40 GB/s, so memory bandwidth is not the bottleneck.

| File Size | AES-256-GCM Encrypt | ChaCha20 Encrypt | AES-256-GCM Decrypt | ChaCha20 Decrypt |
|-----------|--------------------:|------------------:|--------------------:|-----------------:|
| 64 KiB    |        780 MiB/s    |      692 MiB/s    |        835 MiB/s    |      694 MiB/s   |
| 1 MiB     |       1.50 GiB/s    |     1.14 GiB/s    |       1.53 GiB/s    |     1.13 GiB/s   |
| 16 MiB    |       1.27 GiB/s    |     1.20 GiB/s    |       1.28 GiB/s    |     1.22 GiB/s   |
| 64 MiB    |       1.14 GiB/s    |     1.14 GiB/s    |       1.15 GiB/s    |     1.14 GiB/s   |
| 256 MiB   |       1.32 GiB/s    |     1.32 GiB/s    |       1.34 GiB/s    |     1.30 GiB/s   |

Chunk size sweep (AES-256-GCM, 64 MiB file):

| Chunk Size | Throughput |
|------------|----------:|
| 64 KiB     | 2.05 GiB/s |
| 256 KiB    | 1.98 GiB/s |
| 1 MiB      | 1.72 GiB/s |
| 4 MiB      | 1.12 GiB/s |
| 8 MiB      | 1.02 GiB/s |
| 16 MiB     | 1.04 GiB/s |

### Performance characteristics

The engine uses `ring` (assembly-optimized AES-NI / NEON / ARMv8-CE) for cipher operations and `pread`/`pwrite` for parallel I/O. Each Rayon thread independently reads a chunk, encrypts/decrypts it, and writes the result — no shared mutable state, no memory mapping.

**Why AES-256-GCM is faster than ChaCha20-Poly1305 on small files:**
`ring`'s AES-GCM backend exploits AES-NI + CLMUL hardware instructions available on x86-64, giving it a hardware advantage over ChaCha20 (which is a software cipher). At larger sizes both ciphers converge to ~1.3 GiB/s, indicating the bottleneck shifts from cipher throughput to I/O syscall overhead.

**Why peak throughput is at 1 MiB, not 256 MiB:**
With 1 MiB total and the default 1 MiB chunk size, there's a single chunk — the Rayon `par_iter` overhead is minimal, and the entire file fits in L2 cache. At 16-64 MiB the per-chunk syscall count rises (16-64 `pread`/`pwrite` pairs) and the working set exceeds cache. At 256 MiB, Rayon's work-stealing fully saturates all cores, partially recovering throughput.

**Why ~1.3 GiB/s and not 10+ GiB/s:**
Modern AES-NI can push 2-4 GiB/s *per core*. With 12 threads, raw cipher throughput could exceed 10 GiB/s. Two factors explain the gap:

1. **pread/pwrite syscall overhead**: Each chunk requires two syscalls (read + write). With 256 chunks for a 256 MiB file, that's 512 kernel transitions. Unlike mmap (which amortizes page faults over large sequential accesses), pread/pwrite pays a fixed per-call cost. The tradeoff: pread/pwrite works correctly with files of any size, has no SIGBUS risk, and doesn't exhaust virtual address space.
2. **Cache hierarchy effects**: The 5600X has 512 KiB L2 per core and 32 MiB shared L3. The default 1 MiB chunk fits in L2 for most of the encrypt/MAC pass, but 12 concurrent chunks (12 MiB active working set) compete for L3 bandwidth.

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

## File Format

All values are little-endian. Total header: 52 bytes.

```
Offset  Size   Field
------  -----  ---------------------
0       10     Magic bytes "CONCRYPTOR"
10       1     Format version (2)
11       1     Cipher type (0 = AES-256-GCM, 1 = ChaCha20-Poly1305)
12       4     Chunk size (bytes, LE)
16       8     Original file size (bytes, LE)
24      16     Argon2 salt (cryptographically random, unique per file)
40      12     Base nonce (cryptographically random, unique per file)
52      ...    [Chunk 0 ciphertext + 16-byte MAC tag]
               [Chunk 1 ciphertext + 16-byte MAC tag]
               ...
```

The salt and base nonce are generated fresh from `rand::thread_rng()` (backed by the OS CSPRNG) on every encryption. Reusing a password across files is safe because different salts produce different Argon2id keys, and different base nonces produce different per-chunk nonces.

## Security Design

- **Nonce derivation**: `chunk_nonce = base_nonce XOR chunk_index` (TLS 1.3 style). Swapping chunks causes decryption failure because the nonce at position N won't match the nonce used to encrypt the chunk originally at position M.
- **Header-authenticated AAD**: Every chunk's AEAD call uses `AAD = header_bytes (52) || chunk_index (8 LE) || is_final (1)` (61 bytes total). The full serialized header is bound into every chunk's authentication tag. Modifying *any* header field (cipher type, chunk size, original size, salt, nonce) invalidates all chunks. This prevents truncation attacks where an adversary edits `original_size` and removes trailing chunks.
- **STREAM-style final chunk indicator**: The last byte of the AAD is `0x01` for the final chunk and `0x00` for all others. This prevents two attacks:
  - **Truncation**: Removing the final chunk and promoting a non-final chunk to the end fails because the non-final chunk was encrypted with `is_final = 0x00` but decryption expects `0x01`.
  - **Extension**: Appending forged chunks fails because the attacker cannot produce a valid tag for `is_final = 0x01` without the key.
- **Fresh randomness per file**: A 16-byte salt and 12-byte base nonce are drawn from the OS CSPRNG (`rand::thread_rng()`) for every encryption. Two encryptions of the same file with the same password produce completely different ciphertext. Nonce reuse (which is catastrophic for AES-GCM) is avoided by construction.
- **Key derivation**: Argon2id with 64 MiB memory cost, 3 time iterations, parallelism of 4. Resistant to GPU/ASIC brute-force attacks.
- **Zeroization**: Encryption keys are zeroized immediately after cipher construction. Passwords are zeroized after use.

## Testing

```bash
# Run the full test suite (38 tests)
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
