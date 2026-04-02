use std::fs;
use std::path::Path;

use concryptor::crypto::derive_key;
use concryptor::engine::{self, build_cipher, Cipher};
use concryptor::header::{CipherType, KdfParams, NONCE_LEN, SALT_LEN};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::RngCore;

const PASSWORD: &[u8] = b"benchmark-password-concryptor";
const SALT: [u8; SALT_LEN] = [0xAA; SALT_LEN];
const BASE_NONCE: [u8; NONCE_LEN] = [0xBB; NONCE_LEN];

/// Low-cost KDF for benchmarks (only used for pre-derivation, not measured).
const BENCH_KDF: KdfParams = KdfParams {
    m_cost: 65_536,
    t_cost: 3,
    p_cost: 4,
};

fn write_random_file(path: &Path, size: usize) {
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; size];
    rng.fill_bytes(&mut buf);
    fs::write(path, &buf).expect("write failed");
}

/// Pre-derive the key once so benchmarks only measure IO + crypto.
fn pre_derive_cipher(cipher_type: CipherType) -> Cipher {
    let key = derive_key(PASSWORD, &SALT, &BENCH_KDF).unwrap();
    build_cipher(cipher_type, &key).unwrap()
}

// ---------------------------------------------------------------------------
// Pure encryption throughput (pre-derived key, mmap + rayon)
// ---------------------------------------------------------------------------

fn bench_encrypt_throughput(c: &mut Criterion) {
    let sizes: &[(u64, &str)] = &[
        (64 * 1024, "64KiB"),
        (1024 * 1024, "1MiB"),
        (16 * 1024 * 1024, "16MiB"),
        (64 * 1024 * 1024, "64MiB"),
        (256 * 1024 * 1024, "256MiB"),
    ];
    let chunk_size: u32 = 4 * 1024 * 1024;

    for cipher_type in [CipherType::Aes256Gcm, CipherType::ChaCha20Poly1305] {
        let name = match cipher_type {
            CipherType::Aes256Gcm => "AES-256-GCM",
            CipherType::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        };

        let cipher = pre_derive_cipher(cipher_type);

        let mut group = c.benchmark_group(format!("encrypt/{name}"));
        group.sample_size(10);

        for &(size, label) in sizes {
            group.throughput(Throughput::Bytes(size));

            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("input.bin");
            write_random_file(&input, size as usize);

            // Warmup: one encrypt so OS caches the file
            let warmup = dir.path().join("warmup.enc");
            engine::encrypt_with_cipher(
                &input,
                &warmup,
                &cipher,
                cipher_type,
                chunk_size,
                SALT,
                BASE_NONCE,
                &BENCH_KDF,
            )
            .unwrap();

            group.bench_with_input(BenchmarkId::new("throughput", label), &size, |b, _| {
                b.iter(|| {
                    let out = dir.path().join("bench.enc");
                    engine::encrypt_with_cipher(
                        black_box(&input),
                        &out,
                        &cipher,
                        cipher_type,
                        chunk_size,
                        SALT,
                        BASE_NONCE,
                        &BENCH_KDF,
                    )
                    .unwrap();
                });
            });
        }
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Pure decryption throughput (pre-derived key)
// ---------------------------------------------------------------------------

fn bench_decrypt_throughput(c: &mut Criterion) {
    let sizes: &[(u64, &str)] = &[
        (64 * 1024, "64KiB"),
        (1024 * 1024, "1MiB"),
        (16 * 1024 * 1024, "16MiB"),
        (64 * 1024 * 1024, "64MiB"),
        (256 * 1024 * 1024, "256MiB"),
    ];
    let chunk_size: u32 = 4 * 1024 * 1024;

    for cipher_type in [CipherType::Aes256Gcm, CipherType::ChaCha20Poly1305] {
        let name = match cipher_type {
            CipherType::Aes256Gcm => "AES-256-GCM",
            CipherType::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        };

        let cipher = pre_derive_cipher(cipher_type);

        let mut group = c.benchmark_group(format!("decrypt/{name}"));
        group.sample_size(10);

        for &(size, label) in sizes {
            group.throughput(Throughput::Bytes(size));

            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("input.bin");
            write_random_file(&input, size as usize);
            let enc = dir.path().join("encrypted.enc");
            engine::encrypt_with_cipher(
                &input,
                &enc,
                &cipher,
                cipher_type,
                chunk_size,
                SALT,
                BASE_NONCE,
                &BENCH_KDF,
            )
            .unwrap();

            group.bench_with_input(BenchmarkId::new("throughput", label), &size, |b, _| {
                b.iter(|| {
                    let dec = dir.path().join("bench.dec");
                    engine::decrypt_with_cipher(black_box(&enc), &dec, &cipher).unwrap();
                });
            });
        }
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Chunk size sweep: fixed 64 MiB file, vary chunk size
// ---------------------------------------------------------------------------

fn bench_chunk_size_sweep(c: &mut Criterion) {
    let file_size: usize = 64 * 1024 * 1024;
    let chunk_sizes: &[(u32, &str)] = &[
        (64 * 1024, "64KiB"),
        (256 * 1024, "256KiB"),
        (1024 * 1024, "1MiB"),
        (4 * 1024 * 1024, "4MiB"),
        (8 * 1024 * 1024, "8MiB"),
        (16 * 1024 * 1024, "16MiB"),
    ];

    let cipher_type = CipherType::Aes256Gcm;
    let cipher = pre_derive_cipher(cipher_type);

    let mut group = c.benchmark_group("chunk_sweep/AES-256-GCM/64MiB");
    group.throughput(Throughput::Bytes(file_size as u64));
    group.sample_size(10);

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.bin");
    write_random_file(&input, file_size);

    for &(cs, label) in chunk_sizes {
        group.bench_with_input(BenchmarkId::new("encrypt", label), &cs, |b, &cs| {
            b.iter(|| {
                let out = dir.path().join(format!("bench_{label}.enc"));
                engine::encrypt_with_cipher(
                    black_box(&input),
                    &out,
                    &cipher,
                    cipher_type,
                    cs,
                    SALT,
                    BASE_NONCE,
                    &BENCH_KDF,
                )
                .unwrap();
            });
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Full roundtrip (encrypt + decrypt, no KDF)
// ---------------------------------------------------------------------------

fn bench_roundtrip(c: &mut Criterion) {
    let sizes: &[(u64, &str)] = &[
        (1024 * 1024, "1MiB"),
        (16 * 1024 * 1024, "16MiB"),
        (64 * 1024 * 1024, "64MiB"),
    ];
    let chunk_size: u32 = 4 * 1024 * 1024;
    let cipher_type = CipherType::Aes256Gcm;
    let cipher = pre_derive_cipher(cipher_type);

    let mut group = c.benchmark_group("roundtrip/AES-256-GCM");
    group.sample_size(10);

    for &(size, label) in sizes {
        group.throughput(Throughput::Bytes(size * 2));

        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.bin");
        write_random_file(&input, size as usize);

        group.bench_with_input(BenchmarkId::new("roundtrip", label), &size, |b, _| {
            b.iter(|| {
                let enc = dir.path().join("rt.enc");
                let dec = dir.path().join("rt.dec");
                engine::encrypt_with_cipher(
                    black_box(&input),
                    &enc,
                    &cipher,
                    cipher_type,
                    chunk_size,
                    SALT,
                    BASE_NONCE,
                    &BENCH_KDF,
                )
                .unwrap();
                engine::decrypt_with_cipher(black_box(&enc), &dec, &cipher).unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_encrypt_throughput,
    bench_decrypt_throughput,
    bench_chunk_size_sweep,
    bench_roundtrip,
);
criterion_main!(benches);
