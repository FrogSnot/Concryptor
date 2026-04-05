use std::fs;
use std::path::Path;

use concryptor::archive;
use concryptor::crypto::{derive_key, derive_nonce};
use concryptor::engine;
use concryptor::header::{
    aligned_chunk_disk_size, CipherType, Header, KdfParams, ALIGNED_HEADER_SIZE, HEADER_SIZE,
    NONCE_LEN, SALT_LEN,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const PASSWORD: &[u8] = b"test-password-for-concryptor";
const CHUNK_1MB: u32 = 1024 * 1024;

/// Low-cost KDF params so tests finish quickly.
const TEST_KDF: KdfParams = KdfParams {
    m_cost: 65_536, // 64 MiB
    t_cost: 3,
    p_cost: 4,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmp() -> TempDir {
    tempfile::tempdir().expect("failed to create temp dir")
}

fn write_random_file(path: &Path, size: usize) {
    let mut rng = rand::rng();
    let mut buf = vec![0u8; size];
    rng.fill_bytes(&mut buf);
    fs::write(path, &buf).expect("write failed");
}

fn write_pattern_file(path: &Path, size: usize) {
    let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    fs::write(path, &data).expect("write failed");
}

fn sha256(path: &Path) -> [u8; 32] {
    let data = fs::read(path).expect("read failed");
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hasher.finalize().into()
}

fn roundtrip(
    input_path: &Path,
    enc_path: &Path,
    dec_path: &Path,
    cipher: CipherType,
    chunk_size: u32,
) {
    engine::encrypt(
        input_path,
        enc_path,
        PASSWORD,
        cipher,
        Some(chunk_size),
        &TEST_KDF,
    )
    .expect("encrypt failed");
    engine::decrypt(enc_path, dec_path, PASSWORD).expect("decrypt failed");
    assert_eq!(sha256(input_path), sha256(dec_path), "roundtrip mismatch");
}

// ===========================================================================
// Header tests
// ===========================================================================

#[test]
fn header_serialize_deserialize_roundtrip() {
    let salt = [0xAA; SALT_LEN];
    let nonce = [0xBB; NONCE_LEN];
    let header = Header::new(
        CipherType::Aes256Gcm,
        4 * 1024 * 1024,
        123456789,
        salt,
        nonce,
    );

    let mut buf = [0u8; HEADER_SIZE];
    header.serialize(&mut buf);
    let parsed = Header::deserialize(&buf).unwrap();

    assert_eq!(parsed.cipher, CipherType::Aes256Gcm);
    assert_eq!(parsed.chunk_size, 4 * 1024 * 1024);
    assert_eq!(parsed.original_size, 123456789);
    assert_eq!(parsed.salt, salt);
    assert_eq!(parsed.base_nonce, nonce);
}

#[test]
fn header_deserialize_rejects_bad_magic() {
    let mut buf = [0u8; HEADER_SIZE];
    buf[..10].copy_from_slice(b"NOTCONCRYP");
    assert!(Header::deserialize(&buf).is_err());
}

#[test]
fn header_deserialize_rejects_short_buffer() {
    let buf = [0u8; 10];
    assert!(Header::deserialize(&buf).is_err());
}

#[test]
fn header_output_size_calculation() {
    // 10 MB file, 4 MB chunks -> 3 chunks (4+4+2)
    let size = Header::output_size(10 * 1024 * 1024, 4 * 1024 * 1024);
    let dcs = aligned_chunk_disk_size(4 * 1024 * 1024);
    let expected = ALIGNED_HEADER_SIZE as u64 + 3 * dcs;
    assert_eq!(size, expected);
}

#[test]
fn header_output_size_empty_file() {
    let size = Header::output_size(0, 4 * 1024 * 1024);
    // Empty file still has 1 chunk (the empty chunk)
    let dcs = aligned_chunk_disk_size(4 * 1024 * 1024);
    let expected = ALIGNED_HEADER_SIZE as u64 + dcs;
    assert_eq!(size, expected);
}

#[test]
fn header_num_chunks_exact_multiple() {
    assert_eq!(Header::num_chunks(8 * 1024 * 1024, 4 * 1024 * 1024), 2);
}

#[test]
fn header_num_chunks_with_remainder() {
    assert_eq!(Header::num_chunks(9 * 1024 * 1024, 4 * 1024 * 1024), 3);
}

// ===========================================================================
// Crypto tests
// ===========================================================================

#[test]
fn derive_key_deterministic() {
    let k1 = derive_key(b"password", &[1u8; 16], &TEST_KDF).unwrap();
    let k2 = derive_key(b"password", &[1u8; 16], &TEST_KDF).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn derive_key_different_salt_yields_different_key() {
    let k1 = derive_key(b"password", &[1u8; 16], &TEST_KDF).unwrap();
    let k2 = derive_key(b"password", &[2u8; 16], &TEST_KDF).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn derive_key_different_password_yields_different_key() {
    let k1 = derive_key(b"alpha", &[0u8; 16], &TEST_KDF).unwrap();
    let k2 = derive_key(b"bravo", &[0u8; 16], &TEST_KDF).unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn derive_nonce_unique_per_index() {
    let base = [0xCC; NONCE_LEN];
    let n0 = derive_nonce(&base, 0);
    let n1 = derive_nonce(&base, 1);
    let n2 = derive_nonce(&base, 1000);
    assert_ne!(n0, n1);
    assert_ne!(n1, n2);
    assert_ne!(n0, n2);
}

#[test]
fn derive_nonce_index_zero_preserves_base() {
    let base = [0x42; NONCE_LEN];
    let n = derive_nonce(&base, 0);
    // XOR with 0 should return the base nonce unchanged
    assert_eq!(n, base);
}

// ===========================================================================
// Roundtrip: AES-256-GCM
// ===========================================================================

#[test]
fn aes_roundtrip_empty_file() {
    let dir = tmp();
    let input = dir.path().join("empty.bin");
    fs::write(&input, b"").unwrap();
    let enc = dir.path().join("empty.enc");
    let dec = dir.path().join("empty.dec");
    roundtrip(&input, &enc, &dec, CipherType::Aes256Gcm, CHUNK_1MB);
    assert_eq!(fs::read(&dec).unwrap().len(), 0);
}

#[test]
fn aes_roundtrip_1_byte() {
    let dir = tmp();
    let input = dir.path().join("one.bin");
    fs::write(&input, &[0xFF]).unwrap();
    let enc = dir.path().join("one.enc");
    let dec = dir.path().join("one.dec");
    roundtrip(&input, &enc, &dec, CipherType::Aes256Gcm, CHUNK_1MB);
}

#[test]
fn aes_roundtrip_exactly_one_chunk() {
    let dir = tmp();
    let input = dir.path().join("exact.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("exact.enc");
    let dec = dir.path().join("exact.dec");
    roundtrip(&input, &enc, &dec, CipherType::Aes256Gcm, CHUNK_1MB);
}

#[test]
fn aes_roundtrip_chunk_boundary_minus_one() {
    let dir = tmp();
    let input = dir.path().join("boundary_m1.bin");
    write_random_file(&input, CHUNK_1MB as usize - 1);
    let enc = dir.path().join("boundary_m1.enc");
    let dec = dir.path().join("boundary_m1.dec");
    roundtrip(&input, &enc, &dec, CipherType::Aes256Gcm, CHUNK_1MB);
}

#[test]
fn aes_roundtrip_chunk_boundary_plus_one() {
    let dir = tmp();
    let input = dir.path().join("boundary_p1.bin");
    write_random_file(&input, CHUNK_1MB as usize + 1);
    let enc = dir.path().join("boundary_p1.enc");
    let dec = dir.path().join("boundary_p1.dec");
    roundtrip(&input, &enc, &dec, CipherType::Aes256Gcm, CHUNK_1MB);
}

#[test]
fn aes_roundtrip_multi_chunk() {
    let dir = tmp();
    let input = dir.path().join("multi.bin");
    write_random_file(&input, 5 * CHUNK_1MB as usize + 12345);
    let enc = dir.path().join("multi.enc");
    let dec = dir.path().join("multi.dec");
    roundtrip(&input, &enc, &dec, CipherType::Aes256Gcm, CHUNK_1MB);
}

#[test]
fn aes_roundtrip_pattern_data() {
    let dir = tmp();
    let input = dir.path().join("pattern.bin");
    write_pattern_file(&input, 3 * CHUNK_1MB as usize);
    let enc = dir.path().join("pattern.enc");
    let dec = dir.path().join("pattern.dec");
    roundtrip(&input, &enc, &dec, CipherType::Aes256Gcm, CHUNK_1MB);
}

#[test]
fn aes_roundtrip_small_chunk_size() {
    let dir = tmp();
    let input = dir.path().join("small_chunk.bin");
    // 256 KiB file with 64 KiB chunks -> 4 chunks
    write_random_file(&input, 256 * 1024);
    let enc = dir.path().join("small_chunk.enc");
    let dec = dir.path().join("small_chunk.dec");
    roundtrip(&input, &enc, &dec, CipherType::Aes256Gcm, 64 * 1024);
}

// ===========================================================================
// Roundtrip: ChaCha20-Poly1305
// ===========================================================================

#[test]
fn chacha_roundtrip_empty_file() {
    let dir = tmp();
    let input = dir.path().join("empty.bin");
    fs::write(&input, b"").unwrap();
    let enc = dir.path().join("empty.enc");
    let dec = dir.path().join("empty.dec");
    roundtrip(&input, &enc, &dec, CipherType::ChaCha20Poly1305, CHUNK_1MB);
}

#[test]
fn chacha_roundtrip_multi_chunk() {
    let dir = tmp();
    let input = dir.path().join("multi.bin");
    write_random_file(&input, 3 * CHUNK_1MB as usize + 999);
    let enc = dir.path().join("multi.enc");
    let dec = dir.path().join("multi.dec");
    roundtrip(&input, &enc, &dec, CipherType::ChaCha20Poly1305, CHUNK_1MB);
}

#[test]
fn chacha_roundtrip_small_chunks() {
    let dir = tmp();
    let input = dir.path().join("small.bin");
    write_random_file(&input, 128 * 1024);
    let enc = dir.path().join("small.enc");
    let dec = dir.path().join("small.dec");
    roundtrip(&input, &enc, &dec, CipherType::ChaCha20Poly1305, 32 * 1024);
}

// ===========================================================================
// Security: wrong password must fail
// ===========================================================================

#[test]
fn wrong_password_fails_aes() {
    let dir = tmp();
    let input = dir.path().join("secret.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("secret.enc");
    let dec = dir.path().join("secret.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let result = engine::decrypt(&enc, &dec, b"wrong-password");
    assert!(
        result.is_err(),
        "decryption with wrong password should fail"
    );
}

#[test]
fn wrong_password_fails_chacha() {
    let dir = tmp();
    let input = dir.path().join("secret.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("secret.enc");
    let dec = dir.path().join("secret.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::ChaCha20Poly1305,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let result = engine::decrypt(&enc, &dec, b"wrong-password");
    assert!(
        result.is_err(),
        "decryption with wrong password should fail"
    );
}

// ===========================================================================
// Security: tamper detection
// ===========================================================================

#[test]
fn tampered_ciphertext_detected() {
    let dir = tmp();
    let input = dir.path().join("secret.bin");
    write_random_file(&input, 2 * CHUNK_1MB as usize);
    let enc = dir.path().join("secret.enc");
    let dec = dir.path().join("secret.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Flip a byte in the middle of the ciphertext body (inside chunk 0)
    let mut data = fs::read(&enc).unwrap();
    let mid = ALIGNED_HEADER_SIZE + CHUNK_1MB as usize / 2;
    data[mid] ^= 0xFF;
    fs::write(&enc, &data).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(result.is_err(), "tampered file should fail authentication");
}

#[test]
fn tampered_tag_detected() {
    let dir = tmp();
    let input = dir.path().join("secret.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("secret.enc");
    let dec = dir.path().join("secret.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Corrupt a byte inside the tag of the only chunk
    let mut data = fs::read(&enc).unwrap();
    let tag_start = ALIGNED_HEADER_SIZE + CHUNK_1MB as usize;
    data[tag_start] ^= 0x01;
    fs::write(&enc, &data).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(result.is_err(), "tampered tag should fail authentication");
}

#[test]
fn tampered_header_salt_detected() {
    let dir = tmp();
    let input = dir.path().join("secret.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("secret.enc");
    let dec = dir.path().join("secret.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Flip a byte in the salt region of the header
    let mut data = fs::read(&enc).unwrap();
    // Salt starts at offset 24 (10 magic + 1 ver + 1 cipher + 4 chunk + 8 origsize)
    data[24] ^= 0xFF;
    fs::write(&enc, &data).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(result.is_err(), "corrupted salt should cause key mismatch");
}

#[test]
fn truncated_file_detected() {
    let dir = tmp();
    let input = dir.path().join("secret.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("secret.enc");
    let dec = dir.path().join("secret.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Truncate the encrypted file
    let data = fs::read(&enc).unwrap();
    fs::write(&enc, &data[..data.len() - 100]).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(result.is_err(), "truncated file should be detected");
}

// ===========================================================================
// Security: chunk reordering attack
// ===========================================================================

#[test]
fn chunk_swap_attack_detected() {
    let dir = tmp();
    let input = dir.path().join("secret.bin");
    // 2 full chunks
    write_random_file(&input, 2 * CHUNK_1MB as usize);
    let enc = dir.path().join("secret.enc");
    let dec = dir.path().join("secret.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let mut data = fs::read(&enc).unwrap();
    let dcs = aligned_chunk_disk_size(CHUNK_1MB) as usize;

    // Swap chunk 0 and chunk 1 in the body
    let body_start = ALIGNED_HEADER_SIZE;
    let chunk0 = data[body_start..body_start + dcs].to_vec();
    let chunk1 = data[body_start + dcs..body_start + 2 * dcs].to_vec();
    data[body_start..body_start + dcs].copy_from_slice(&chunk1);
    data[body_start + dcs..body_start + 2 * dcs].copy_from_slice(&chunk0);
    fs::write(&enc, &data).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(
        result.is_err(),
        "chunk swap should be detected by nonce+AAD binding"
    );
}

// ===========================================================================
// Encrypted file structure validation
// ===========================================================================

#[test]
fn encrypted_file_has_correct_size() {
    let dir = tmp();
    let input = dir.path().join("sized.bin");
    let size = 3 * CHUNK_1MB as usize + 500;
    write_random_file(&input, size);
    let enc = dir.path().join("sized.enc");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let expected = Header::output_size(size as u64, CHUNK_1MB);
    let actual = fs::metadata(&enc).unwrap().len();
    assert_eq!(actual, expected);
}

#[test]
fn encrypted_file_header_readable() {
    let dir = tmp();
    let input = dir.path().join("readable.bin");
    write_random_file(&input, 1000);
    let enc = dir.path().join("readable.enc");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::ChaCha20Poly1305,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let data = fs::read(&enc).unwrap();
    let header = Header::deserialize(&data[..HEADER_SIZE]).unwrap();
    assert_eq!(header.cipher, CipherType::ChaCha20Poly1305);
    assert_eq!(header.chunk_size, CHUNK_1MB);
    assert_eq!(header.original_size, 1000);
}

// ===========================================================================
// Edge case: same file encrypted twice produces different ciphertext
// ===========================================================================

#[test]
fn encryption_is_non_deterministic() {
    let dir = tmp();
    let input = dir.path().join("ndet.bin");
    write_pattern_file(&input, 4096);
    let enc1 = dir.path().join("ndet1.enc");
    let enc2 = dir.path().join("ndet2.enc");

    engine::encrypt(
        &input,
        &enc1,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .unwrap();
    engine::encrypt(
        &input,
        &enc2,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .unwrap();

    let d1 = fs::read(&enc1).unwrap();
    let d2 = fs::read(&enc2).unwrap();
    // Salt and nonce are random, so content must differ
    assert_ne!(
        d1, d2,
        "encrypting the same file twice should produce different output"
    );
}

// ===========================================================================
// Cross-cipher: AES encrypted file must not decrypt if header says ChaCha
// ===========================================================================

#[test]
fn cipher_type_mismatch_fails() {
    let dir = tmp();
    let input = dir.path().join("cross.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("cross.enc");
    let dec = dir.path().join("cross.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .unwrap();

    // Overwrite the cipher byte in the header to claim it's ChaCha20
    let mut data = fs::read(&enc).unwrap();
    data[11] = CipherType::ChaCha20Poly1305 as u8; // byte 11 = cipher type
    fs::write(&enc, &data).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(
        result.is_err(),
        "cipher type mismatch should fail decryption"
    );
}

// ===========================================================================
// Stress: many small chunks
// ===========================================================================

#[test]
fn many_small_chunks() {
    let dir = tmp();
    let input = dir.path().join("many.bin");
    // 1 MiB file with 4 KiB chunks -> 256 chunks
    write_random_file(&input, 1024 * 1024);
    let enc = dir.path().join("many.enc");
    let dec = dir.path().join("many.dec");
    roundtrip(&input, &enc, &dec, CipherType::Aes256Gcm, 4 * 1024);
}

// ===========================================================================
// Security: truncation attack (header original_size manipulation)
// ===========================================================================

#[test]
fn truncation_attack_modify_original_size_detected() {
    let dir = tmp();
    let input = dir.path().join("trunc.bin");
    // 3 chunks worth of data
    write_random_file(&input, 3 * CHUNK_1MB as usize);
    let enc = dir.path().join("trunc.enc");
    let dec = dir.path().join("trunc.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Attacker modifies original_size in the header to claim only 2 chunks,
    // then truncates the file to match the new claimed size.
    let data = fs::read(&enc).unwrap();
    let fake_size: u64 = 2 * CHUNK_1MB as u64;
    let dcs = aligned_chunk_disk_size(CHUNK_1MB) as usize;
    let fake_file_size = ALIGNED_HEADER_SIZE + 2 * dcs;
    let mut tampered = data[..fake_file_size].to_vec();
    tampered[16..24].copy_from_slice(&fake_size.to_le_bytes());
    fs::write(&enc, &tampered).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(
        result.is_err(),
        "truncation attack (modified original_size) must be detected via header-bound AAD"
    );
}

#[test]
fn truncation_attack_remove_last_chunk_detected() {
    let dir = tmp();
    let input = dir.path().join("trunc2.bin");
    // 2 full chunks
    write_random_file(&input, 2 * CHUNK_1MB as usize);
    let enc = dir.path().join("trunc2.enc");
    let dec = dir.path().join("trunc2.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Attacker removes the last chunk and adjusts header to 1 chunk.
    let data = fs::read(&enc).unwrap();
    let fake_size: u64 = CHUNK_1MB as u64;
    let dcs = aligned_chunk_disk_size(CHUNK_1MB) as usize;
    let fake_file_size = ALIGNED_HEADER_SIZE + dcs;
    let mut tampered = data[..fake_file_size].to_vec();
    tampered[16..24].copy_from_slice(&fake_size.to_le_bytes());
    fs::write(&enc, &tampered).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(
        result.is_err(),
        "removing last chunk must be detected: chunk 0 was not the final chunk at encryption time"
    );
}

// ===========================================================================
// Security: header field manipulation
// ===========================================================================

#[test]
fn modified_chunk_size_in_header_detected() {
    let dir = tmp();
    let input = dir.path().join("hdr.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("hdr.enc");
    let dec = dir.path().join("hdr.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Change the chunk_size field in the header (offset 12..16)
    let mut data = fs::read(&enc).unwrap();
    let new_cs: u32 = 512 * 1024;
    data[12..16].copy_from_slice(&new_cs.to_le_bytes());
    fs::write(&enc, &data).unwrap();

    // File size won't match the new header's expectation, OR AAD mismatch will catch it
    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(result.is_err(), "modified chunk_size must be detected");
}

// ===========================================================================
// Security: padding tamper detection
// ===========================================================================

#[test]
fn tampered_padding_detected() {
    let dir = tmp();
    let input = dir.path().join("pad.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("pad.enc");
    let dec = dir.path().join("pad.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Write non-zero bytes into the padding region after the tag.
    let mut data = fs::read(&enc).unwrap();
    let padding_start = ALIGNED_HEADER_SIZE + CHUNK_1MB as usize + 16; // after ciphertext + tag
    data[padding_start] = 0xFF;
    data[padding_start + 1] = 0x42;
    fs::write(&enc, &data).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(result.is_err(), "tampered padding should be detected");
    // Output file should have been cleaned up.
    assert!(!dec.exists(), "partial output should be deleted on failure");
}

// ===========================================================================
// Security: failed decryption cleans up partial output
// ===========================================================================

#[test]
fn failed_decrypt_removes_output() {
    let dir = tmp();
    let input = dir.path().join("cleanup.bin");
    write_random_file(&input, 2 * CHUNK_1MB as usize);
    let enc = dir.path().join("cleanup.enc");
    let dec = dir.path().join("cleanup.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let result = engine::decrypt(&enc, &dec, b"wrong-password");
    assert!(result.is_err());
    assert!(
        !dec.exists(),
        "output file must be removed after failed decryption"
    );
}

// ===========================================================================
// Security: reserved header bytes tampering (full-header AAD, v4+)
// ===========================================================================

#[test]
fn tampered_reserved_header_bytes_detected() {
    let dir = tmp();
    let input = dir.path().join("res.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("res.enc");
    let dec = dir.path().join("res.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Modify reserved padding bytes (offset 64-4095) that were previously unauthenticated.
    let mut data = fs::read(&enc).unwrap();
    data[100] = 0xFF;
    data[2048] = 0xDE;
    data[4000] = 0xAD;
    fs::write(&enc, &data).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(
        result.is_err(),
        "tampering with reserved header bytes must be detected via full-header AAD"
    );
}

#[test]
fn tampered_kdf_params_in_header_detected() {
    let dir = tmp();
    let input = dir.path().join("kdf.bin");
    write_random_file(&input, CHUNK_1MB as usize);
    let enc = dir.path().join("kdf.enc");
    let dec = dir.path().join("kdf.dec");

    engine::encrypt(
        &input,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    // Modify the KDF m_cost field (bytes 52-55) in the header.
    let mut data = fs::read(&enc).unwrap();
    let fake_m_cost: u32 = 32_768;
    data[52..56].copy_from_slice(&fake_m_cost.to_le_bytes());
    fs::write(&enc, &data).unwrap();

    let result = engine::decrypt(&enc, &dec, PASSWORD);
    assert!(
        result.is_err(),
        "tampering with KDF parameters must be detected (wrong key + AAD mismatch)"
    );
}

// ===========================================================================
// Directory archive: pack / unpack roundtrip
// ===========================================================================

/// Create a test directory structure with known content.
fn create_test_dir(base: &Path) {
    let sub = base.join("subdir");
    fs::create_dir_all(&sub).unwrap();
    fs::write(base.join("hello.txt"), b"hello world").unwrap();
    write_random_file(&base.join("random.bin"), 8192);
    write_pattern_file(&sub.join("pattern.dat"), 4096);
    fs::create_dir_all(base.join("empty_dir")).unwrap();
}

/// Recursively collect all relative file paths and their SHA-256 hashes.
fn dir_fingerprint(base: &Path) -> std::collections::BTreeMap<String, [u8; 32]> {
    let mut map = std::collections::BTreeMap::new();
    collect_files(base, base, &mut map);
    map
}

fn collect_files(
    root: &Path,
    current: &Path,
    map: &mut std::collections::BTreeMap<String, [u8; 32]>,
) {
    for entry in fs::read_dir(current).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .to_string();
        if path.is_dir() {
            collect_files(root, &path, map);
        } else {
            map.insert(rel, sha256(&path));
        }
    }
}

#[test]
fn archive_pack_unpack_roundtrip() {
    let dir = tmp();
    let src = dir.path().join("mydir");
    fs::create_dir(&src).unwrap();
    create_test_dir(&src);

    let tar_path = dir.path().join("mydir.tar");
    archive::pack(&src, &tar_path).expect("pack failed");
    assert!(tar_path.exists());

    let extract_dir = dir.path().join("extracted");
    archive::unpack(&tar_path, &extract_dir).expect("unpack failed");

    // The archive stores "mydir/" as the root entry, so extracted content is in extracted/mydir/
    let restored = extract_dir.join("mydir");
    assert!(restored.is_dir(), "extracted directory should exist");

    let orig = dir_fingerprint(&src);
    let rest = dir_fingerprint(&restored);
    assert_eq!(
        orig, rest,
        "directory contents must match after pack/unpack"
    );
}

#[test]
fn archive_encrypt_decrypt_roundtrip_aes() {
    let dir = tmp();
    let src = dir.path().join("secret_dir");
    fs::create_dir(&src).unwrap();
    create_test_dir(&src);

    let tar_tmp = dir.path().join("tmp.tar");
    archive::pack(&src, &tar_tmp).expect("pack failed");

    let enc = dir.path().join("secret_dir.tar.enc");
    engine::encrypt(
        &tar_tmp,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");
    fs::remove_file(&tar_tmp).unwrap();

    let dec_tar = dir.path().join("decrypted.tar");
    engine::decrypt(&enc, &dec_tar, PASSWORD).expect("decrypt failed");

    let extract_dir = dir.path().join("restored");
    archive::unpack(&dec_tar, &extract_dir).expect("unpack failed");

    let orig = dir_fingerprint(&src);
    let rest = dir_fingerprint(&extract_dir.join("secret_dir"));
    assert_eq!(
        orig, rest,
        "directory contents must match after encrypt/decrypt roundtrip"
    );
}

#[test]
fn archive_encrypt_decrypt_roundtrip_chacha() {
    let dir = tmp();
    let src = dir.path().join("chacha_dir");
    fs::create_dir(&src).unwrap();
    create_test_dir(&src);

    let tar_tmp = dir.path().join("tmp.tar");
    archive::pack(&src, &tar_tmp).expect("pack failed");

    let enc = dir.path().join("chacha_dir.tar.enc");
    engine::encrypt(
        &tar_tmp,
        &enc,
        PASSWORD,
        CipherType::ChaCha20Poly1305,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");
    fs::remove_file(&tar_tmp).unwrap();

    let dec_tar = dir.path().join("decrypted.tar");
    engine::decrypt(&enc, &dec_tar, PASSWORD).expect("decrypt failed");

    let extract_dir = dir.path().join("restored");
    archive::unpack(&dec_tar, &extract_dir).expect("unpack failed");

    let orig = dir_fingerprint(&src);
    let rest = dir_fingerprint(&extract_dir.join("chacha_dir"));
    assert_eq!(
        orig, rest,
        "directory contents must match after encrypt/decrypt roundtrip"
    );
}

#[test]
fn archive_empty_directory() {
    let dir = tmp();
    let src = dir.path().join("emptydir");
    fs::create_dir(&src).unwrap();

    let tar_path = dir.path().join("empty.tar");
    archive::pack(&src, &tar_path).expect("pack failed");

    let enc = dir.path().join("empty.tar.enc");
    engine::encrypt(
        &tar_path,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let dec_tar = dir.path().join("dec.tar");
    engine::decrypt(&enc, &dec_tar, PASSWORD).expect("decrypt failed");

    let extract_dir = dir.path().join("restored");
    archive::unpack(&dec_tar, &extract_dir).expect("unpack failed");
    assert!(
        extract_dir.join("emptydir").is_dir(),
        "empty directory should be preserved"
    );
}

#[test]
fn archive_nested_directories() {
    let dir = tmp();
    let src = dir.path().join("nested");
    fs::create_dir_all(src.join("a/b/c/d")).unwrap();
    fs::write(src.join("a/b/c/d/deep.txt"), b"deep content").unwrap();
    fs::write(src.join("a/top.txt"), b"top level").unwrap();

    let tar_path = dir.path().join("nested.tar");
    archive::pack(&src, &tar_path).expect("pack failed");

    let enc = dir.path().join("nested.tar.enc");
    engine::encrypt(
        &tar_path,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let dec_tar = dir.path().join("dec.tar");
    engine::decrypt(&enc, &dec_tar, PASSWORD).expect("decrypt failed");

    let extract_dir = dir.path().join("restored");
    archive::unpack(&dec_tar, &extract_dir).expect("unpack failed");

    let orig = dir_fingerprint(&src);
    let rest = dir_fingerprint(&extract_dir.join("nested"));
    assert_eq!(orig, rest, "deeply nested directory contents must match");
}

#[test]
fn archive_wrong_password_fails() {
    let dir = tmp();
    let src = dir.path().join("secret");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("file.txt"), b"secret data").unwrap();

    let tar_path = dir.path().join("secret.tar");
    archive::pack(&src, &tar_path).expect("pack failed");

    let enc = dir.path().join("secret.tar.enc");
    engine::encrypt(
        &tar_path,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let dec_tar = dir.path().join("bad.tar");
    let result = engine::decrypt(&enc, &dec_tar, b"wrong-password");
    assert!(
        result.is_err(),
        "decryption with wrong password should fail for archives"
    );
}

#[test]
fn archive_pack_rejects_non_directory() {
    let dir = tmp();
    let file = dir.path().join("not_a_dir.txt");
    fs::write(&file, b"just a file").unwrap();
    let tar_path = dir.path().join("out.tar");
    let result = archive::pack(&file, &tar_path);
    assert!(result.is_err(), "pack should reject non-directory input");
}

#[test]
fn archive_temp_file_cleanup() {
    let dir = tmp();
    let temp =
        archive::TempFile::new(&dir.path().join("ref"), ".test").expect("TempFile creation failed");
    let path = temp.path().to_path_buf();
    assert!(path.exists(), "temp file should exist after creation");
    drop(temp);
    assert!(!path.exists(), "temp file should be deleted after drop");
}

// ===========================================================================
// Directory archive: symlink handling
// ===========================================================================

#[cfg(unix)]
#[test]
fn archive_preserves_valid_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = tmp();
    let src = dir.path().join("links");
    fs::create_dir_all(src.join("subdir")).unwrap();
    fs::write(src.join("real.txt"), b"target file").unwrap();
    fs::write(src.join("subdir/nested.txt"), b"nested file").unwrap();
    // Symlink within the same directory
    symlink("real.txt", src.join("link_same_dir")).unwrap();
    // Symlink from subdir to parent (valid: stays within archive)
    symlink("../real.txt", src.join("subdir/link_to_parent")).unwrap();

    let tar_path = dir.path().join("links.tar");
    archive::pack(&src, &tar_path).expect("pack failed");

    let extract_dir = dir.path().join("extracted");
    archive::unpack(&tar_path, &extract_dir).expect("unpack failed");

    let restored = extract_dir.join("links");
    // Verify the symlinks exist and point to the right targets
    assert!(restored.join("link_same_dir").is_symlink());
    assert_eq!(
        fs::read_to_string(restored.join("link_same_dir")).unwrap(),
        "target file"
    );
    assert!(restored.join("subdir/link_to_parent").is_symlink());
    assert_eq!(
        fs::read_to_string(restored.join("subdir/link_to_parent")).unwrap(),
        "target file"
    );
}

#[cfg(unix)]
#[test]
fn archive_rejects_escaping_symlink() {
    use std::os::unix::fs::symlink;

    let dir = tmp();
    let src = dir.path().join("evil");
    fs::create_dir(&src).unwrap();
    // Create a symlink that escapes the archive root
    symlink("../../etc/passwd", src.join("escape")).unwrap();

    let tar_path = dir.path().join("evil.tar");
    archive::pack(&src, &tar_path).expect("pack failed");

    let extract_dir = dir.path().join("extracted");
    let result = archive::unpack(&tar_path, &extract_dir);
    assert!(
        result.is_err(),
        "symlink escaping archive root must be rejected"
    );
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("escaping extraction root"),
        "error should mention escaping root, got: {err_msg}"
    );
}

#[cfg(unix)]
#[test]
fn archive_rejects_absolute_symlink_target() {
    use std::os::unix::fs::symlink;

    let dir = tmp();
    let src = dir.path().join("abslink");
    fs::create_dir(&src).unwrap();
    symlink("/etc/passwd", src.join("abs")).unwrap();

    let tar_path = dir.path().join("abslink.tar");
    archive::pack(&src, &tar_path).expect("pack failed");

    let extract_dir = dir.path().join("extracted");
    let result = archive::unpack(&tar_path, &extract_dir);
    assert!(result.is_err(), "absolute symlink target must be rejected");
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("escaping extraction root"),
        "error should mention escaping root, got: {err_msg}"
    );
}

// ===========================================================================
// Directory archive: large directory with many files
// ===========================================================================

#[test]
fn archive_many_files() {
    let dir = tmp();
    let src = dir.path().join("many_files");
    fs::create_dir(&src).unwrap();
    for i in 0..50 {
        fs::write(src.join(format!("file_{i:03}.txt")), format!("content {i}")).unwrap();
    }

    let tar_path = dir.path().join("many.tar");
    archive::pack(&src, &tar_path).expect("pack failed");

    let enc = dir.path().join("many.tar.enc");
    engine::encrypt(
        &tar_path,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let dec_tar = dir.path().join("dec.tar");
    engine::decrypt(&enc, &dec_tar, PASSWORD).expect("decrypt failed");

    let extract_dir = dir.path().join("restored");
    archive::unpack(&dec_tar, &extract_dir).expect("unpack failed");

    let orig = dir_fingerprint(&src);
    let rest = dir_fingerprint(&extract_dir.join("many_files"));
    assert_eq!(
        orig, rest,
        "directory with many files must match after roundtrip"
    );
}

// ===========================================================================
// Directory archive: binary and mixed content
// ===========================================================================

#[test]
fn archive_binary_content_roundtrip() {
    let dir = tmp();
    let src = dir.path().join("bindir");
    fs::create_dir_all(src.join("data")).unwrap();
    // Large binary file
    write_random_file(&src.join("data/random.bin"), 2 * CHUNK_1MB as usize + 7777);
    // Empty file
    fs::write(src.join("data/empty"), b"").unwrap();
    // 1-byte file
    fs::write(src.join("one_byte"), &[0xAB]).unwrap();

    let tar_path = dir.path().join("bin.tar");
    archive::pack(&src, &tar_path).expect("pack failed");

    let enc = dir.path().join("bin.tar.enc");
    engine::encrypt(
        &tar_path,
        &enc,
        PASSWORD,
        CipherType::Aes256Gcm,
        Some(CHUNK_1MB),
        &TEST_KDF,
    )
    .expect("encrypt failed");

    let dec_tar = dir.path().join("dec.tar");
    engine::decrypt(&enc, &dec_tar, PASSWORD).expect("decrypt failed");

    let extract_dir = dir.path().join("restored");
    archive::unpack(&dec_tar, &extract_dir).expect("unpack failed");

    let orig = dir_fingerprint(&src);
    let rest = dir_fingerprint(&extract_dir.join("bindir"));
    assert_eq!(
        orig, rest,
        "binary content must be preserved through roundtrip"
    );
}
