use anyhow::{bail, Context, Result};

pub const MAGIC: &[u8; 10] = b"CONCRYPTOR";
pub const VERSION: u8 = 2;
pub const TAG_SIZE: usize = 16; // AES-GCM and ChaCha20Poly1305 both use 16-byte tags
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const HEADER_SIZE: usize = MAGIC.len() + 1 + 1 + 4 + 8 + SALT_LEN + NONCE_LEN; // 52 bytes

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherType {
    Aes256Gcm = 0,
    ChaCha20Poly1305 = 1,
}

impl CipherType {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Self::Aes256Gcm),
            1 => Ok(Self::ChaCha20Poly1305),
            _ => bail!("unknown cipher type: {b}"),
        }
    }
}

/// File header layout (52 bytes):
///   [Magic: 10B][Version: 1B][Cipher: 1B][ChunkSize: 4B LE]
///   [OrigSize: 8B LE][Salt: 16B][BaseNonce: 12B]
#[derive(Debug, Clone)]
pub struct Header {
    pub cipher: CipherType,
    pub chunk_size: u32,
    pub original_size: u64,
    pub salt: [u8; SALT_LEN],
    pub base_nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn new(
        cipher: CipherType,
        chunk_size: u32,
        original_size: u64,
        salt: [u8; SALT_LEN],
        base_nonce: [u8; NONCE_LEN],
    ) -> Self {
        Self { cipher, chunk_size, original_size, salt, base_nonce }
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        assert!(buf.len() >= HEADER_SIZE, "buffer too small for header");
        let mut pos = 0;

        buf[pos..pos + MAGIC.len()].copy_from_slice(MAGIC);
        pos += MAGIC.len();

        buf[pos] = VERSION;
        pos += 1;

        buf[pos] = self.cipher as u8;
        pos += 1;

        buf[pos..pos + 4].copy_from_slice(&self.chunk_size.to_le_bytes());
        pos += 4;

        buf[pos..pos + 8].copy_from_slice(&self.original_size.to_le_bytes());
        pos += 8;

        buf[pos..pos + SALT_LEN].copy_from_slice(&self.salt);
        pos += SALT_LEN;

        buf[pos..pos + NONCE_LEN].copy_from_slice(&self.base_nonce);
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            bail!("file too small to contain a valid Concryptor header");
        }

        let mut pos = 0;

        if &buf[pos..pos + MAGIC.len()] != MAGIC.as_slice() {
            bail!("invalid magic bytes: not a Concryptor file");
        }
        pos += MAGIC.len();

        let version = buf[pos];
        if version != VERSION {
            bail!("unsupported file version: {version} (expected {VERSION})");
        }
        pos += 1;

        let cipher = CipherType::from_byte(buf[pos])
            .context("failed to parse cipher type")?;
        pos += 1;

        let chunk_size = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let original_size = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
        pos += 8;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[pos..pos + SALT_LEN]);
        pos += SALT_LEN;

        let mut base_nonce = [0u8; NONCE_LEN];
        base_nonce.copy_from_slice(&buf[pos..pos + NONCE_LEN]);

        Ok(Self { cipher, chunk_size, original_size, salt, base_nonce })
    }

    /// Total output file size for encryption.
    pub fn output_size(input_size: u64, chunk_size: u32) -> u64 {
        let cs = chunk_size as u64;
        let num_chunks = input_size.div_ceil(cs).max(1);
        HEADER_SIZE as u64 + input_size + num_chunks * TAG_SIZE as u64
    }

    /// Number of chunks for a given input size and chunk size.
    pub fn num_chunks(input_size: u64, chunk_size: u32) -> u64 {
        (input_size.div_ceil(chunk_size as u64)).max(1)
    }
}
