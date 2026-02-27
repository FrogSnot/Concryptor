use anyhow::{bail, Context, Result};

pub const MAGIC: &[u8; 10] = b"CONCRYPTOR";
pub const VERSION: u8 = 3;
pub const TAG_SIZE: usize = 16; // AES-GCM and ChaCha20Poly1305 both use 16-byte tags
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const HEADER_SIZE: usize = MAGIC.len() + 1 + 1 + 4 + 8 + SALT_LEN + NONCE_LEN; // 52 bytes
pub const SECTOR_SIZE: usize = 4096;
pub const ALIGNED_HEADER_SIZE: usize = SECTOR_SIZE;

/// Offset within the aligned header where KDF parameters are stored (after the 52-byte core).
const KDF_PARAMS_OFFSET: usize = HEADER_SIZE;

/// KDF parameters stored in the aligned header's reserved space.
/// Self-authenticating: wrong params produce a wrong key, failing AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32, // memory in KiB
    pub t_cost: u32, // iterations
    pub p_cost: u32, // parallelism
}

impl KdfParams {
    pub const DEFAULT: Self = Self {
        m_cost: 256 * 1024, // 256 MiB
        t_cost: 3,
        p_cost: 4,
    };

    /// Legacy params for files that predate self-describing KDF (all-zero sentinel).
    const LEGACY: Self = Self {
        m_cost: 65_536, // 64 MiB
        t_cost: 3,
        p_cost: 4,
    };

    /// Write KDF parameters into the aligned header buffer at offset 52.
    pub fn write_to_aligned(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= KDF_PARAMS_OFFSET + 12);
        buf[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + 4].copy_from_slice(&self.m_cost.to_le_bytes());
        buf[KDF_PARAMS_OFFSET + 4..KDF_PARAMS_OFFSET + 8].copy_from_slice(&self.t_cost.to_le_bytes());
        buf[KDF_PARAMS_OFFSET + 8..KDF_PARAMS_OFFSET + 12].copy_from_slice(&self.p_cost.to_le_bytes());
    }

    /// Read KDF parameters from an aligned header buffer.
    /// Returns legacy defaults if the fields are all zero (pre-V3.1 files).
    pub fn read_from_aligned(buf: &[u8]) -> Self {
        if buf.len() < KDF_PARAMS_OFFSET + 12 {
            return Self::LEGACY;
        }
        let m = u32::from_le_bytes(buf[KDF_PARAMS_OFFSET..KDF_PARAMS_OFFSET + 4].try_into().unwrap());
        let t = u32::from_le_bytes(buf[KDF_PARAMS_OFFSET + 4..KDF_PARAMS_OFFSET + 8].try_into().unwrap());
        let p = u32::from_le_bytes(buf[KDF_PARAMS_OFFSET + 8..KDF_PARAMS_OFFSET + 12].try_into().unwrap());
        if m == 0 && t == 0 && p == 0 {
            Self::LEGACY
        } else {
            Self { m_cost: m, t_cost: t, p_cost: p }
        }
    }
}

/// Disk size of each encrypted chunk slot, padded to the next SECTOR_SIZE boundary.
/// Every chunk occupies the same slot size for uniform offset arithmetic and O_DIRECT alignment.
pub fn aligned_chunk_disk_size(chunk_size: u32) -> u64 {
    let enc_size = chunk_size as u64 + TAG_SIZE as u64;
    enc_size.div_ceil(SECTOR_SIZE as u64) * SECTOR_SIZE as u64
}

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
        let num_chunks = Self::num_chunks(input_size, chunk_size);
        ALIGNED_HEADER_SIZE as u64 + num_chunks * aligned_chunk_disk_size(chunk_size)
    }

    /// Number of chunks for a given input size and chunk size.
    pub fn num_chunks(input_size: u64, chunk_size: u32) -> u64 {
        (input_size.div_ceil(chunk_size as u64)).max(1)
    }
}
