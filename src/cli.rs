use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CipherArg {
    Aes,
    Chacha,
}

#[derive(Parser, Debug)]
#[command(
    name = "concryptor",
    version,
    about = "A multi-threaded AEAD encryption engine",
    long_about = "Concryptor encrypts and decrypts files using AES-256-GCM or ChaCha20-Poly1305 \
                  with parallel chunk processing, memory-mapped I/O, and Argon2id key derivation."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Encrypt a file
    #[command(alias = "enc", alias = "e")]
    Encrypt {
        /// Input file to encrypt
        input: PathBuf,

        /// Output file (defaults to <input>.enc)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Cipher algorithm
        #[arg(short, long, value_enum, default_value = "aes")]
        cipher: CipherArg,

        /// Chunk size in MiB
        #[arg(long, default_value = "4")]
        chunk_size: u32,

        /// Argon2id memory cost in MiB (higher = more resistant to brute-force)
        #[arg(long, default_value = "256")]
        memory: u32,

        /// Password (skips interactive prompt; visible in process listings and shell history)
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Decrypt a file
    #[command(alias = "dec", alias = "d")]
    Decrypt {
        /// Input file to decrypt
        input: PathBuf,

        /// Output file (defaults to <input> with .enc stripped, or <input>.dec)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Password (skips interactive prompt; visible in process listings and shell history)
        #[arg(short, long)]
        password: Option<String>,
    },
}
