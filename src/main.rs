mod cli;
mod crypto;
mod engine;
mod header;

use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::Parser;
use zeroize::Zeroize;

use cli::{CipherArg, Cli, Command};
use header::CipherType;

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { input, output, cipher, chunk_size, memory } => {
            let output = output.unwrap_or_else(|| {
                let mut p = input.as_os_str().to_owned();
                p.push(".enc");
                PathBuf::from(p)
            });

            let cipher_type = match cipher {
                CipherArg::Aes => CipherType::Aes256Gcm,
                CipherArg::Chacha => CipherType::ChaCha20Poly1305,
            };

            let chunk_bytes = chunk_size.saturating_mul(1024 * 1024);
            if chunk_bytes == 0 {
                anyhow::bail!("chunk size must be at least 1 MiB");
            }

            let mut password = read_password_twice()?;
            let kdf_params = header::KdfParams {
                m_cost: memory.saturating_mul(1024),
                t_cost: 3,
                p_cost: 4,
            };
            let result = engine::encrypt(&input, &output, password.as_bytes(), cipher_type, Some(chunk_bytes), &kdf_params);
            password.zeroize();
            result?;
        }

        Command::Decrypt { input, output } => {
            let output = output.unwrap_or_else(|| {
                let name = input.to_string_lossy();
                if let Some(stripped) = name.strip_suffix(".enc") {
                    PathBuf::from(stripped)
                } else {
                    let mut p = input.as_os_str().to_owned();
                    p.push(".dec");
                    PathBuf::from(p)
                }
            });

            let mut password = rpassword::prompt_password("Password: ")
                .map_err(|e| anyhow::anyhow!("failed to read password: {e}"))?;
            let result = engine::decrypt(&input, &output, password.as_bytes());
            password.zeroize();
            result?;
        }
    }

    Ok(())
}

fn read_password_twice() -> Result<String> {
    let p1 = rpassword::prompt_password("Password: ")
        .map_err(|e| anyhow::anyhow!("failed to read password: {e}"))?;
    let p2 = rpassword::prompt_password("Confirm password: ")
        .map_err(|e| anyhow::anyhow!("failed to read password: {e}"))?;
    if p1 != p2 {
        anyhow::bail!("passwords do not match");
    }
    if p1.is_empty() {
        anyhow::bail!("password cannot be empty");
    }
    Ok(p1)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        process::exit(1);
    }
}
