mod archive;
mod cli;
mod crypto;
mod engine;
mod header;

use std::path::{Path, PathBuf};
use std::process;

use anyhow::Result;
use clap::Parser;
use zeroize::Zeroize;

use cli::{CipherArg, Cli, Command};
use header::CipherType;

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Encrypt { input, output, cipher, chunk_size, memory, password } => {
            let is_dir = input.is_dir();

            let output = output.unwrap_or_else(|| {
                if is_dir {
                    // Resolve the true directory name (handles ".", "..", trailing /)
                    let dir_name = input
                        .canonicalize()
                        .ok()
                        .and_then(|c| c.file_name().map(|n| n.to_owned()))
                        .unwrap_or_else(|| std::ffi::OsString::from("archive"));
                    let mut name = dir_name;
                    name.push(".tar.enc");
                    input.parent().unwrap_or(Path::new(".")).join(name)
                } else {
                    let mut p = input.as_os_str().to_owned();
                    p.push(".enc");
                    PathBuf::from(p)
                }
            });

            let cipher_type = match cipher {
                CipherArg::Aes => CipherType::Aes256Gcm,
                CipherArg::Chacha => CipherType::ChaCha20Poly1305,
            };

            let chunk_bytes = chunk_size.saturating_mul(1024 * 1024);
            if chunk_bytes == 0 {
                anyhow::bail!("chunk size must be at least 1 MiB");
            }

            let mut password = match password {
                Some(p) => {
                    if p.is_empty() {
                        anyhow::bail!("password cannot be empty");
                    }
                    p
                }
                None => read_password_twice()?,
            };
            let kdf_params = header::KdfParams {
                m_cost: memory.saturating_mul(1024),
                t_cost: 3,
                p_cost: 4,
            };

            // If input is a directory, create a temporary tar archive first.
            // The temp file is auto-deleted when _temp_guard drops.
            let (effective_input, _temp_guard) = if is_dir {
                let temp = archive::TempFile::new(&output, ".tar")?;
                eprintln!("Archiving directory...");
                archive::pack(&input, temp.path())?;
                (temp.path().to_path_buf(), Some(temp))
            } else {
                (input.clone(), None)
            };

            let result = engine::encrypt(
                &effective_input, &output,
                password.as_bytes(), cipher_type,
                Some(chunk_bytes), &kdf_params,
            );
            password.zeroize();
            // Clean up partial .enc output on failure (temp tar is auto-cleaned by Drop).
            if result.is_err() {
                let _ = std::fs::remove_file(&output);
            }
            result?;
        }

        Command::Decrypt { input, output, extract, password } => {
            let mut password = match password {
                Some(p) => {
                    if p.is_empty() {
                        anyhow::bail!("password cannot be empty");
                    }
                    p
                }
                None => rpassword::prompt_password("Password: ")
                    .map_err(|e| anyhow::anyhow!("failed to read password: {e}"))?,
            };

            if extract {
                let extract_dir = output.unwrap_or_else(|| {
                    let name = input.to_string_lossy();
                    if let Some(stripped) = name.strip_suffix(".tar.enc") {
                        PathBuf::from(stripped)
                    } else if let Some(stripped) = name.strip_suffix(".enc") {
                        PathBuf::from(stripped)
                    } else {
                        let mut p = input.as_os_str().to_owned();
                        p.push(".d");
                        PathBuf::from(p)
                    }
                });

                let temp = archive::TempFile::new(&input, ".tar")?;
                let result = engine::decrypt(&input, temp.path(), password.as_bytes());
                password.zeroize();
                result?;

                eprintln!("Extracting archive...");
                archive::unpack(temp.path(), &extract_dir)?;
                eprintln!("Extracted to {}", extract_dir.display());
            } else {
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

                let result = engine::decrypt(&input, &output, password.as_bytes());
                password.zeroize();
                result?;
            }
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
