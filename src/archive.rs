use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand::RngCore;
use tar::EntryType;

/// A temporary file that is automatically deleted when dropped.
/// Uses a 128-bit CSPRNG filename and O_CREAT|O_EXCL to prevent races.
pub struct TempFile {
    path: PathBuf,
}

impl TempFile {
    /// Create a new empty temp file in the same directory as `reference_path`.
    pub fn new(reference_path: &Path, suffix: &str) -> Result<Self> {
        let dir = reference_path.parent().unwrap_or(Path::new("."));
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        let mut buf = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut buf);
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!(".concryptor-{hex}{suffix}"));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("failed to create temp file: {}", path.display()))?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Create a tar archive of `dir_path`, writing to `output_path`.
/// Preserves permissions, timestamps, and directory structure.
/// Symlinks are stored as-is (not followed) to preserve the directory faithfully.
/// The directory's own name becomes the root entry in the archive, so
/// extracting reproduces the original directory by name.
pub fn pack(dir_path: &Path, output_path: &Path) -> Result<()> {
    if !dir_path.is_dir() {
        bail!("'{}' is not a directory", dir_path.display());
    }

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(output_path)
        .with_context(|| format!("cannot create archive: {}", output_path.display()))?;

    let mut builder = tar::Builder::new(file);
    builder.follow_symlinks(false);

    let dir_name = dir_path
        .file_name()
        .context("directory path has no name component")?;
    builder
        .append_dir_all(dir_name, dir_path)
        .with_context(|| format!("failed to archive: {}", dir_path.display()))?;
    builder.into_inner()?.sync_all()?;
    Ok(())
}

/// Check whether a symlink/hardlink target, resolved from `entry_path`'s
/// parent directory, would escape the archive root.
///
/// Rejects absolute targets outright. For relative targets, walks the
/// normalized component list and tracks directory depth; if depth ever
/// goes negative the link escapes.
fn link_target_escapes_root(entry_path: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return true;
    }
    let parent = entry_path.parent().unwrap_or(Path::new(""));
    let resolved = parent.join(target);
    let mut depth: i32 = 0;
    for component in resolved.components() {
        match component {
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            Component::Normal(_) => depth += 1,
            _ => {}
        }
    }
    false
}

/// Extract a tar archive at `archive_path` into `output_dir`.
///
/// Defence-in-depth validation (on top of the tar crate's own guards):
/// - Rejects entries with absolute paths
/// - Rejects entries with `..` path components
/// - Rejects symlinks/hardlinks whose targets escape the archive root
///   (absolute targets or relative targets that traverse above the root)
pub fn unpack(archive_path: &Path, output_dir: &Path) -> Result<()> {
    let file = fs::File::open(archive_path)
        .with_context(|| format!("cannot open archive: {}", archive_path.display()))?;

    fs::create_dir_all(output_dir)
        .with_context(|| format!("cannot create output directory: {}", output_dir.display()))?;

    let mut archive = tar::Archive::new(file);
    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(false);

    for entry in archive
        .entries()
        .context("failed to read archive entries")?
    {
        let mut entry = entry.context("corrupt archive entry")?;
        let path = entry.path().context("invalid entry path")?.into_owned();

        if path.is_absolute() {
            bail!("archive contains absolute path: {}", path.display());
        }
        for component in path.components() {
            if matches!(component, Component::ParentDir) {
                bail!("archive contains path traversal: {}", path.display());
            }
        }

        // Validate symlink and hardlink targets don't escape the extraction root.
        let entry_type = entry.header().entry_type();
        if matches!(entry_type, EntryType::Symlink | EntryType::Link) {
            if let Some(target) = entry.link_name().context("invalid link target")? {
                let target = target.into_owned();
                if link_target_escapes_root(&path, &target) {
                    bail!(
                        "archive contains link escaping extraction root: {} -> {}",
                        path.display(),
                        target.display()
                    );
                }
            }
        }

        entry
            .unpack_in(output_dir)
            .with_context(|| format!("failed to extract: {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_absolute_target() {
        assert!(link_target_escapes_root(
            Path::new("dir/link"),
            Path::new("/etc/passwd"),
        ));
    }

    #[test]
    fn escapes_relative_traversal() {
        // dir/link -> ../../etc/passwd  =>  resolved: etc/passwd at depth -1
        assert!(link_target_escapes_root(
            Path::new("dir/link"),
            Path::new("../../etc/passwd"),
        ));
    }

    #[test]
    fn stays_within_root_sibling() {
        // dir/link -> ../other/file  =>  resolved: other/file  (depth stays >= 0)
        assert!(!link_target_escapes_root(
            Path::new("dir/link"),
            Path::new("../other/file"),
        ));
    }

    #[test]
    fn stays_within_root_same_dir() {
        assert!(!link_target_escapes_root(
            Path::new("dir/link"),
            Path::new("sibling.txt"),
        ));
    }

    #[test]
    fn escapes_deep_traversal() {
        // a/b/c/link -> ../../../../x  =>  depth goes to -1
        assert!(link_target_escapes_root(
            Path::new("a/b/c/link"),
            Path::new("../../../../x"),
        ));
    }

    #[test]
    fn stays_within_deep_backref() {
        // a/b/c/link -> ../../../x  =>  resolved: x  (depth = 0, never negative)
        assert!(!link_target_escapes_root(
            Path::new("a/b/c/link"),
            Path::new("../../../x"),
        ));
    }
}
