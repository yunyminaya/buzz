//! Atomic fsync file writers.
//!
//! `atomic_write_restricted_with_fsync` uses `atomic-write-file` (owner-only
//! mode, `commit()` handles fsync+rename on the temp fd and fsyncs the parent
//! directory on Unix).
//!
//! `atomic_write_with_fsync` is a plain tmp→fsync→rename path used for files
//! that do not carry secret material (e.g. `teams.json`).  It also fsyncs the
//! parent directory on Unix after rename.

use std::path::Path;

/// Write `payload` to `path` atomically (tmp → fsync → rename → fsync-parent).
/// Resolves symlinks so the rename lands on the physical target.
///
/// On Unix, fsyncs the parent directory after rename to durably commit the
/// directory entry — without it the data blocks may survive a crash while the
/// renamed entry does not.  This matches the durability guarantee provided by
/// `atomic-write-file::commit()` on the restricted-write path.
pub fn atomic_write_with_fsync(path: &Path, payload: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let tmp = resolved.with_extension("json.tmp");
    let mut file =
        std::fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
    file.write_all(payload)
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    file.sync_all()
        .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    drop(file);
    std::fs::rename(&tmp, &resolved)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), resolved.display()))?;

    // Fsync the parent directory so the directory entry for the new name is
    // durably committed.  Best-effort on platforms that do not support it.
    #[cfg(unix)]
    if let Some(parent) = resolved.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

/// Atomic write (tmp → fsync → rename) with `0o600` permissions. Used for
/// `managed-agents.json`, which may carry plaintext agent nsecs.
pub fn atomic_write_restricted_with_fsync(path: &Path, payload: &[u8]) -> Result<(), String> {
    use atomic_write_file::AtomicWriteFile;
    use std::io::Write;

    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut file = AtomicWriteFile::open(&resolved)
        .map_err(|e| format!("open {} for atomic write: {e}", resolved.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("set {} permissions: {e}", resolved.display()))?;
    }

    file.write_all(payload)
        .map_err(|e| format!("write {}: {e}", resolved.display()))?;

    // AtomicWriteFile::commit() handles the rename; sync the temp fd first.
    // The `sync_before_close` feature isn't exposed, so we flush explicitly.
    file.flush()
        .map_err(|e| format!("flush {}: {e}", resolved.display()))?;
    file.commit()
        .map_err(|e| format!("commit {}: {e}", resolved.display()))
}
