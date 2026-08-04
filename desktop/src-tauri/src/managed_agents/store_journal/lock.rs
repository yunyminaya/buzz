//! Interprocess advisory lock (RAII guard).
//!
//! Unix: `flock(2)`.  Windows: named mutex.  Other platforms: no-op.

use std::path::Path;

use super::anchor::ADVISORY_LOCK_FILENAME;

/// RAII guard for the interprocess advisory lock.
pub struct JournalLockGuard {
    #[cfg(unix)]
    #[allow(dead_code)]
    file: std::fs::File,
    #[cfg(windows)]
    mutex_handle: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(not(any(unix, windows)))]
    _phantom: (),
}

impl JournalLockGuard {
    /// Acquire the exclusive advisory lock for `anchor_dir`, blocking until
    /// the lock is available.
    pub fn acquire(anchor_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(anchor_dir)
            .map_err(|e| format!("create anchor dir {}: {e}", anchor_dir.display()))?;
        let lock_path = anchor_dir.join(ADVISORY_LOCK_FILENAME);

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&lock_path)
                .map_err(|e| format!("open journal lock {}: {e}", lock_path.display()))?;
            let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(format!("journal flock {}: {err}", lock_path.display()));
            }
            Ok(JournalLockGuard { file })
        }

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            // Derive a unique mutex name from the lock file path.
            let path_str = lock_path
                .to_str()
                .unwrap_or("buzz-store-journal")
                .replace(['\\', '/', ':'], "-");
            let name: Vec<u16> = std::ffi::OsStr::new(&format!("Global\\{path_str}"))
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let handle = unsafe {
                windows_sys::Win32::System::Threading::CreateMutexW(
                    std::ptr::null_mut(),
                    0,
                    name.as_ptr(),
                )
            };
            if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                return Err(format!("CreateMutexW failed for journal lock"));
            }
            let wait = unsafe {
                windows_sys::Win32::System::Threading::WaitForSingleObject(
                    handle,
                    windows_sys::Win32::System::Threading::INFINITE,
                )
            };
            // WAIT_OBJECT_0 (0x00) — acquired normally.
            // WAIT_ABANDONED (0x80) — prior holder crashed; mutex ownership
            //   transferred to us.  The journal may be in an intermediate state;
            //   boot recovery will repair it.  Treating this as a failure would
            //   permanently deadlock on a crashed-holder scenario — the exact
            //   case this substrate exists to handle.
            // WAIT_FAILED (0xFFFFFFFF) or any other value — genuine error.
            const WAIT_OBJECT_0: u32 = 0x00000000;
            const WAIT_ABANDONED: u32 = 0x00000080;
            if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
                let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
                return Err(format!(
                    "WaitForSingleObject failed: wait={wait:#010x} last_error={err}"
                ));
            }
            if wait == WAIT_ABANDONED {
                eprintln!(
                    "buzz-desktop: journal lock: acquired abandoned mutex — \
                     prior holder crashed, boot recovery will repair state"
                );
            }
            return Ok(JournalLockGuard {
                mutex_handle: handle,
            });
        }

        #[cfg(not(any(unix, windows)))]
        {
            Ok(JournalLockGuard { _phantom: () })
        }
    }
}

#[cfg(windows)]
impl Drop for JournalLockGuard {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.mutex_handle);
            windows_sys::Win32::Foundation::CloseHandle(self.mutex_handle);
        }
    }
}
