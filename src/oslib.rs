// SPDX-License-Identifier: BSD-3-Clause

use crate::soft_idmap::{HostGid, HostUid, Id};
use bitflags::bitflags;
use std::ffi::CStr;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Error, Result};
use std::os::unix::io::{AsRawFd, BorrowedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::prelude::FromRawFd;

// A helper function that check the return value of a C function call
// and wraps it in a `Result` type, returning the `errno` code as `Err`.
fn check_retval<T: From<i8> + PartialEq>(t: T) -> Result<T> {
    if t == T::from(-1_i8) {
        Err(Error::last_os_error())
    } else {
        Ok(t)
    }
}

/// Simple object to collect basic facts about the OS,
/// such as available syscalls.
#[cfg(target_os = "linux")]
pub struct OsFacts {
    pub has_openat2: bool,
}

#[cfg(target_os = "linux")]
#[allow(clippy::new_without_default)]
impl OsFacts {
    /// This object should only be constructed using new.
    #[must_use]
    #[cfg(target_os = "linux")]
    pub fn new() -> Self {
        // Checking for `openat2()` since it first appeared in Linux 5.6.
        // SAFETY: all-zero byte-pattern is a valid `libc::open_how`
        let how: libc::open_how = unsafe { std::mem::zeroed() };
        let cwd = CString::new(".").unwrap();
        // SAFETY: `cwd.as_ptr()` points to a valid NUL-terminated string,
        // and the `how` pointer is a valid pointer to an `open_how` struct.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                cwd.as_ptr(),
                std::ptr::addr_of!(how),
                std::mem::size_of::<libc::open_how>(),
            )
        };

        let has_openat2 = fd >= 0;
        if has_openat2 {
            // SAFETY: `fd` is an open file descriptor
            unsafe {
                libc::close(fd as libc::c_int);
            }
        }

        Self { has_openat2 }
    }
}

/// Safe wrapper for `mount(2)`
///
/// # Errors
///
/// Will return `Err(errno)` if `mount(2)` fails.
/// Each filesystem type may have its own special errors and its own special behavior,
/// see `mount(2)` and the linux source kernel for details.
///
/// # Panics
///
/// This function panics if the strings `source`, `target` or `fstype` contain an internal 0 byte.
#[cfg(target_os = "linux")]
pub fn mount(source: Option<&str>, target: &str, fstype: Option<&str>, flags: u64) -> Result<()> {
    let source = CString::new(source.unwrap_or("")).unwrap();
    let source = source.as_ptr();

    let target = CString::new(target).unwrap();
    let target = target.as_ptr();

    let fstype = CString::new(fstype.unwrap_or("")).unwrap();
    let fstype = fstype.as_ptr();

    // Safety: `source`, `target` or `fstype` are a valid C string pointers
    check_retval(unsafe { libc::mount(source, target, fstype, flags, std::ptr::null()) })?;
    Ok(())
}

/// Safe wrapper for `umount2(2)`
///
/// # Errors
///
/// Will return `Err(errno)` if `umount2(2)` fails.
/// Each filesystem type may have its own special errors and its own special behavior,
/// see `umount2(2)` and the linux source kernel for details.
///
/// # Panics
///
/// This function panics if the strings `target` contains an internal 0 byte.
#[cfg(target_os = "linux")]
pub fn umount2(target: &str, flags: i32) -> Result<()> {
    let target = CString::new(target).unwrap();
    let target = target.as_ptr();

    // Safety: `target` is a valid C string pointer
    check_retval(unsafe { libc::umount2(target, flags) })?;
    Ok(())
}

/// Safe wrapper for `fchdir(2)`
///
/// # Errors
///
/// Will return `Err(errno)` if `fchdir(2)` fails.
/// Each filesystem type may have its own special errors, see `fchdir(2)` for details.
pub fn fchdir(fd: RawFd) -> Result<()> {
    check_retval(unsafe { libc::fchdir(fd) })?;
    Ok(())
}

/// Safe wrapper for `fchmod(2)`
///
/// # Errors
///
/// Will return `Err(errno)` if `fchmod(2)` fails.
/// Each filesystem type may have its own special errors, see `fchmod(2)` for details.
pub fn fchmod(fd: RawFd, mode: u32) -> Result<()> {
    check_retval(unsafe { libc::fchmod(fd, mode as libc::mode_t) })?;
    Ok(())
}

/// Safe wrapper for `fchmodat(2)`
///
/// # Errors
///
/// Will return `Err(errno)` if `fchmodat(2)` fails.
/// Each filesystem type may have its own special errors, see `fchmodat(2)` for details.
#[cfg(target_os = "linux")]
pub fn fchmodat(dirfd: RawFd, pathname: String, mode: u32, flags: i32) -> Result<()> {
    let pathname =
        CString::new(pathname).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let pathname = pathname.as_ptr();

    check_retval(unsafe { libc::fchmodat(dirfd, pathname, mode, flags) })?;
    Ok(())
}

/// Safe wrapper for `umask(2)`
pub fn umask(mask: u32) -> u32 {
    // SAFETY: this call doesn't modify any memory and there is no need
    // to check the return value because this system call always succeeds.
    #[allow(clippy::useless_conversion)]
    let old_mask = unsafe { libc::umask(mask as libc::mode_t) }.into();
    old_mask
}

/// An RAII implementation of a scoped file mode creation mask (umask), it set the
/// new umask. When this structure is dropped (falls out of scope), it set the previous
/// value of the mask.
pub struct ScopedUmask {
    umask: u32,
}

impl ScopedUmask {
    pub fn new(new_umask: impl Into<u32>) -> Self {
        Self {
            umask: umask(new_umask.into()),
        }
    }
}

impl Drop for ScopedUmask {
    fn drop(&mut self) {
        umask(self.umask);
    }
}

/// Safe wrapper around `openat(2)`.
///
/// # Errors
///
/// Will return `Err(errno)` if `openat(2)` fails,
/// see `openat(2)` for details.
pub fn openat(dir: &impl AsRawFd, pathname: &CStr, flags: i32, mode: Option<u32>) -> Result<RawFd> {
    let mode = u64::from(mode.unwrap_or(0));

    // SAFETY: `pathname` points to a valid NUL-terminated string.
    // However, the caller must ensure that `dir` can provide a valid file descriptor.
    check_retval(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            pathname.as_ptr(),
            flags as libc::c_int,
            mode,
        )
    })
}

/// Safe wrapper around `open_tree(2)`.
///
/// # Errors
///
/// Will return `Err(errno)` if `open_tree(2)` fails,
/// see `open_tree(2)` for details.
#[cfg(target_os = "linux")]
pub fn open_tree(dir: Option<&dyn AsRawFd>, pathname: &CStr, flags: u32) -> Result<RawFd> {
    let fd = dir.map(AsRawFd::as_raw_fd).unwrap_or(libc::AT_FDCWD);

    // SAFETY: `libc::syscall` is called with the correct arity and types.
    // `pathname` points to a valid NUL-terminated string.
    // `fd` is guaranteed to be a valid file descriptor or AT_FDCWD.
    check_retval(
        unsafe { libc::syscall(libc::SYS_open_tree, fd, pathname.as_ptr(), flags) } as RawFd,
    )
}

// libc does not define this on musl.
// https://github.com/rust-lang/libc/pull/3534#discussion_r2573036200
#[cfg(target_os = "linux")]
pub const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x00000004;

/// Safe wrapper around `move_mount(2)`.
///
/// # Errors
///
/// Will return `Err(errno)` if `move_mount(2)` fails,
/// see `move_mount(2)` for details.
#[cfg(target_os = "linux")]
pub fn move_mount(
    from_dir: Option<&dyn AsRawFd>,
    from_path: &CStr,
    to_dir: Option<&dyn AsRawFd>,
    to_path: &CStr,
    flags: u32,
) -> Result<()> {
    let from_fd = from_dir.map(AsRawFd::as_raw_fd).unwrap_or(libc::AT_FDCWD);
    let to_fd = to_dir.map(AsRawFd::as_raw_fd).unwrap_or(libc::AT_FDCWD);

    // SAFETY: `libc::syscall` is called with the correct arity and types.
    // `from_path` and `to_path` point to valid NUL-terminated strings.
    // `from_fd` and `to_fd` are guaranteed to be valid file descirptors or AT_FDCWD.
    check_retval(unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            from_fd,
            from_path.as_ptr(),
            to_fd,
            to_path.as_ptr(),
            flags,
        )
    })?;

    Ok(())
}

/// An utility function that uses `openat2(2)` to restrict the how the provided pathname
/// is resolved. It uses the following flags:
/// - `RESOLVE_IN_ROOT`: Treat the directory referred to by dirfd as the root directory while
///   resolving pathname. This has the effect as though virtiofsd had used chroot(2) to modify its
///   root directory to dirfd.
/// - `RESOLVE_NO_MAGICLINKS`: Disallow all magic-link (i.e., proc(2) link-like files) resolution
///   during path resolution.
///
/// Additionally, the flags `O_NOFOLLOW` and `O_CLOEXEC` are added.
///
/// # Error
///
/// Will return `Err(errno)` if `openat2(2)` fails, see the man page for details.
///
/// # Safety
///
/// The caller must ensure that dirfd is a valid file descriptor.
#[cfg(target_os = "linux")]
pub fn do_open_relative_to(
    dir: &impl AsRawFd,
    pathname: &CStr,
    flags: i32,
    mode: Option<u32>,
) -> Result<RawFd> {
    // `openat2(2)` returns an error if `how.mode` contains bits other than those in range 07777,
    // let's ignore the extra bits to be compatible with `openat(2)`.
    let mode = u64::from(mode.unwrap_or(0)) & 0o7777;

    // SAFETY: all-zero byte-pattern represents a valid `libc::open_how`
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.resolve = libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS;
    how.flags = flags as u64;
    how.mode = mode;

    // SAFETY: `pathname` points to a valid NUL-terminated string, and the `how` pointer is a valid
    // pointer to an `open_how` struct. However, the caller must ensure that `dir` can provide a
    // valid file descriptor (this can be changed to BorrowedFd).
    check_retval(unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            pathname.as_ptr(),
            std::ptr::addr_of!(how),
            std::mem::size_of::<libc::open_how>(),
        )
    } as RawFd)
}

mod filehandle {
    use crate::passthrough::file_handle::SerializableFileHandle;
    use crate::util::other_io_error;
    use std::convert::{TryFrom, TryInto};
    use std::io;

    const MAX_HANDLE_SZ: usize = 128;

    #[derive(Clone, PartialOrd, Ord, PartialEq, Eq)]
    #[repr(C)]
    pub struct CFileHandle {
        handle_bytes: libc::c_uint,
        handle_type: libc::c_int,
        f_handle: [u8; MAX_HANDLE_SZ],
    }

    impl Default for CFileHandle {
        fn default() -> Self {
            CFileHandle {
                handle_bytes: MAX_HANDLE_SZ as libc::c_uint,
                handle_type: 0,
                f_handle: [0; MAX_HANDLE_SZ],
            }
        }
    }

    impl CFileHandle {
        pub fn as_bytes(&self) -> &[u8] {
            &self.f_handle[..(self.handle_bytes as usize)]
        }

        pub fn handle_type(&self) -> libc::c_int {
            self.handle_type
        }
    }

    impl TryFrom<&SerializableFileHandle> for CFileHandle {
        type Error = io::Error;

        fn try_from(sfh: &SerializableFileHandle) -> io::Result<Self> {
            let sfh_bytes = sfh.as_bytes();
            if sfh_bytes.len() > MAX_HANDLE_SZ {
                return Err(other_io_error("File handle too long"));
            }
            let mut f_handle = [0u8; MAX_HANDLE_SZ];
            f_handle[..sfh_bytes.len()].copy_from_slice(sfh_bytes);

            Ok(CFileHandle {
                handle_bytes: sfh_bytes.len().try_into().map_err(|err| {
                    other_io_error(format!(
                        "Handle size ({} bytes) too big: {err}",
                        sfh_bytes.len(),
                    ))
                })?,
                #[allow(clippy::useless_conversion)]
                handle_type: sfh.handle_type().try_into().map_err(|err| {
                    other_io_error(format!(
                        "Handle type (0x{:x}) too large: {err}",
                        sfh.handle_type(),
                    ))
                })?,
                f_handle,
            })
        }
    }

    #[cfg(target_os = "linux")]
    extern "C" {
        pub fn name_to_handle_at(
            dirfd: libc::c_int,
            pathname: *const libc::c_char,
            file_handle: *mut CFileHandle,
            mount_id: *mut libc::c_int,
            flags: libc::c_int,
        ) -> libc::c_int;

        // Technically `file_handle` should be a `mut` pointer, but `open_by_handle_at()` is specified
        // not to change it, so we can declare it `const`.
        pub fn open_by_handle_at(
            mount_fd: libc::c_int,
            file_handle: *const CFileHandle,
            flags: libc::c_int,
        ) -> libc::c_int;
    }
}
pub use filehandle::CFileHandle;

#[cfg(target_os = "linux")]
pub fn name_to_handle_at(
    dirfd: &impl AsRawFd,
    pathname: &CStr,
    file_handle: &mut CFileHandle,
    mount_id: &mut libc::c_int,
    flags: libc::c_int,
) -> Result<()> {
    // SAFETY: `dirfd` is a valid file descriptor, `file_handle`
    // is a valid reference to `CFileHandle`, and `mount_id` is
    // valid reference to an `int`
    check_retval(unsafe {
        filehandle::name_to_handle_at(
            dirfd.as_raw_fd(),
            pathname.as_ptr(),
            file_handle,
            mount_id,
            flags,
        )
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn open_by_handle_at(
    mount_fd: &impl AsRawFd,
    file_handle: &CFileHandle,
    flags: libc::c_int,
) -> Result<File> {
    // SAFETY: `mount_fd` is a valid file descriptor and `file_handle`
    // is a valid reference to `CFileHandle`
    let fd = check_retval(unsafe {
        filehandle::open_by_handle_at(mount_fd.as_raw_fd(), file_handle, flags)
    })?;

    // SAFETY: `open_by_handle_at()` guarantees `fd` is a valid file descriptor
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
bitflags! {
    /// A bitwise OR of zero or more flags passed in as a parameter to the
    /// write vectored function `writev_at()`.
    pub struct WritevFlags: i32 {
        /// High priority writes. Allows block-based filesystems to use polling of the device, which
        /// provides lower latency, but may use additional resources. (Currently, this feature is
        /// usable only on a file descriptor opened using the `O_DIRECT` flag.)
        const RWF_HIPRI = libc::RWF_HIPRI;

        /// Provide a per-write equivalent of the `O_DSYNC` `open(2)` flag. Its effect applies
        /// only to the data range written by the system call.
        const RWF_DSYNC = libc::RWF_DSYNC;

        /// Provide a per-write equivalent of the `O_SYNC` `open(2)` flag. Its effect applies only
        /// to the data range written by the system call.
        const RWF_SYNC = libc::RWF_SYNC;

        /// Provide a per-write equivalent of the `O_APPEND` `open(2)` flag. Its effect applies only
        /// to the data range written by the system call. The offset argument does not affect the
        /// write operation; the data is always appended to the end of the file.
        /// However, if the offset argument is -1, the current file offset is updated.
        const RWF_APPEND = libc::RWF_APPEND;

        /// Do not honor the `O_APPEND` `open(2)` flag (since Linux 6.9).
        const RWF_NOAPPEND = libc::RWF_NOAPPEND;

        /// Requires that writes to regular files in block-based filesystems be issued with
        /// torn-write protection. Torn-write protection means that for a power or any other
        /// hardware failure, all or none of the data from the write will be stored, but never a
        /// mix of old and new data (since Linux 6.11).
        const RWF_ATOMIC = libc::RWF_ATOMIC;

        /// Uncached buffered write (since Linux 6.14).
        const RWF_DONTCACHE = libc::RWF_DONTCACHE;
    }
}

#[cfg(target_os = "linux")]
bitflags! {
    /// A bitwise OR of zero or more flags passed in as a parameter to the
    /// read vectored function `readv_at()`.
    pub struct ReadvFlags: i32 {
        /// High priority read. Allows block-based filesystems to use polling of the device, which
        /// provides lower latency, but may use additional resources. (Currently, this feature is
        /// usable only on a file descriptor opened using the O_DIRECT flag.)
        const RWF_HIPRI = libc::RWF_HIPRI;

        /// Do not wait for data which is not immediately available. If this flag is specified,
        /// the `readv_at()` will return instantly if it would have to read data from the backing
        /// storage or wait for a lock. If some data was successfully read, it will return the
        /// number of bytes read. If no bytes were read, it will return -1 and set errno to
        /// `EAGAIN`.
        const RWF_NOWAIT = libc::RWF_NOWAIT;

        /// Uncached buffered read, any data read will be removed from the page cache upon
        /// completion (since Linux 6.14).
        const RWF_DONTCACHE = libc::RWF_DONTCACHE;
    }
}

/// Safe wrapper for `pwritev2(2)`
///
/// This system call is similar `pwritev(2)`, but add a new argument,
/// flags, which modifies the behavior on a per-call basis.
/// Unlike `pwritev(2)`, if the offset argument is -1, then the current file offset
/// is used and updated.
///
/// # Errors
///
/// Will return `Err(errno)` if `pwritev2(2)` fails, see `pwritev2(2)` for details.
///
/// # Safety
///
/// The caller must ensure that each iovec element is valid (i.e., it has a valid `iov_base`
/// pointer and `iov_len`).
#[cfg(target_os = "linux")]
pub unsafe fn writev_at(
    fd: BorrowedFd,
    iovecs: &[libc::iovec],
    offset: i64,
    flags: Option<WritevFlags>,
) -> Result<usize> {
    let flags = flags.unwrap_or(WritevFlags::empty());
    // SAFETY: `fd` is a valid filed descriptor, `iov` is a valid pointer
    // to the iovec slice `ìovecs` of `iovcnt` elements. However, the caller
    // must ensure that each iovec element has a valid `iov_base` pointer and `iov_len`.
    let bytes_written = check_retval(unsafe {
        libc::pwritev2(
            fd.as_raw_fd(),
            iovecs.as_ptr(),
            iovecs.len() as libc::c_int,
            offset,
            flags.bits(),
        )
    })?;
    Ok(bytes_written as usize)
}

/// Safe wrapper for `preadv2(2)`
///
/// This system call is similar `preadv(2)`, but add a new argument,
/// flags, which modifies the behavior on a per-call basis.
/// Unlike `preadv(2)`, if the offset argument is -1, then the current file offset
/// is used and updated.
///
/// # Errors
///
/// Will return `Err(errno)` if `preadv2(2)` fails, see `preadv2(2)` for details.
///
/// # Safety
///
/// The caller must ensure that each iovec element is valid (i.e., it has a valid `iov_base`
/// pointer and `iov_len`).
#[cfg(target_os = "linux")]
pub unsafe fn readv_at(
    fd: BorrowedFd,
    iovecs: &[libc::iovec],
    offset: i64,
    flags: Option<ReadvFlags>,
) -> Result<usize> {
    let flags = flags.unwrap_or(ReadvFlags::empty());
    // SAFETY: `fd` is a valid filed descriptor, `iov` is a valid pointer
    // to the iovec slice `ìovecs` of `iovcnt` elements. However, the caller
    // must ensure that each iovec element has a valid `iov_base` pointer and `iov_len`.
    let bytes_read = check_retval(unsafe {
        libc::preadv2(
            fd.as_raw_fd(),
            iovecs.as_ptr(),
            iovecs.len() as libc::c_int,
            offset,
            flags.bits(),
        )
    })?;
    Ok(bytes_read as usize)
}

pub struct PipeReader(File);

impl io::Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

pub struct PipeWriter(File);

impl io::Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[cfg(target_os = "linux")]
pub fn pipe() -> io::Result<(PipeReader, PipeWriter)> {
    let mut fds: [RawFd; 2] = [-1, -1];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok((
            PipeReader(unsafe { File::from_raw_fd(fds[0]) }),
            PipeWriter(unsafe { File::from_raw_fd(fds[1]) }),
        ))
    }
}

// We want credential changes to be per-thread because otherwise
// we might interfere with operations being carried out on other
// threads with different uids/gids. However, posix requires that
// all threads in a process share the same credentials. To do this
// libc uses signals to ensure that when one thread changes its
// credentials the other threads do the same thing.
//
// So instead we invoke the syscall directly in order to get around
// this limitation. Another option is to use the setfsuid and
// setfsgid systems calls. However since those calls have no way to
// return an error, it's preferable to do this instead.
/// Set effective user ID
#[cfg(target_os = "linux")]
pub fn seteffuid(uid: HostUid) -> io::Result<()> {
    check_retval(unsafe { libc::syscall(libc::SYS_setresuid, -1, uid.into_inner(), -1) })?;
    Ok(())
}

/// Set effective group ID
#[cfg(target_os = "linux")]
pub fn seteffgid(gid: HostGid) -> io::Result<()> {
    check_retval(unsafe { libc::syscall(libc::SYS_setresgid, -1, gid.into_inner(), -1) })?;
    Ok(())
}

/// Set supplementary group
#[cfg(target_os = "linux")]
pub fn setsupgroup(gids: &[HostGid]) -> io::Result<()> {
    check_retval(unsafe {
        libc::syscall(
            libc::SYS_setgroups,
            gids.len(),
            // Safe because `HostGid` is exactly `libc::gid_t` with `repr(transparent)`
            gids.as_ptr() as *const libc::gid_t,
        )
    })?;
    Ok(())
}

/// Drop all supplementary groups
#[cfg(target_os = "linux")]
pub fn dropsupgroups() -> io::Result<()> {
    check_retval(unsafe {
        libc::syscall(libc::SYS_setgroups, 0, std::ptr::null::<libc::gid_t>())
    })?;
    Ok(())
}

/// macOS has no file handles.  Report them unsupported, as Linux does for filesystems that have
/// none, so the caller falls back to keeping file descriptors.
#[cfg(target_os = "macos")]
pub fn name_to_handle_at(
    _dirfd: &impl AsRawFd,
    _pathname: &CStr,
    _file_handle: &mut CFileHandle,
    _mount_id: &mut libc::c_int,
    _flags: libc::c_int,
) -> Result<()> {
    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
}

#[cfg(target_os = "macos")]
pub fn open_by_handle_at(
    _mount_fd: &impl AsRawFd,
    _file_handle: &CFileHandle,
    _flags: libc::c_int,
) -> Result<File> {
    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
}

#[cfg(target_os = "macos")]
bitflags! {
    /// A bitwise OR of zero or more flags passed in as a parameter to the
    /// write vectored function `writev_at()`.
    pub struct WritevFlags: i32 {
        /// Append the data to the end of the file, ignoring the offset.
        const RWF_APPEND = 0x1;
    }
}

#[cfg(target_os = "macos")]
bitflags! {
    /// A bitwise OR of zero or more flags passed in as a parameter to the
    /// read vectored function `readv_at()`.  macOS has none.
    pub struct ReadvFlags: i32 {
    }
}

/// `pwritev(2)`, or `writev(2)` for `RWF_APPEND`.
///
/// macOS has no `pwritev2()`.  It does, unlike Linux, ignore `O_APPEND` for positional writes, so
/// `RWF_APPEND` sets `O_APPEND` on `fd` (if necessary) and uses `writev()`; this does not affect
/// any `pwritev()` on the same file.
///
/// # Errors
///
/// Will return `Err(errno)` if the write fails.
///
/// # Safety
///
/// The caller must ensure that each iovec element is valid (i.e., it has a valid `iov_base`
/// pointer and `iov_len`).
#[cfg(target_os = "macos")]
pub unsafe fn writev_at(
    fd: BorrowedFd,
    iovecs: &[libc::iovec],
    offset: i64,
    flags: Option<WritevFlags>,
) -> Result<usize> {
    let append = flags.is_some_and(|f| f.contains(WritevFlags::RWF_APPEND));
    if append {
        // SAFETY: `fd` is a valid file descriptor.
        let fl = check_retval(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) })?;
        if fl & libc::O_APPEND == 0 {
            // SAFETY: `fd` is a valid file descriptor.
            check_retval(unsafe {
                libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_APPEND)
            })?;
        }
    }
    let iovcnt = iovecs.len() as libc::c_int;
    // SAFETY: `fd` is a valid file descriptor, `iovecs` is a valid slice of `iovcnt` elements,
    // and the caller ensures that each element is valid.
    let bytes_written = check_retval(unsafe {
        if append {
            libc::writev(fd.as_raw_fd(), iovecs.as_ptr(), iovcnt)
        } else {
            libc::pwritev(fd.as_raw_fd(), iovecs.as_ptr(), iovcnt, offset)
        }
    })?;
    Ok(bytes_written as usize)
}

/// `preadv(2)`: macOS has no `preadv2()`, and no `ReadvFlags`.
///
/// # Errors
///
/// Will return `Err(errno)` if `preadv(2)` fails.
///
/// # Safety
///
/// The caller must ensure that each iovec element is valid (i.e., it has a valid `iov_base`
/// pointer and `iov_len`).
#[cfg(target_os = "macos")]
pub unsafe fn readv_at(
    fd: BorrowedFd,
    iovecs: &[libc::iovec],
    offset: i64,
    _flags: Option<ReadvFlags>,
) -> Result<usize> {
    // SAFETY: `fd` is a valid file descriptor, `iovecs` is a valid slice, and the caller ensures
    // that each element is valid.
    let bytes_read = check_retval(unsafe {
        libc::preadv(
            fd.as_raw_fd(),
            iovecs.as_ptr(),
            iovecs.len() as libc::c_int,
            offset,
        )
    })?;
    Ok(bytes_read as usize)
}

#[cfg(target_os = "macos")]
extern "C" {
    // <unistd.h>.  Deprecated, but it is the only way to change one thread's credentials.
    fn pthread_setugid_np(uid: libc::uid_t, gid: libc::gid_t) -> libc::c_int;
    // <unistd.h>
    fn fsync_volume_np(fd: libc::c_int, flags: libc::c_int) -> libc::c_int;
}

/// `KAUTH_UID_NONE` and `KAUTH_GID_NONE` (`<sys/kauth.h>`): passed to `pthread_setugid_np()`, they
/// return the thread to the process's credentials.
#[cfg(target_os = "macos")]
const KAUTH_UID_NONE: libc::uid_t = !0 - 100;
#[cfg(target_os = "macos")]
const KAUTH_GID_NONE: libc::gid_t = !0 - 100;

/// Give the calling thread its own effective UID and GID.
///
/// macOS's `setresuid()` and friends always change the whole process, so this uses
/// `pthread_setugid_np()`.  The thread's group list becomes `gid` plus the groups that the
/// directory service gives `uid`; there is no per-thread `setgroups()`.  Requires the process to
/// run as root.  Undo with `revert_thread_credentials()` before calling this again.
#[cfg(target_os = "macos")]
pub fn set_thread_credentials(uid: HostUid, gid: HostGid) -> io::Result<()> {
    // SAFETY: this call does not touch memory.
    check_retval(unsafe { pthread_setugid_np(uid.into_inner(), gid.into_inner()) })?;
    Ok(())
}

/// Return the calling thread to the process's credentials.
#[cfg(target_os = "macos")]
pub fn revert_thread_credentials() -> io::Result<()> {
    // SAFETY: this call does not touch memory.
    check_retval(unsafe { pthread_setugid_np(KAUTH_UID_NONE, KAUTH_GID_NONE) })?;
    Ok(())
}

/// Linux's `XATTR_CREATE` and `XATTR_REPLACE`, the values FUSE carries for `setxattr()`.
const LINUX_XATTR_CREATE: libc::c_int = 0x1;
const LINUX_XATTR_REPLACE: libc::c_int = 0x2;

/// macOS reports a missing attribute as `ENOATTR`; Linux, and so the rest of virtiofsd and the
/// guest, as `ENODATA`.
#[cfg(target_os = "macos")]
fn xattr_error() -> io::Error {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOATTR) => io::Error::from_raw_os_error(libc::ENODATA),
        _ => err,
    }
}

#[cfg(target_os = "linux")]
fn xattr_error() -> io::Error {
    io::Error::last_os_error()
}

fn xattr_retval(ret: isize) -> io::Result<usize> {
    if ret < 0 {
        Err(xattr_error())
    } else {
        Ok(ret as usize)
    }
}

/// Safe wrapper for `fsetxattr(2)`.  `flags` are Linux's (`XATTR_CREATE`, `XATTR_REPLACE`).
pub fn fsetxattr(fd: &impl AsRawFd, name: &CStr, value: &[u8], flags: libc::c_int) -> Result<()> {
    if flags & !(LINUX_XATTR_CREATE | LINUX_XATTR_REPLACE) != 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }

    // SAFETY: `name` is a valid C string, `value` a valid slice, and we check the return value.
    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::fsetxattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            flags,
        )
    };

    #[cfg(target_os = "macos")]
    let ret = {
        let mut darwin_flags = 0;
        if flags & LINUX_XATTR_CREATE != 0 {
            darwin_flags |= libc::XATTR_CREATE;
        }
        if flags & LINUX_XATTR_REPLACE != 0 {
            darwin_flags |= libc::XATTR_REPLACE;
        }
        // SAFETY: `name` is a valid C string, `value` a valid slice, and we check the return
        // value.
        unsafe {
            libc::fsetxattr(
                fd.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
                darwin_flags,
            )
        }
    };

    xattr_retval(ret as isize).map(|_| ())
}

/// A buffer for the extended attribute calls: `NULL` if empty, which queries the size needed.
fn xattr_buf(buf: &mut [u8]) -> *mut u8 {
    if buf.is_empty() {
        std::ptr::null_mut()
    } else {
        buf.as_mut_ptr()
    }
}

/// Safe wrapper for `fgetxattr(2)`.  An empty `buf` queries the value's size.
pub fn fgetxattr(fd: &impl AsRawFd, name: &CStr, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: `name` is a valid C string, the call writes at most `buf.len()` bytes into `buf`,
    // and we check the return value.
    let ret = unsafe {
        libc::fgetxattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            xattr_buf(buf) as *mut libc::c_void,
            buf.len(),
            #[cfg(target_os = "macos")]
            0,
            #[cfg(target_os = "macos")]
            0,
        )
    };
    xattr_retval(ret)
}

/// Safe wrapper for `flistxattr(2)`.  An empty `buf` queries the list's size.
pub fn flistxattr(fd: &impl AsRawFd, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: the call writes at most `buf.len()` bytes into `buf`, and we check the return value.
    let ret = unsafe {
        libc::flistxattr(
            fd.as_raw_fd(),
            xattr_buf(buf) as *mut libc::c_char,
            buf.len(),
            #[cfg(target_os = "macos")]
            0,
        )
    };
    xattr_retval(ret)
}

/// Safe wrapper for `fremovexattr(2)`.
pub fn fremovexattr(fd: &impl AsRawFd, name: &CStr) -> Result<()> {
    // SAFETY: `name` is a valid C string, and we check the return value.
    let ret = unsafe {
        libc::fremovexattr(
            fd.as_raw_fd(),
            name.as_ptr(),
            #[cfg(target_os = "macos")]
            0,
        )
    };
    xattr_retval(ret as isize).map(|_| ())
}

/// Linux's `renameat2()` flags, which are what FUSE carries.
#[cfg(target_os = "macos")]
const LINUX_RENAME_NOREPLACE: u32 = 1 << 0;
#[cfg(target_os = "macos")]
pub(crate) const LINUX_RENAME_EXCHANGE: u32 = 1 << 1;

/// Safe wrapper for `renameat2(2)`.  `flags` are Linux's.
pub fn renameat2(
    olddir: &impl AsRawFd,
    oldname: &CStr,
    newdir: &impl AsRawFd,
    newname: &CStr,
    flags: u32,
) -> Result<()> {
    // TODO: Switch to libc::renameat2 once https://github.com/rust-lang/libc/pull/1508 lands
    // and we have glibc 2.28.
    // SAFETY: the names are valid C strings, and we check the return value.
    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            olddir.as_raw_fd(),
            oldname.as_ptr(),
            newdir.as_raw_fd(),
            newname.as_ptr(),
            flags,
        )
    };

    #[cfg(target_os = "macos")]
    let ret = {
        // RENAME_WHITEOUT has no macOS equivalent.
        if flags & !(LINUX_RENAME_NOREPLACE | LINUX_RENAME_EXCHANGE) != 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mut darwin_flags = 0;
        if flags & LINUX_RENAME_NOREPLACE != 0 {
            darwin_flags |= libc::RENAME_EXCL;
        }
        if flags & LINUX_RENAME_EXCHANGE != 0 {
            darwin_flags |= libc::RENAME_SWAP;
        }
        // SAFETY: the names are valid C strings, and we check the return value.
        unsafe {
            libc::renameatx_np(
                olddir.as_raw_fd(),
                oldname.as_ptr(),
                newdir.as_raw_fd(),
                newname.as_ptr(),
                darwin_flags,
            )
        }
    };

    check_retval(ret)?;
    Ok(())
}

/// Safe wrapper for `mknodat(2)`.  `rdev` is a FUSE device number (Linux's encoding).
pub fn mknodat(dir: &impl AsRawFd, name: &CStr, mode: u32, rdev: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    let dev = libc::dev_t::from(rdev);

    #[cfg(target_os = "macos")]
    let dev = {
        // Darwin's dev_t has 8 bits of major and 24 of minor.
        let (major, minor) = crate::libc_compat::fuse_rdev_split(rdev);
        if major > 0xff || minor > 0x00ff_ffff {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        ((major << 24) | minor) as libc::dev_t
    };

    // SAFETY: `name` is a valid C string, and we check the return value.
    check_retval(unsafe {
        libc::mknodat(dir.as_raw_fd(), name.as_ptr(), mode as libc::mode_t, dev)
    })?;
    Ok(())
}

/// Read the target of the symbolic link that `fd` refers to (an `O_PATH` descriptor on Linux, an
/// `O_SYMLINK` one on macOS).
pub fn freadlink(fd: &impl AsRawFd, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: the call writes at most `buf.len()` bytes into `buf`, and we check the return value.
    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::readlinkat(
            fd.as_raw_fd(),
            CStr::from_bytes_with_nul_unchecked(b"\0").as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };

    // SAFETY: the call writes at most `buf.len()` bytes into `buf`, and we check the return value.
    #[cfg(target_os = "macos")]
    let ret = unsafe {
        libc::freadlink(
            fd.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    } as isize;

    Ok(check_retval(ret)? as usize)
}

/// Flush a file's data (`datasync`) or data and metadata to stable storage.
///
/// On macOS, `fsync()` only hands the data to the drive, which may keep it in a volatile cache;
/// `F_FULLFSYNC` also flushes that cache, which is what the guest is asking for.  It does both
/// data and metadata.  Filesystems that do not support it get `fsync()`.
pub fn fsync(fd: &impl AsRawFd, datasync: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: this call does not touch memory.
    check_retval(unsafe {
        if datasync {
            libc::fdatasync(fd.as_raw_fd())
        } else {
            libc::fsync(fd.as_raw_fd())
        }
    })?;

    #[cfg(target_os = "macos")]
    {
        let _ = datasync;
        // SAFETY: this call does not touch memory.
        if let Err(err) = check_retval(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_FULLFSYNC) }) {
            match err.raw_os_error() {
                Some(libc::ENOTSUP) | Some(libc::EINVAL) | Some(libc::ENOTTY) => {
                    // SAFETY: this call does not touch memory.
                    check_retval(unsafe { libc::fsync(fd.as_raw_fd()) })?;
                }
                _ => return Err(err),
            }
        }
    }

    Ok(())
}

/// Flush the filesystem that `fd` is on, see `syncfs(2)`.
pub fn syncfs(fd: &impl AsRawFd) -> Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: this call does not touch memory.
    check_retval(unsafe { libc::syncfs(fd.as_raw_fd()) })?;

    #[cfg(target_os = "macos")]
    {
        // <unistd.h>
        const SYNC_VOLUME_FULLSYNC: libc::c_int = 0x01;
        const SYNC_VOLUME_WAIT: libc::c_int = 0x02;
        // SAFETY: this call does not touch memory.
        check_retval(unsafe {
            fsync_volume_np(fd.as_raw_fd(), SYNC_VOLUME_FULLSYNC | SYNC_VOLUME_WAIT)
        })?;
    }

    Ok(())
}
