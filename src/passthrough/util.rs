// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

#[cfg(target_os = "macos")]
use crate::libc_compat as libc;

use crate::util::{other_io_error, ErrorContext, ResultErrorContext};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{fmt, io};

/// Safe wrapper around libc::openat().
pub fn openat(dir_fd: &impl AsRawFd, path: &str, flags: libc::c_int) -> io::Result<File> {
    let path_cstr =
        CString::new(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Safe because:
    // - CString::new() has returned success and thus guarantees `path_cstr` is a valid
    //   NUL-terminated string
    // - this does not modify any memory
    // - we check the return value
    // We do not check `flags` because if the kernel cannot handle poorly specified flags then we
    // have much bigger problems.
    let fd = unsafe { libc::openat(dir_fd.as_raw_fd(), path_cstr.as_ptr(), flags) };
    if fd >= 0 {
        // Safe because we just opened this fd
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Same as `openat()`, but produces more verbose errors.
///
/// Do not use this for operations where the error is returned to the guest, as the raw OS error
/// value will be clobbered.
pub fn openat_verbose(dir_fd: &impl AsRawFd, path: &str, flags: libc::c_int) -> io::Result<File> {
    openat(dir_fd, path, flags).err_context(|| path)
}

/// Open `/proc/self/fd/{fd}` with the given flags to effectively duplicate the given `fd` with new
/// flags (e.g. to turn an `O_PATH` file descriptor into one that can be used for I/O).
#[cfg(target_os = "linux")]
pub fn reopen_fd_through_proc(
    fd: &impl AsRawFd,
    flags: libc::c_int,
    proc_self_fd: &File,
) -> io::Result<File> {
    // Clear the `O_NOFOLLOW` flag if it is set since we need to follow the `/proc/self/fd` symlink
    // to get the file.
    openat(
        proc_self_fd,
        format!("{}", fd.as_raw_fd()).as_str(),
        flags & !libc::O_NOFOLLOW,
    )
}

/// Returns true if it's safe to open this inode without O_PATH.
pub fn is_safe_inode(mode: u32) -> bool {
    // Only regular files and directories are considered safe to be opened from the file
    // server without O_PATH.
    matches!(mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR)
}

pub fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

pub fn einval() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

pub fn erofs() -> io::Error {
    io::Error::from_raw_os_error(libc::EROFS)
}

/**
 * Errors that `get_path_by_fd()` can encounter.
 *
 * This specialized error type exists so that
 * [`crate::passthrough::device_state::preserialization::proc_paths`] can decide which errors it
 * considers recoverable.
 */
#[derive(Debug)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) enum FdPathError {
    /// `readlinkat()` failed with the contained error.
    ReadLink(io::Error),

    /// Link name is too long.
    TooLong,

    /// Link name is not a valid C string.
    InvalidCString(io::Error),

    /// Returned path (contained string) is not a plain file path.
    NotAFile(String),

    /// Returned path (contained string) is reported to be deleted, i.e. no longer valid.
    Deleted(String),
}

/// Looks up an FD's path through /proc/self/fd
#[cfg(target_os = "linux")]
pub(crate) fn get_path_by_fd(
    fd: &impl AsRawFd,
    proc_self_fd: &impl AsRawFd,
) -> Result<CString, FdPathError> {
    let fname = format!("{}\0", fd.as_raw_fd());
    let fname_cstr = CStr::from_bytes_with_nul(fname.as_bytes()).unwrap();

    let max_len = libc::PATH_MAX as usize; // does not include final NUL byte
    let mut link_target = vec![0u8; max_len + 1]; // make space for NUL byte

    let ret = unsafe {
        libc::readlinkat(
            proc_self_fd.as_raw_fd(),
            fname_cstr.as_ptr(),
            link_target.as_mut_ptr().cast::<libc::c_char>(),
            max_len,
        )
    };
    if ret < 0 {
        return Err(FdPathError::ReadLink(io::Error::last_os_error()));
    } else if ret as usize == max_len {
        return Err(FdPathError::TooLong);
    }

    link_target.truncate(ret as usize + 1);
    let link_target_cstring = CString::from_vec_with_nul(link_target)
        .map_err(|err| FdPathError::InvalidCString(other_io_error(err)))?;
    let link_target_str = link_target_cstring.to_string_lossy();

    let pre_slash = link_target_str.split('/').next().unwrap();
    if pre_slash.contains(':') {
        return Err(FdPathError::NotAFile(link_target_str.into_owned()));
    }

    if let Some(path) = link_target_str.strip_suffix(" (deleted)") {
        return Err(FdPathError::Deleted(path.to_owned()));
    }

    Ok(link_target_cstring)
}

impl From<FdPathError> for io::Error {
    fn from(err: FdPathError) -> Self {
        match err {
            FdPathError::ReadLink(err) => err.context("readlink"),
            FdPathError::TooLong => other_io_error("Path returned from readlink is too long"),
            FdPathError::InvalidCString(err) => err.context("readlink returned invalid path"),
            FdPathError::NotAFile(path) => other_io_error(format!("Not a file ({path})")),
            FdPathError::Deleted(path) => other_io_error(format!("Inode deleted ({path})")),
        }
    }
}

impl fmt::Display for FdPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FdPathError::ReadLink(err) => write!(f, "readlink: {err}"),
            FdPathError::TooLong => write!(f, "Path returned from readlink is too long"),
            FdPathError::InvalidCString(err) => write!(f, "readlink returned invalid path: {err}"),
            FdPathError::NotAFile(path) => write!(f, "Not a file ({path})"),
            FdPathError::Deleted(path) => write!(f, "Inode deleted ({path})"),
        }
    }
}

impl std::error::Error for FdPathError {}

/// Debugging helper function: Turn the given file descriptor into a string representation we can
/// show the user.  If `proc_self_fd` is given, try to obtain the actual path through the symlink
/// in /proc/self/fd; otherwise (or on error), just print the integer representation (as
/// "{fd:%i}").
pub fn printable_fd(fd: &impl AsRawFd, proc_self_fd: Option<&impl AsRawFd>) -> String {
    if let Some(Ok(path)) = proc_self_fd.map(|psf| get_path_by_fd(fd, psf)) {
        match path.into_string() {
            Ok(s) => s,
            Err(err) => err.into_cstring().to_string_lossy().into_owned(),
        }
    } else {
        format!("{{fd:{}}}", fd.as_raw_fd())
    }
}

pub fn relative_path<'a>(path: &'a CStr, prefix: &CStr) -> io::Result<&'a CStr> {
    let mut relative_path = path
        .to_bytes_with_nul()
        .strip_prefix(prefix.to_bytes())
        .ok_or_else(|| {
            other_io_error(format!(
                "Path {path:?} is outside the directory ({prefix:?})"
            ))
        })?;

    // Remove leading / if left
    while let Some(prefixless) = relative_path.strip_prefix(b"/") {
        relative_path = prefixless;
    }

    // Must succeed: Was a `CStr` before, converted to `&[u8]` via `to_bytes_with_nul()`, so must
    // still contain exactly one NUL byte at the end of the slice
    Ok(CStr::from_bytes_with_nul(relative_path).unwrap())
}

/// `fstat()` into the Linux-shaped `stat64`.
#[cfg(target_os = "macos")]
fn fstat(fd: &impl AsRawFd) -> io::Result<libc::stat64> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // Safe because this only writes to `st` and we check the return value.
    if unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safe because `fstat()` has initialized `st`.
    Ok(libc::stat64::from(unsafe { &st.assume_init() }))
}

/// The path of the file `fd` refers to, from `fcntl(F_GETPATH)`.  macOS keeps the name a vnode
/// was last reached by, so the path may be stale: anything opened by it must be checked to be
/// the same inode as `fd`.
#[cfg(target_os = "macos")]
fn fd_path(fd: &impl AsRawFd) -> io::Result<CString> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // Safe because `F_GETPATH` writes at most `PATH_MAX` bytes into `buf`, and we check the
    // return value.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf.truncate(len);
    CString::new(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Open `path` relative to `dir` (no symbolic link may be part of it), and check that it is the
/// inode `st` describes, or fail with `ESTALE`.  `O_TRUNC` is applied only after the check.
#[cfg(target_os = "macos")]
pub(crate) fn open_same_inode(
    dir: &impl AsRawFd,
    path: &CStr,
    flags: libc::c_int,
    st: &libc::stat64,
) -> io::Result<File> {
    let open = |flags| -> io::Result<File> {
        let path = path
            .to_str()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let file = openat(
            dir,
            path,
            flags & !(libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC)
                | libc::O_NOFOLLOW_ANY,
        )?;
        let new_st = fstat(&file)?;
        if (new_st.st_dev, new_st.st_ino) != (st.st_dev, st.st_ino) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok(file)
    };

    let file = open(flags)?;
    if flags & libc::O_TRUNC != 0 {
        if flags & libc::O_ACCMODE == libc::O_RDONLY {
            open(libc::O_WRONLY | libc::O_CLOEXEC)?.set_len(0)?;
        } else {
            file.set_len(0)?;
        }
    }
    Ok(file)
}

/// macOS has no `/proc/self/fd`.  A directory is reopened through its `.` entry.  Anything else
/// is reopened by the path that `fcntl(F_GETPATH)` reports, without following symbolic links, and
/// the result must be the same inode, or this fails with `ESTALE` (the guest then looks the file
/// up again).  This also means that unlinked files cannot be reopened.
#[cfg(target_os = "macos")]
pub fn reopen_fd_through_proc(
    fd: &impl AsRawFd,
    flags: libc::c_int,
    _proc_self_fd: &File,
) -> io::Result<File> {
    let st = fstat(fd)?;
    if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
        let flags = flags & !(libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL);
        return openat(fd, ".", flags | libc::O_DIRECTORY);
    }
    open_same_inode(&libc::AT_FDCWD, &fd_path(fd)?, flags, &st)
}

/// macOS has no `/proc/self/fd`; get the path from `fcntl(F_GETPATH)` instead.
#[cfg(target_os = "macos")]
pub(crate) fn get_path_by_fd(
    fd: &impl AsRawFd,
    _proc_self_fd: &impl AsRawFd,
) -> Result<CString, FdPathError> {
    let path = fd_path(fd).map_err(FdPathError::ReadLink)?;
    if fstat(fd).map_err(FdPathError::ReadLink)?.st_nlink == 0 {
        return Err(FdPathError::Deleted(path.to_string_lossy().into_owned()));
    }
    Ok(path)
}

/// Create a hard link `newdir`/`newname` to the inode that `fd` refers to.
///
/// Linux links the `/proc/self/fd` entry.  macOS links the inode by the name `fcntl(F_GETPATH)`
/// reports, relative to its parent directory, after checking that the name still is that inode.
#[cfg(target_os = "macos")]
pub fn link_fd_at(fd: &impl AsRawFd, newdir: &impl AsRawFd, newname: &CStr) -> io::Result<()> {
    let st = fstat(fd)?;
    let path = fd_path(fd)?;
    let bytes = path.as_bytes();
    let slash = bytes
        .iter()
        .rposition(|&b| b == b'/')
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ESTALE))?;
    let parent = CString::new(if slash == 0 {
        &b"/"[..]
    } else {
        &bytes[..slash]
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let name = CString::new(&bytes[slash + 1..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let parent = openat(
        &libc::AT_FDCWD,
        parent
            .to_str()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY | libc::O_CLOEXEC,
    )?;
    let entry = crate::passthrough::stat::statx(&parent, Some(&name))?.st;
    if (entry.st_dev, entry.st_ino) != (st.st_dev, st.st_ino) {
        return Err(io::Error::from_raw_os_error(libc::ESTALE));
    }

    // Safe because this doesn't modify any memory and we check the return value.
    let res = unsafe {
        libc::linkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            newdir.as_raw_fd(),
            newname.as_ptr(),
            0,
        )
    };
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Translate the guest's `lseek()` `whence` (Linux's values) to the host's.  Linux and macOS
/// agree on `SEEK_SET`, `SEEK_CUR` and `SEEK_END`, but swap `SEEK_DATA` (3 on Linux) and
/// `SEEK_HOLE` (4 on Linux).
#[cfg(target_os = "macos")]
pub fn host_seek_whence(whence: u32) -> io::Result<libc::c_int> {
    match whence {
        0 => Ok(libc::SEEK_SET),
        1 => Ok(libc::SEEK_CUR),
        2 => Ok(libc::SEEK_END),
        3 => Ok(libc::SEEK_DATA),
        4 => Ok(libc::SEEK_HOLE),
        _ => Err(einval()),
    }
}

/// Linux's `fallocate()` mode flags, which are what FUSE carries.
#[cfg(target_os = "macos")]
const FALLOC_FL_KEEP_SIZE: u32 = 0x01;

/// `fallocate()` for macOS, which only has `fcntl(F_PREALLOCATE)` (allocation beyond the end of
/// the file) and `ftruncate()`.
///
/// Mode 0 (allocate and extend) and `FALLOC_FL_KEEP_SIZE` (allocate only) are supported; any
/// other mode, e.g. hole punching, fails with `EOPNOTSUPP`, after which the guest falls back to
/// writing.  Preallocation is best-effort on Apple filesystems: if a filesystem does not support
/// it, the range is not reserved, but `ENOSPC` is reported.
#[cfg(target_os = "macos")]
pub fn fallocate(fd: &impl AsRawFd, mode: u32, offset: u64, length: u64) -> io::Result<()> {
    if mode & !FALLOC_FL_KEEP_SIZE != 0 {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    let end = offset
        .checked_add(length)
        .filter(|&end| end <= i64::MAX as u64)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EFBIG))?;

    let size = fstat(fd)?.st_size as u64;
    if end <= size {
        return Ok(());
    }

    // `F_PEOFPOSMODE` counts from the end of the file, so `fst_offset` must be 0.
    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATECONTIG,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: (end - size) as libc::off_t,
        fst_bytesalloc: 0,
    };
    // Safe because this only accesses `store`, and we check the return value.
    let mut res = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_PREALLOCATE, &mut store) };
    if res < 0 {
        store.fst_flags = libc::F_ALLOCATEALL;
        // Safe because this only accesses `store`, and we check the return value.
        res = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_PREALLOCATE, &mut store) };
    }
    if res < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSPC) {
            return Err(err);
        }
    }

    if mode & FALLOC_FL_KEEP_SIZE == 0 {
        // Safe because this doesn't modify any memory and we check the return value.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), end as libc::off_t) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
