// Copyright 2020 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#[cfg(target_os = "macos")]
use crate::libc_compat as libc;

use crate::filesystem::{DirEntry, DirectoryIterator};

#[cfg(target_os = "macos")]
use std::convert::TryInto;
use std::ffi::CStr;
use std::io;
#[cfg(target_os = "linux")]
use std::mem::size_of;
use std::ops::{Deref, DerefMut};
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "linux")]
use log::debug;

#[cfg(target_os = "linux")]
use vm_memory::ByteValued;

#[cfg(target_os = "linux")]
#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct LinuxDirent64 {
    d_ino: libc::ino64_t,
    d_off: libc::off64_t,
    d_reclen: libc::c_ushort,
    d_ty: libc::c_uchar,
}
#[cfg(target_os = "linux")]
unsafe impl ByteValued for LinuxDirent64 {}

#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct ReadDir<P> {
    buf: P,
    current: usize,
    end: usize,
}

#[cfg(target_os = "linux")]
impl<P: DerefMut<Target = [u8]>> ReadDir<P> {
    /// Seek to `offset` in the directory and read a batch of entries.
    ///
    /// For offsets that exceed `i64::MAX` (e.g., AWS EFS cookies with the
    /// high bit set), the `u64`-to-`off64_t` cast produces a negative value,
    /// which the kernel rejects. In that case we fall back to scan from the
    /// beginning and move forward to the target cookie.
    pub fn new<D: AsRawFd>(dir: &D, offset: u64, buf: P) -> io::Result<Self> {
        // SAFETY: Safe because this doesn't modify any memory and we check the return value.
        // The possible wrapping of the `u64` to `i64` cast is intended.
        let res =
            unsafe { libc::lseek64(dir.as_raw_fd(), offset as libc::off64_t, libc::SEEK_SET) };
        if res >= 0 {
            return unsafe { Self::new_no_seek(dir, buf) };
        }

        // Only fall back for `EINVAL` caused by a large offset.
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINVAL) || offset <= i64::MAX as u64 {
            return Err(err);
        }

        debug!("lseek64 failed for directory offset {offset:#x}, falling back to linear scan");

        Self::new_walk_to(dir, offset, buf)
    }

    /// Fallback for offsets that `lseek64` cannot handle: rewinds and walks
    /// entries until the target cookie.
    fn new_walk_to<D: AsRawFd>(dir: &D, target_offset: u64, mut buf: P) -> io::Result<Self> {
        // SAFETY: Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lseek64(dir.as_raw_fd(), 0, libc::SEEK_SET) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        loop {
            let mut rd = unsafe { Self::new_no_seek(dir, buf)? };
            if rd.remaining() == 0 {
                return Ok(rd); // not found
            }

            // `d_off` is an opaque cookie interpretable only by the filesystem
            // that generated it. It may be supplied as an offset to `lseek()`
            // to position the directory stream after the current entry (not at it).
            // So to resume from a given cookie, we must skip past the entry with
            // `d_off == target_offset`, and return everything that follows.
            if rd.move_past(target_offset) {
                if rd.remaining() > 0 {
                    return Ok(rd); // found
                }
                // it's last in this batch, fd is already at the next one
                return unsafe { Self::new_no_seek(dir, rd.buf) };
            }

            buf = rd.buf; // not in this batch
        }
    }

    /// Move past `target_offset`. Everything remaining is what the guest has not yet received.
    fn move_past(&mut self, target_offset: u64) -> bool {
        while let Some(entry) = DirectoryIterator::next(self) {
            if entry.offset == target_offset {
                return true;
            }
        }
        false
    }

    /// Continue reading from the current position in the directory without seeking.
    ///
    /// # Safety
    /// Caller must ensure the current position is valid, for example, by exclusively using this
    /// function on a given FD, potentially repeatedly.
    pub unsafe fn new_no_seek<D: AsRawFd>(dir: &D, mut buf: P) -> io::Result<Self> {
        // Safe because the kernel guarantees that it will only write to `buf` and we check the
        // return value.
        let res = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                dir.as_raw_fd(),
                buf.as_mut_ptr() as *mut LinuxDirent64,
                buf.len() as libc::c_int,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(ReadDir {
            buf,
            current: 0,
            end: res as usize,
        })
    }
}

/// Offset of `d_name` in Darwin's `struct dirent`. The compiler would pad a
/// `#[repr(C)]` struct to 24 bytes; the kernel layout has the name at 21.
#[cfg(target_os = "macos")]
const DIRENT_NAME_OFF: usize = 21;

#[cfg(target_os = "macos")]
extern "C" {
    fn __getdirentries64(
        fd: libc::c_int,
        buf: *mut libc::c_void,
        bufsize: libc::size_t,
        basep: *mut libc::off_t,
    ) -> libc::ssize_t;
}

/// macOS's `d_seekoff` is 0 on APFS, so the guest's FUSE cookie is a 1-based
/// count of entries already returned. Each call rewinds and skips that many.
#[cfg(target_os = "macos")]
pub struct ReadDir<P> {
    buf: P,
    current: usize,
    end: usize,
    next_index: u64,
}

#[cfg(target_os = "macos")]
impl<P> Default for ReadDir<P>
where
    P: Default,
{
    fn default() -> Self {
        ReadDir {
            buf: P::default(),
            current: 0,
            end: 0,
            next_index: 0,
        }
    }
}

#[cfg(target_os = "macos")]
impl<P: DerefMut<Target = [u8]>> ReadDir<P> {
    pub fn new<D: AsRawFd>(dir: &D, offset: u64, buf: P) -> io::Result<Self> {
        let res = unsafe { libc::lseek(dir.as_raw_fd(), 0, libc::SEEK_SET) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut rd = unsafe { Self::new_no_seek(dir, buf)? };
        if offset == 0 {
            return Ok(rd);
        }
        let mut skipped = 0u64;
        loop {
            while DirectoryIterator::next(&mut rd).is_some() {
                skipped += 1;
                if skipped == offset {
                    if rd.remaining() > 0 {
                        rd.next_index = offset;
                        return Ok(rd);
                    }
                    // Last in this batch; the fd is already at the next one.
                    let mut next = unsafe { Self::new_no_seek(dir, rd.buf)? };
                    next.next_index = offset;
                    return Ok(next);
                }
            }
            let buf = rd.buf;
            rd = unsafe { Self::new_no_seek(dir, buf)? };
            if rd.remaining() == 0 {
                rd.next_index = offset;
                return Ok(rd);
            }
        }
    }

    /// # Safety
    /// Caller must ensure the current position is valid, for example, by exclusively using this
    /// function on a given FD, potentially repeatedly.
    pub unsafe fn new_no_seek<D: AsRawFd>(dir: &D, mut buf: P) -> io::Result<Self> {
        let mut basep: libc::off_t = 0;
        let res = unsafe {
            __getdirentries64(
                dir.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                &mut basep,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ReadDir {
            buf,
            current: 0,
            end: res as usize,
            next_index: 0,
        })
    }
}

#[cfg(target_os = "macos")]
impl<P: Deref<Target = [u8]>> DirectoryIterator for ReadDir<P> {
    fn next(&mut self) -> Option<DirEntry<'_>> {
        let rem = &self.buf[self.current..self.end];
        if rem.len() < DIRENT_NAME_OFF {
            return None;
        }
        let d_ino = u64::from_ne_bytes(rem[0..8].try_into().unwrap());
        let d_reclen = u16::from_ne_bytes(rem[16..18].try_into().unwrap()) as usize;
        let d_namlen = u16::from_ne_bytes(rem[18..20].try_into().unwrap()) as usize;
        let d_type = rem[20];
        if d_reclen == 0 || d_reclen > rem.len() {
            return None;
        }
        let name_end = DIRENT_NAME_OFF + d_namlen;
        if name_end > rem.len() {
            return None;
        }
        let name = if name_end < rem.len() && rem[name_end] == 0 {
            unsafe { CStr::from_bytes_with_nul_unchecked(&rem[DIRENT_NAME_OFF..=name_end]) }
        } else {
            strip_padding(&rem[DIRENT_NAME_OFF..name_end])
        };
        self.current += d_reclen;
        self.next_index += 1;
        Some(DirEntry {
            ino: d_ino,
            offset: self.next_index,
            type_: u32::from(d_type),
            name,
        })
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_test {
    use super::*;
    use std::fs;
    use vmm_sys_util::tempdir::TempDir;

    fn collect(directory: &fs::File) -> Vec<(u64, String)> {
        let mut entries = Vec::new();
        let mut offset = 0u64;
        loop {
            let mut rd = ReadDir::new(directory, offset, vec![0u8; 4096]).unwrap();
            if rd.remaining() == 0 {
                break;
            }
            while let Some(e) = DirectoryIterator::next(&mut rd) {
                offset = e.offset;
                entries.push((e.offset, e.name.to_string_lossy().into_owned()));
            }
        }
        entries
    }

    #[test]
    fn readdir_resumes_from_cookie() {
        let td = TempDir::new_with_prefix("/tmp/virtiofsd_test_").unwrap();
        for i in 0..200 {
            fs::write(td.as_path().join(format!("file_{i:03}")), b"").unwrap();
        }
        let file = fs::File::open(td.as_path()).unwrap();
        let all = collect(&file);
        assert!(all.len() >= 202, "got {}", all.len());
        for mid in [0, all.len() / 2, all.len() - 2] {
            let cookie = all[mid].0;
            let mut rd = ReadDir::new(&file, cookie, vec![0u8; 256]).unwrap();
            let first = DirectoryIterator::next(&mut rd).expect("entry after cookie");
            assert_eq!(first.name.to_string_lossy(), all[mid + 1].1);
            assert_eq!(first.offset, all[mid + 1].0);
        }
    }
}

impl<P> ReadDir<P> {
    /// Returns the number of bytes from the internal buffer that have not yet been consumed.
    pub fn remaining(&self) -> usize {
        self.end.saturating_sub(self.current)
    }
}

#[cfg(target_os = "linux")]
impl<P: Deref<Target = [u8]>> DirectoryIterator for ReadDir<P> {
    fn next(&mut self) -> Option<DirEntry<'_>> {
        let rem = &self.buf[self.current..self.end];
        if rem.is_empty() {
            return None;
        }

        // We only use debug asserts here because these values are coming from the kernel and we
        // trust them implicitly.
        debug_assert!(
            rem.len() >= size_of::<LinuxDirent64>(),
            "not enough space left in `rem`"
        );

        let (front, back) = rem.split_at(size_of::<LinuxDirent64>());

        let dirent64 =
            LinuxDirent64::from_slice(front).expect("unable to get LinuxDirent64 from slice");

        let namelen = dirent64.d_reclen as usize - size_of::<LinuxDirent64>();
        debug_assert!(namelen <= back.len(), "back is smaller than `namelen`");

        // The kernel will pad the name with additional nul bytes until it is 8-byte aligned so
        // we need to strip those off here.
        let name = strip_padding(&back[..namelen]);
        let entry = DirEntry {
            ino: dirent64.d_ino,
            offset: dirent64.d_off as u64,
            type_: dirent64.d_ty as u32,
            name,
        };

        debug_assert!(
            rem.len() >= dirent64.d_reclen as usize,
            "rem is smaller than `d_reclen`"
        );
        self.current += dirent64.d_reclen as usize;

        Some(entry)
    }
}

// Like `CStr::from_bytes_with_nul` but strips any bytes after the first '\0'-byte. Panics if `b`
// doesn't contain any '\0' bytes.
fn strip_padding(b: &[u8]) -> &CStr {
    // It would be nice if we could use memchr here but that's locked behind an unstable gate.
    let pos = b
        .iter()
        .position(|&c| c == 0)
        .expect("`b` doesn't contain any nul bytes");

    // Safe because we are creating this string with the first nul-byte we found so we can
    // guarantee that it is nul-terminated and doesn't contain any interior nuls.
    unsafe { CStr::from_bytes_with_nul_unchecked(&b[..=pos]) }
}

#[cfg(all(test, target_os = "linux"))]
mod test {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use vmm_sys_util::tempdir::TempDir;

    fn make_test_dir(num_files: usize) -> (TempDir, fs::File) {
        let td = TempDir::new_with_prefix("/tmp/virtiofsd_test_").unwrap();
        for i in 0..num_files {
            fs::write(td.as_path().join(format!("file_{i:03}")), b"").unwrap();
        }
        let file = fs::File::open(td.as_path()).unwrap();
        (td, file)
    }

    /// Build a fake `ReadDir` from raw dirent fields.
    /// `entry` is `(d_ino, d_off, name)`.
    fn build_dirent_buf(entries: &[(u64, u64, &[u8])]) -> ReadDir<Vec<u8>> {
        let header = size_of::<LinuxDirent64>();
        let mut buf = vec![0u8; 4096];
        let mut pos = 0;
        for &(ino, d_off, name) in entries {
            let reclen = (header + name.len() + 1).next_multiple_of(8);
            let dirent = LinuxDirent64 {
                d_ino: ino,
                d_off: d_off as i64,
                d_reclen: reclen as libc::c_ushort,
                d_ty: libc::DT_REG,
            };
            assert!(
                pos + reclen <= buf.len(),
                "dirent buffer overflow: need {} bytes but buf is {}",
                pos + reclen,
                buf.len()
            );
            buf[pos..pos + header].copy_from_slice(dirent.as_slice());
            buf[pos + header..pos + header + name.len()].copy_from_slice(name);
            pos += reclen;
        }
        ReadDir {
            buf,
            current: 0,
            end: pos,
        }
    }

    fn next_entry(rd: &mut ReadDir<Vec<u8>>) -> Option<(u64, u64, CString)> {
        let e = rd.next()?;
        Some((e.ino, e.offset, e.name.to_owned()))
    }

    /// Read all entries from `directory`. Returns `(d_ino, d_off, name)` tuples.
    fn collect_entries(directory: &fs::File) -> Vec<(u64, u64, CString)> {
        let mut entries = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let mut rd = ReadDir::new(directory, offset, vec![0u8; 4096]).unwrap();
            if rd.remaining() == 0 {
                break;
            }
            while let Some(e) = next_entry(&mut rd) {
                offset = e.1;
                entries.push(e);
            }
        }
        entries
    }

    #[test]
    fn padded_cstrings() {
        assert_eq!(strip_padding(b".\0\0\0\0\0\0\0").to_bytes(), b".");
        assert_eq!(strip_padding(b"..\0\0\0\0\0\0").to_bytes(), b"..");
        assert_eq!(
            strip_padding(b"normal cstring\0").to_bytes(),
            b"normal cstring"
        );
        assert_eq!(strip_padding(b"\0\0\0\0").to_bytes(), b"");
        assert_eq!(
            strip_padding(b"interior\0nul bytes\0\0\0").to_bytes(),
            b"interior"
        );
    }

    #[test]
    #[should_panic(expected = "`b` doesn't contain any nul bytes")]
    fn no_nul_byte() {
        strip_padding(b"no nul bytes in string");
    }

    #[test]
    fn move_past_finds_target_in_middle() {
        let mut rd = build_dirent_buf(&[(1, 100, b"a"), (2, 200, b"b"), (3, 300, b"c")]);
        assert!(ReadDir::move_past(&mut rd, 200));
        let e = next_entry(&mut rd).unwrap();
        assert_eq!((e.0, e.1), (3, 300));
    }

    #[test]
    fn move_past_finds_target_at_end() {
        let mut rd = build_dirent_buf(&[(1, 100, b"a"), (2, 200, b"b")]);
        assert!(ReadDir::move_past(&mut rd, 200));
        assert_eq!(rd.remaining(), 0);
    }

    #[test]
    fn move_past_not_found() {
        let mut rd = build_dirent_buf(&[(1, 100, b"a"), (2, 200, b"b")]);
        assert!(!ReadDir::move_past(&mut rd, 999));
        assert_eq!(rd.remaining(), 0);
    }

    #[test]
    fn move_past_large_cookie() {
        let large = u64::MAX - 42;
        let mut rd = build_dirent_buf(&[(1, 100, b"a"), (2, large, b"b"), (3, 300, b"c")]);
        assert!(ReadDir::move_past(&mut rd, large));
        let e = next_entry(&mut rd).unwrap();
        assert_eq!((e.0, e.1), (3, 300));
    }

    #[test]
    fn new_walk_to_matches_lseek_path() {
        let (_td, file) = make_test_dir(10);
        let all = collect_entries(&file);

        for (_, cookie, _) in all.iter().take(all.len().saturating_sub(1)) {
            let mut rd_seek = ReadDir::new(&file, *cookie, vec![0u8; 4096]).unwrap();
            let mut rd_walk = ReadDir::new_walk_to(&file, *cookie, vec![0u8; 4096]).unwrap();

            loop {
                match (next_entry(&mut rd_seek), next_entry(&mut rd_walk)) {
                    (None, None) => break,
                    (Some(a), Some(b)) => assert_eq!(a, b, "mismatch at cookie {}", cookie),
                    _ => panic!("entry count mismatch at cookie {}", cookie),
                }
            }
        }
    }

    #[test]
    fn new_walk_to_small_buffer() {
        let (_td, file) = make_test_dir(20);
        let all = collect_entries(&file);

        for window in all.windows(2) {
            let cookie = window[0].1;
            let mut rd = ReadDir::new_walk_to(&file, cookie, vec![0u8; 128]).unwrap();
            let e = next_entry(&mut rd).expect("expected entry after cookie");
            assert_eq!(e.0, window[1].0, "ino mismatch at cookie {}", cookie);
        }
    }

    #[test]
    fn new_falls_back_to_walk_for_large_offset() {
        let (_td, file) = make_test_dir(1);
        let rd = ReadDir::new(&file, u64::MAX, vec![0u8; 4096]).unwrap();
        assert_eq!(rd.remaining(), 0);
    }
}
