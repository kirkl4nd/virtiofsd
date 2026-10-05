// SPDX-License-Identifier: BSD-3-Clause

//! `libc`, plus the few Linux definitions the rest of virtiofsd is written against.
//!
//! Modules that need them import this as `libc` on macOS. On Linux it is plain `libc`.
//!
//! macOS's `struct stat` and `struct statvfs` are narrower than Linux's (a 16-bit `st_mode`
//! and `st_nlink`, 32-bit `statvfs` block counts) and its `dev_t` encodes device numbers
//! differently. Rather than casting at every use, macOS gets Linux-shaped `stat64` and
//! `statvfs64` structures that are filled in once, where the host's are read, with device
//! numbers already in the Linux encoding that FUSE uses on the wire.

#![allow(non_camel_case_types)]

#[cfg(target_os = "macos")]
pub use libc::*;

// Named explicitly, so they take precedence over `libc`'s.
#[cfg(target_os = "macos")]
pub use macos::{
    dev_t, fstatvfs64, ino64_t, nlink_t, off64_t, stat64, statvfs64, O_PATH, S_IFBLK, S_IFCHR,
    S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, S_IRUSR, S_ISGID, S_IWUSR,
};

/// Encode a device number the way 64-bit glibc's `makedev()` does, which is also what the
/// low 32 bits of FUSE's `rdev` carry (the kernel's `new_encode_dev()`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn linux_makedev(major: u32, minor: u32) -> u64 {
    let (major, minor) = (u64::from(major), u64::from(minor));
    ((major & 0x0000_0fff) << 8)
        | ((major & 0xffff_f000) << 32)
        | (minor & 0x0000_00ff)
        | ((minor & 0xffff_ff00) << 12)
}

/// Split a FUSE `rdev` (the kernel's `new_encode_dev()`) into major and minor numbers.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn fuse_rdev_split(rdev: u32) -> (u32, u32) {
    let major = (rdev & 0x000f_ff00) >> 8;
    let minor = (rdev & 0x0000_00ff) | ((rdev >> 12) & 0x000f_ff00);
    (major, minor)
}

#[cfg(target_os = "macos")]
mod macos {
    use std::mem::MaybeUninit;

    /// macOS has no `O_PATH`.  Where virtiofsd keeps a descriptor only to refer to an inode, it
    /// opens it for event notification only (`O_EVTONLY`), which does not keep the volume from
    /// being unmounted, without blocking on FIFOs or acquiring a controlling terminal.  Unlike
    /// `O_PATH`, this needs read permission and actually opens the file, which is impossible for
    /// sockets.  Symbolic links are opened with `O_SYMLINK` in place of `O_NOFOLLOW`.
    pub const O_PATH: libc::c_int = libc::O_EVTONLY | libc::O_NONBLOCK | libc::O_NOCTTY;

    pub type ino64_t = u64;
    pub type off64_t = i64;
    pub type dev_t = u64;
    pub type nlink_t = u64;

    // `mode_t` is 16 bits on macOS; mode values are `u32` everywhere else in virtiofsd, as on
    // Linux. Syscalls that take a `mode_t` cast at the call.
    pub const S_IFMT: u32 = libc::S_IFMT as u32;
    pub const S_IFREG: u32 = libc::S_IFREG as u32;
    pub const S_IFDIR: u32 = libc::S_IFDIR as u32;
    pub const S_IFLNK: u32 = libc::S_IFLNK as u32;
    pub const S_IFIFO: u32 = libc::S_IFIFO as u32;
    pub const S_IFSOCK: u32 = libc::S_IFSOCK as u32;
    pub const S_IFCHR: u32 = libc::S_IFCHR as u32;
    pub const S_IFBLK: u32 = libc::S_IFBLK as u32;
    pub const S_ISGID: u32 = libc::S_ISGID as u32;
    pub const S_IRUSR: u32 = libc::S_IRUSR as u32;
    pub const S_IWUSR: u32 = libc::S_IWUSR as u32;

    /// Linux's `struct stat64`, with `st_rdev` in the Linux encoding.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct stat64 {
        pub st_dev: dev_t,
        pub st_ino: ino64_t,
        pub st_nlink: nlink_t,
        pub st_mode: u32,
        pub st_uid: libc::uid_t,
        pub st_gid: libc::gid_t,
        pub st_rdev: dev_t,
        pub st_size: off64_t,
        pub st_blksize: i64,
        pub st_blocks: i64,
        pub st_atime: i64,
        pub st_atime_nsec: i64,
        pub st_mtime: i64,
        pub st_mtime_nsec: i64,
        pub st_ctime: i64,
        pub st_ctime_nsec: i64,
    }

    impl From<&libc::stat> for stat64 {
        fn from(st: &libc::stat) -> Self {
            // Darwin's dev_t is a signed 32-bit value: 8 bits of major, 24 of minor.
            let darwin_dev = |dev: libc::dev_t| dev as u32;
            let rdev = darwin_dev(st.st_rdev);
            stat64 {
                st_dev: dev_t::from(darwin_dev(st.st_dev)),
                st_ino: st.st_ino,
                st_nlink: nlink_t::from(st.st_nlink),
                st_mode: u32::from(st.st_mode),
                st_uid: st.st_uid,
                st_gid: st.st_gid,
                st_rdev: super::linux_makedev(rdev >> 24, rdev & 0x00ff_ffff),
                st_size: st.st_size,
                st_blksize: i64::from(st.st_blksize),
                st_blocks: st.st_blocks,
                st_atime: st.st_atime,
                st_atime_nsec: st.st_atime_nsec,
                st_mtime: st.st_mtime,
                st_mtime_nsec: st.st_mtime_nsec,
                st_ctime: st.st_ctime,
                st_ctime_nsec: st.st_ctime_nsec,
            }
        }
    }

    /// The fields of Linux's `struct statvfs64` that FUSE reports.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct statvfs64 {
        pub f_bsize: u64,
        pub f_frsize: u64,
        pub f_blocks: u64,
        pub f_bfree: u64,
        pub f_bavail: u64,
        pub f_files: u64,
        pub f_ffree: u64,
        pub f_namemax: u64,
    }

    /// `fstatvfs64()` built on `fstatfs()`, whose counts are 64-bit (macOS's own `fstatvfs()`
    /// truncates them to 32 bits).
    ///
    /// # Safety
    ///
    /// `buf` must be valid for writing a `statvfs64`.
    pub unsafe fn fstatvfs64(fd: libc::c_int, buf: *mut statvfs64) -> libc::c_int {
        let mut sfs = MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: `sfs` is valid for writing a `statfs`.
        if unsafe { libc::fstatfs(fd, sfs.as_mut_ptr()) } != 0 {
            return -1;
        }
        // SAFETY: `fstatfs()` succeeded, so it has initialized `sfs`.
        let sfs = unsafe { sfs.assume_init() };
        // SAFETY: `fpathconf()` only reads `fd`.
        let namemax = unsafe { libc::fpathconf(fd, libc::_PC_NAME_MAX) };

        let st = statvfs64 {
            // As macOS's own fstatvfs(): `f_bsize` is the preferred I/O size, and the counts
            // are in units of the fundamental block size.
            f_bsize: sfs.f_iosize as u64,
            f_frsize: u64::from(sfs.f_bsize),
            f_blocks: sfs.f_blocks,
            f_bfree: sfs.f_bfree,
            f_bavail: sfs.f_bavail,
            f_files: sfs.f_files,
            f_ffree: sfs.f_ffree,
            f_namemax: if namemax > 0 { namemax as u64 } else { 255 },
        };
        // SAFETY: the caller guarantees `buf` is valid for writing.
        unsafe { buf.write(st) };
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_makedev_matches_the_kernel_encoding() {
        // new_encode_dev(MKDEV(8, 1)) for /dev/sda1, and a minor that needs the high bits.
        assert_eq!(linux_makedev(8, 1), 0x801);
        assert_eq!(linux_makedev(1, 0x12345), 0x1230_0145);
        for (major, minor) in [(0, 0), (8, 1), (136, 3), (0xfff, 0xfffff), (1, 0x12345)] {
            assert_eq!(
                fuse_rdev_split(linux_makedev(major, minor) as u32),
                (major, minor)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_makedev_matches_libc() {
        for (major, minor) in [
            (0, 0),
            (8, 1),
            (136, 3),
            (0xfff, 0xfffff),
            (0x1234, 0x567890),
        ] {
            assert_eq!(linux_makedev(major, minor), libc::makedev(major, minor));
        }
    }
}
