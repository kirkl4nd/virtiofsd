// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Inodes referenced by name (macOS).
//!
//! On Linux, virtiofsd keeps an `O_PATH` file descriptor for every inode, which can be opened for
//! any type of file, without permission to read it and without side effects.  macOS has nothing
//! equivalent: Opening a socket fails, opening a device node calls into its driver, opening a FIFO
//! makes it look like it had a reader, and opening anything requires read permission.  Such inodes
//! are referenced by their parent directory and their name in it instead, which is checked to
//! still refer to the same inode whenever it is used.

use crate::libc_compat as libc;
use crate::passthrough::guest_fd_limit::GuestFile;
use crate::passthrough::inode_store::InodeIds;
use crate::passthrough::stat::{statx, StatExt};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::sync::Mutex;

pub struct InodeName {
    location: Mutex<(GuestFile, CString)>,
}

impl InodeName {
    pub(crate) fn new(dir: GuestFile, name: &CStr) -> Self {
        InodeName {
            location: Mutex::new((dir, name.to_owned())),
        }
    }

    /// Change the inode's location to that of `other`, which must refer to the same inode.
    pub(crate) fn set_from(&self, other: InodeName) {
        *self.location.lock().unwrap() = other.location.into_inner().unwrap();
    }

    /// Call `f` with the inode's parent directory, its name, and its current stat information,
    /// after checking that the name still refers to the inode identified by `ids`.  Fails with
    /// `ESTALE` if it does not.
    pub(crate) fn with<T, F>(&self, ids: &InodeIds, f: F) -> io::Result<T>
    where
        F: FnOnce(&File, &CStr, StatExt) -> io::Result<T>,
    {
        let location = self.location.lock().unwrap();
        let (dir, name) = &*location;
        let st = statx(dir.get_file(), Some(name)).map_err(|err| {
            if err.raw_os_error() == Some(libc::ENOENT) {
                io::Error::from_raw_os_error(libc::ESTALE)
            } else {
                err
            }
        })?;
        if (st.st.st_dev, st.st.st_ino) != (ids.dev, ids.ino) {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        f(dir.get_file(), name, st)
    }
}
