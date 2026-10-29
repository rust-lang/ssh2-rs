use libc::{c_int, c_long, c_uint, c_ulong, size_t};
use parking_lot::{Mutex, MutexGuard};
use std::convert::TryFrom;
use std::ffi::CString;
use std::io::prelude::*;
use std::io::{self, ErrorKind, SeekFrom};
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::Arc;

use util;
use {raw, Error, ErrorCode, SessionInner};

/// A handle to a remote filesystem over SFTP.
///
/// Instances are created through the `sftp` method on a `Session`.
pub struct Sftp {
    inner: Option<Arc<SftpInnerDropWrapper>>,
}
/// This contains an Option so that we're able to disable the Drop hook when dropping manually,
/// while still dropping all the fields of SftpInner (which we couldn't do with `mem::forget`)
struct SftpInnerDropWrapper(Option<SftpInner>);
struct SftpInner {
    raw: *mut raw::LIBSSH2_SFTP,
    sess: Arc<Mutex<SessionInner>>,
}

// Sftp is both Send and Sync; the compiler can't see it because it
// is pessimistic about the raw pointer.  We use Arc/Mutex to guard accessing
// the raw pointer so we are safe for both.
unsafe impl Send for Sftp {}
unsafe impl Sync for Sftp {}

struct LockedSftp<'sftp> {
    raw: *mut raw::LIBSSH2_SFTP,
    sess: MutexGuard<'sftp, SessionInner>,
}

/// A file handle to an SFTP connection.
///
/// Files behave similarly to `std::old_io::File` in that they are readable and
/// writable and support operations like stat and seek.
///
/// Files are created through `open`, `create`, and `open_mode` on an instance
/// of `Sftp`.
pub struct File {
    inner: Option<FileInner>,
}
struct FileInner {
    raw: *mut raw::LIBSSH2_SFTP_HANDLE,
    sftp: Arc<SftpInnerDropWrapper>,
}

// File is both Send and Sync; the compiler can't see it because it
// is pessimistic about the raw pointer.  We use Arc/Mutex to guard accessing
// the raw pointer so we are safe for both.
unsafe impl Send for File {}
unsafe impl Sync for File {}

struct LockedFile<'file> {
    raw: *mut raw::LIBSSH2_SFTP_HANDLE,
    sess: MutexGuard<'file, SessionInner>,
}

/// Metadata information about a remote file.
///
/// Fields are not necessarily all provided
#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_copy_implementations)]
pub struct FileStat {
    /// File size, in bytes of the file.
    pub size: Option<u64>,
    /// Owner ID of the file
    pub uid: Option<u32>,
    /// Owning group of the file
    pub gid: Option<u32>,
    /// Permissions (mode) of the file
    pub perm: Option<u32>,
    /// Last access time of the file
    pub atime: Option<u64>,
    /// Last modification time of the file
    pub mtime: Option<u64>,
}

/// An enum representing a type of file.
#[derive(PartialEq)]
pub enum FileType {
    /// Named pipe (S_IFIFO)
    NamedPipe,
    /// Character device (S_IFCHR)
    CharDevice,
    /// Block device (S_IFBLK)
    BlockDevice,
    /// Directory (S_IFDIR)
    Directory,
    /// Regular file (S_IFREG)
    RegularFile,
    /// Symbolic link (S_IFLNK)
    Symlink,
    /// Unix domain socket (S_IFSOCK)
    Socket,
    /// Other filetype (does not correspond to any of the other ones)
    Other(c_ulong),
}

bitflags! {
    /// Options that can be used to configure how a file is opened
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct OpenFlags: c_ulong {
        /// Open the file for reading.
        const READ = raw::LIBSSH2_FXF_READ;
        /// Open the file for writing. If both this and `Read` are specified,
        /// the file is opened for both reading and writing.
        const WRITE = raw::LIBSSH2_FXF_WRITE;
        /// Force all writes to append data at the end of the file.
        const APPEND = raw::LIBSSH2_FXF_APPEND;
        /// If this flag is specified, then a new file will be created if one
        /// does not already exist (if `Truncate` is specified, the new file
        /// will be truncated to zero length if it previously exists).
        const CREATE = raw::LIBSSH2_FXF_CREAT;
        /// Forces an existing file with the same name to be truncated to zero
        /// length when creating a file by specifying `Create`. Using this flag
        /// implies the `Create` flag.
        const TRUNCATE = raw::LIBSSH2_FXF_TRUNC | Self::CREATE.bits();
        /// Causes the request to fail if the named file already exists. Using
        /// this flag implies the `Create` flag.
        const EXCLUSIVE = raw::LIBSSH2_FXF_EXCL | Self::CREATE.bits();
    }
}

bitflags! {
    /// Options to `Sftp::rename`.
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct RenameFlags: c_long {
        /// In a rename operation, overwrite the destination if it already
        /// exists. If this flag is not present then it is an error if the
        /// destination already exists.
        const OVERWRITE = raw::LIBSSH2_SFTP_RENAME_OVERWRITE;
        /// Inform the remote that an atomic rename operation is desired if
        /// available.
        const ATOMIC = raw::LIBSSH2_SFTP_RENAME_ATOMIC;
        /// Inform the remote end that the native system calls for renaming
        /// should be used.
        const NATIVE = raw::LIBSSH2_SFTP_RENAME_NATIVE;
    }
}

/// How to open a file handle with libssh2.
#[derive(Copy, Clone)]
pub enum OpenType {
    /// Specify that a file shoud be opened.
    File = raw::LIBSSH2_SFTP_OPENFILE as isize,
    /// Specify that a directory should be opened.
    Dir = raw::LIBSSH2_SFTP_OPENDIR as isize,
}

impl Sftp {
    pub(crate) fn from_raw_opt(
        raw: *mut raw::LIBSSH2_SFTP,
        err: Option<Error>,
        sess: &Arc<Mutex<SessionInner>>,
    ) -> Result<Self, Error> {
        if raw.is_null() {
            Err(err.unwrap_or_else(Error::unknown))
        } else {
            Ok(Self {
                inner: Some(Arc::new(SftpInnerDropWrapper(Some(SftpInner {
                    raw,
                    sess: Arc::clone(sess),
                })))),
            })
        }
    }

    /// Open a handle to a file.
    ///
    /// The mode will represent the permissions for the file ([Wikipedia](<https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation>)).
    pub fn open_mode<T: AsRef<Path>>(
        &self,
        filename: T,
        flags: OpenFlags,
        mode: i32,
        open_type: OpenType,
    ) -> Result<File, Error> {
        let filename = CString::new(util::path2bytes(filename.as_ref())?)?;

        let locked = self.lock()?;
        unsafe {
            let ret = raw::libssh2_sftp_open_ex(
                locked.raw,
                filename.as_ptr() as *const _,
                filename.as_bytes().len() as c_uint,
                flags.bits() as c_ulong,
                mode as c_long,
                open_type as c_int,
            );
            if ret.is_null() {
                let rc = raw::libssh2_session_last_errno(locked.sess.raw);
                Err(Self::error_code_into_error(locked.sess.raw, locked.raw, rc))
            } else {
                Ok(File::from_raw(self, ret))
            }
        }
    }

    /// Helper to open a file in the `Read` mode.
    pub fn open<T: AsRef<Path>>(&self, filename: T) -> Result<File, Error> {
        self.open_mode(filename, OpenFlags::READ, 0o644, OpenType::File)
    }

    /// Helper to create a file in write-only mode with truncation.
    pub fn create(&self, filename: &Path) -> Result<File, Error> {
        self.open_mode(
            filename,
            OpenFlags::WRITE | OpenFlags::TRUNCATE,
            0o644,
            OpenType::File,
        )
    }

    /// Helper to open a directory for reading its contents.
    pub fn opendir<T: AsRef<Path>>(&self, dirname: T) -> Result<File, Error> {
        self.open_mode(dirname, OpenFlags::READ, 0, OpenType::Dir)
    }

    /// Convenience function to read the files in a directory.
    ///
    /// The returned paths are all joined with `dirname` when returned, and the
    /// paths `.` and `..` are filtered out of the returned list.
    pub fn readdir<T: AsRef<Path>>(&self, dirname: T) -> Result<Vec<(PathBuf, FileStat)>, Error> {
        let mut dir = self.opendir(dirname.as_ref())?;
        let mut ret = Vec::new();
        loop {
            match dir.readdir() {
                Ok((filename, stat)) => {
                    if &*filename == Path::new(".") || &*filename == Path::new("..") {
                        continue;
                    }

                    ret.push((dirname.as_ref().join(&filename), stat))
                }
                Err(ref e) if e.code() == ErrorCode::Session(raw::LIBSSH2_ERROR_FILE) => break,
                Err(e) => {
                    if e.code() != ErrorCode::Session(raw::LIBSSH2_ERROR_EAGAIN) {
                        return Err(e);
                    }
                }
            }
        }
        Ok(ret)
    }

    /// Create a directory on the remote file system.
    ///
    /// The mode will set the permissions of the new directory ([Wikipedia](<https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation>)).
    pub fn mkdir(&self, filename: &Path, mode: i32) -> Result<(), Error> {
        let filename = CString::new(util::path2bytes(filename)?)?;
        let locked = self.lock()?;
        Self::rc(&locked, unsafe {
            raw::libssh2_sftp_mkdir_ex(
                locked.raw,
                filename.as_ptr() as *const _,
                filename.as_bytes().len() as c_uint,
                mode as c_long,
            )
        })
    }

    /// Remove a directory from the remote file system.
    pub fn rmdir(&self, filename: &Path) -> Result<(), Error> {
        let filename = CString::new(util::path2bytes(filename)?)?;
        let locked = self.lock()?;
        Self::rc(&locked, unsafe {
            raw::libssh2_sftp_rmdir_ex(
                locked.raw,
                filename.as_ptr() as *const _,
                filename.as_bytes().len() as c_uint,
            )
        })
    }

    /// Get the metadata for a file, performed by stat(2)
    pub fn stat(&self, filename: &Path) -> Result<FileStat, Error> {
        let filename = CString::new(util::path2bytes(filename)?)?;
        let locked = self.lock()?;
        unsafe {
            let mut ret = mem::zeroed();
            Self::rc(
                &locked,
                raw::libssh2_sftp_stat_ex(
                    locked.raw,
                    filename.as_ptr() as *const _,
                    filename.as_bytes().len() as c_uint,
                    raw::LIBSSH2_SFTP_STAT,
                    &mut ret,
                ),
            )
            .map(|_| FileStat::from_raw(&ret))
        }
    }

    /// Get the metadata for a file, performed by lstat(2)
    pub fn lstat(&self, filename: &Path) -> Result<FileStat, Error> {
        let filename = CString::new(util::path2bytes(filename)?)?;
        let locked = self.lock()?;
        unsafe {
            let mut ret = mem::zeroed();
            Self::rc(
                &locked,
                raw::libssh2_sftp_stat_ex(
                    locked.raw,
                    filename.as_ptr() as *const _,
                    filename.as_bytes().len() as c_uint,
                    raw::LIBSSH2_SFTP_LSTAT,
                    &mut ret,
                ),
            )
            .map(|_| FileStat::from_raw(&ret))
        }
    }

    /// Set the metadata for a file.
    pub fn setstat(&self, filename: &Path, stat: FileStat) -> Result<(), Error> {
        let filename = CString::new(util::path2bytes(filename)?)?;
        let locked = self.lock()?;
        Self::rc(&locked, unsafe {
            let mut raw = stat.raw();
            raw::libssh2_sftp_stat_ex(
                locked.raw,
                filename.as_ptr() as *const _,
                filename.as_bytes().len() as c_uint,
                raw::LIBSSH2_SFTP_SETSTAT,
                &mut raw,
            )
        })
    }

    /// Create a symlink at `target` pointing at `path`.
    pub fn symlink(&self, path: &Path, target: &Path) -> Result<(), Error> {
        let path = CString::new(util::path2bytes(path)?)?;
        let target = CString::new(util::path2bytes(target)?)?;
        let locked = self.lock()?;
        Self::rc(&locked, unsafe {
            raw::libssh2_sftp_symlink_ex(
                locked.raw,
                path.as_ptr() as *const _,
                path.as_bytes().len() as c_uint,
                target.as_ptr() as *mut _,
                target.as_bytes().len() as c_uint,
                raw::LIBSSH2_SFTP_SYMLINK,
            )
        })
    }

    /// Read a symlink at `path`.
    pub fn readlink(&self, path: &Path) -> Result<PathBuf, Error> {
        self.readlink_op(path, raw::LIBSSH2_SFTP_READLINK)
    }

    /// Resolve the real path for `path`.
    pub fn realpath(&self, path: &Path) -> Result<PathBuf, Error> {
        self.readlink_op(path, raw::LIBSSH2_SFTP_REALPATH)
    }

    fn readlink_op(&self, path: &Path, op: c_int) -> Result<PathBuf, Error> {
        let path = CString::new(util::path2bytes(path)?)?;
        let mut ret = Vec::<u8>::with_capacity(128);
        let mut rc;
        let locked = self.lock()?;
        loop {
            rc = unsafe {
                raw::libssh2_sftp_symlink_ex(
                    locked.raw,
                    path.as_ptr() as *const _,
                    path.as_bytes().len() as c_uint,
                    ret.as_ptr() as *mut _,
                    ret.capacity() as c_uint,
                    op,
                )
            };
            if rc == raw::LIBSSH2_ERROR_BUFFER_TOO_SMALL {
                let cap = ret.capacity();
                ret.reserve(cap * 2);
            } else {
                break;
            }
        }
        Self::rc(&locked, rc).map(move |_| {
            unsafe { ret.set_len(rc as usize) }
            util::mkpath(&ret)
        })
    }

    /// Rename a filesystem object on the remote filesystem.
    ///
    /// The semantics of this command typically include the ability to move a
    /// filesystem object between folders and/or filesystem mounts. If the
    /// `Overwrite` flag is not set and the destfile entry already exists, the
    /// operation will fail.
    ///
    /// Use of the other flags (Native or Atomic) indicate a preference (but
    /// not a requirement) for the remote end to perform an atomic rename
    /// operation and/or using native system calls when possible.
    ///
    /// If no flags are specified then all flags are used.
    pub fn rename(&self, src: &Path, dst: &Path, flags: Option<RenameFlags>) -> Result<(), Error> {
        let flags =
            flags.unwrap_or(RenameFlags::ATOMIC | RenameFlags::OVERWRITE | RenameFlags::NATIVE);
        let src = CString::new(util::path2bytes(src)?)?;
        let dst = CString::new(util::path2bytes(dst)?)?;
        let locked = self.lock()?;
        Self::rc(&locked, unsafe {
            raw::libssh2_sftp_rename_ex(
                locked.raw,
                src.as_ptr() as *const _,
                src.as_bytes().len() as c_uint,
                dst.as_ptr() as *const _,
                dst.as_bytes().len() as c_uint,
                flags.bits(),
            )
        })
    }

    /// Remove a file on the remote filesystem
    pub fn unlink(&self, file: &Path) -> Result<(), Error> {
        let file = CString::new(util::path2bytes(file)?)?;
        let locked = self.lock()?;
        Self::rc(&locked, unsafe {
            raw::libssh2_sftp_unlink_ex(
                locked.raw,
                file.as_ptr() as *const _,
                file.as_bytes().len() as c_uint,
            )
        })
    }

    fn lock(&self) -> Result<LockedSftp<'_>, Error> {
        match self.inner.as_ref() {
            Some(sftp_inner_drop_wrapper) => {
                let sftp_inner = sftp_inner_drop_wrapper
                    .0
                    .as_ref()
                    .expect("Never unset until shutdown, in which case inner is also unset");
                let sess = sftp_inner.sess.lock();
                Ok(LockedSftp {
                    sess,
                    raw: sftp_inner.raw,
                })
            }
            None => Err(Error::from_errno(ErrorCode::Session(
                raw::LIBSSH2_ERROR_BAD_USE,
            ))),
        }
    }

    // This method is used by the async ssh crate
    #[doc(hidden)]
    pub fn shutdown(&mut self) -> Result<(), Error> {
        // We cannot shutdown the SFTP if files are still open, etc, as these store a ref to the sftp in libssh2.
        // We have to make sure we are the last reference to it.
        let wrapper = self
            .inner
            .as_mut()
            .and_then(Arc::get_mut)
            .ok_or_else(|| Error::from_errno(ErrorCode::Session(raw::LIBSSH2_ERROR_BAD_USE)))?;
        let inner = wrapper.0.as_ref().expect(
            "We were holding an Arc<SftpInnerDropWrapper>, \
                    so nobody could unset this (set on creation)",
        );
        let rc = inner
            .sess
            .lock()
            .rc(unsafe { raw::libssh2_sftp_shutdown(inner.raw) });

        // EAGAIN leaves the native handle alive so shutdown can be retried (or
        // completed by Drop). Every other result consumes the native handle.
        if !matches!(&rc, Err(e) if e.code() == ErrorCode::Session(raw::LIBSSH2_ERROR_EAGAIN)) {
            wrapper.0 = None;
            self.inner = None;
        }
        rc
    }

    fn error_code_into_error(
        session_raw: *mut raw::LIBSSH2_SESSION,
        sftp_raw: *mut raw::LIBSSH2_SFTP,
        rc: libc::c_int,
    ) -> Error {
        if rc >= 0 {
            Error::unknown()
        } else if rc == raw::LIBSSH2_ERROR_SFTP_PROTOCOL {
            let actual_rc = unsafe { raw::libssh2_sftp_last_error(sftp_raw) };
            // TODO: This conversion from `c_ulong` to `c_int` should not be
            // necessary if the constants `LIBSSH2_FX_*` in the `-sys` crate
            // are typed as `c_ulong`, as they should be.
            if let Ok(actual_rc) = libc::c_int::try_from(actual_rc) {
                Error::from_errno(ErrorCode::SFTP(actual_rc))
            } else {
                Error::unknown()
            }
        } else {
            Error::from_session_error_raw(session_raw, rc)
        }
    }

    fn error_code_into_result(
        session_raw: *mut raw::LIBSSH2_SESSION,
        sftp_raw: *mut raw::LIBSSH2_SFTP,
        rc: libc::c_int,
    ) -> Result<(), Error> {
        if rc >= 0 {
            Ok(())
        } else {
            Err(Self::error_code_into_error(session_raw, sftp_raw, rc))
        }
    }

    fn rc(locked: &LockedSftp, rc: libc::c_int) -> Result<(), Error> {
        Self::error_code_into_result(locked.sess.raw, locked.raw, rc)
    }
}

impl Drop for SftpInnerDropWrapper {
    fn drop(&mut self) {
        // Check we were not early-dropped
        if let Some(inner) = self.0.take() {
            let sess = inner.sess.lock();
            // Set ssh2 to blocking during the drop
            let was_blocking = sess.is_blocking();
            sess.set_blocking(true);
            // The shutdown statement can go wrong and return an error code, but we are too late
            // in the execution to recover it.
            let _shutdown_result = unsafe { raw::libssh2_sftp_shutdown(inner.raw) };
            sess.set_blocking(was_blocking);
        }
    }
}

impl File {
    /// Wraps a raw pointer in a new File structure tied to the lifetime of the
    /// given session.
    ///
    /// This consumes ownership of `raw`.
    unsafe fn from_raw(sftp: &Sftp, raw: *mut raw::LIBSSH2_SFTP_HANDLE) -> File {
        File {
            inner: Some(FileInner {
                raw,
                sftp: Arc::clone(
                    &sftp
                        .inner
                        .as_ref()
                        .expect("Cannot open file after sftp shutdown"),
                ),
            }),
        }
    }

    /// Set the metadata for this handle.
    pub fn setstat(&mut self, stat: FileStat) -> Result<(), Error> {
        let locked = self.lock()?;
        self.rc(&locked, unsafe {
            let mut raw = stat.raw();
            raw::libssh2_sftp_fstat_ex(locked.raw, &mut raw, 1)
        })
    }

    /// Get the metadata for this handle.
    pub fn stat(&mut self) -> Result<FileStat, Error> {
        let locked = self.lock()?;
        unsafe {
            let mut ret = mem::zeroed();
            self.rc(&locked, raw::libssh2_sftp_fstat_ex(locked.raw, &mut ret, 0))
                .map(|_| FileStat::from_raw(&ret))
        }
    }

    #[allow(missing_docs)] // sure wish I knew what this did...
    pub fn statvfs(&mut self) -> Result<raw::LIBSSH2_SFTP_STATVFS, Error> {
        let locked = self.lock()?;
        unsafe {
            let mut ret = mem::zeroed();
            self.rc(&locked, raw::libssh2_sftp_fstatvfs(locked.raw, &mut ret))
                .map(move |_| ret)
        }
    }

    /// Reads a block of data from a handle and returns file entry information
    /// for the next entry, if any.
    ///
    /// Note that this provides raw access to the `readdir` function from
    /// libssh2. This will return an error when there are no more files to
    /// read, and files such as `.` and `..` will be included in the return
    /// values.
    ///
    /// Also note that the return paths will not be absolute paths, they are
    /// the filenames of the files in this directory.
    pub fn readdir(&mut self) -> Result<(PathBuf, FileStat), Error> {
        let locked = self.lock()?;

        // libssh2 through 1.10.0 skips entries if the buffer
        // is not large enough: it's not enough to resize and try again
        // on getting an error. So, we make it quite large here.
        // See <https://github.com/alexcrichton/ssh2-rs/issues/217>.
        let mut buf = Vec::<u8>::with_capacity(4 * 1024);
        let mut stat = unsafe { mem::zeroed() };
        let mut rc;
        loop {
            rc = unsafe {
                raw::libssh2_sftp_readdir_ex(
                    locked.raw,
                    buf.as_mut_ptr() as *mut _,
                    buf.capacity() as size_t,
                    null_mut(),
                    0,
                    &mut stat,
                )
            };
            if rc == raw::LIBSSH2_ERROR_BUFFER_TOO_SMALL {
                let cap = buf.capacity();
                buf.reserve(cap * 2);
            } else {
                break;
            }
        }
        if rc == 0 {
            Err(Error::new(
                ErrorCode::Session(raw::LIBSSH2_ERROR_FILE),
                "no more files",
            ))
        } else {
            self.rc(&locked, rc).map(move |_| {
                unsafe {
                    buf.set_len(rc as usize);
                }
                (util::mkpath(&buf), FileStat::from_raw(&stat))
            })
        }
    }

    /// This function causes the remote server to synchronize the file data and
    /// metadata to disk (like fsync(2)).
    ///
    /// For this to work requires fsync@openssh.com support on the server.
    pub fn fsync(&mut self) -> Result<(), Error> {
        let locked = self.lock()?;
        self.rc(&locked, unsafe { raw::libssh2_sftp_fsync(locked.raw) })
    }

    fn lock(&self) -> Result<LockedFile<'_>, Error> {
        match self.inner.as_ref() {
            Some(file_inner) => {
                let sftp_inner = file_inner.sftp.0.as_ref().expect(
                    "We are holding an Arc<SftpInnerDropWrapper>, \
                        so nobody could unset this (set on creation)",
                );
                let sess = sftp_inner.sess.lock();
                Ok(LockedFile {
                    sess,
                    raw: file_inner.raw,
                })
            }
            None => Err(Error::from_errno(ErrorCode::Session(
                raw::LIBSSH2_ERROR_BAD_USE,
            ))),
        }
    }

    #[doc(hidden)]
    pub fn close(&mut self) -> Result<(), Error> {
        let rc = {
            let locked = self.lock()?;
            self.rc(&locked, unsafe {
                raw::libssh2_sftp_close_handle(locked.raw)
            })
        };

        // If EGAIN was returned, we'll need to call this again to complete the operation.
        // If any other error was returned, or if it completed OK, we must not use the
        // handle again.
        match rc {
            Err(e) if e.code() == ErrorCode::Session(raw::LIBSSH2_ERROR_EAGAIN) => Err(e),
            rc => {
                self.inner = None;
                rc
            }
        }
    }

    fn rc(&self, locked: &LockedFile, rc: libc::c_int) -> Result<(), Error> {
        if let Some(file_inner) = self.inner.as_ref() {
            let sftp_inner = file_inner.sftp.0.as_ref().expect(
                "We are holding an Arc<SftpInnerDropWrapper>, \
                        so nobody could unset this (set on creation)",
            );
            Sftp::error_code_into_result(locked.sess.raw, sftp_inner.raw, rc)
        } else if rc < 0 {
            Err(Error::from_errno(ErrorCode::Session(rc)))
        } else {
            Ok(())
        }
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let locked = self.lock()?;
        let rc = unsafe {
            raw::libssh2_sftp_read(locked.raw, buf.as_mut_ptr() as *mut _, buf.len() as size_t)
        };
        if rc < 0 {
            let rc = rc as libc::c_int;
            if let Some(file_inner) = self.inner.as_ref() {
                let sftp_inner = file_inner.sftp.0.as_ref().expect(
                    "We are holding an Arc<SftpInnerDropWrapper>, \
                        so nobody could unset this (set on creation)",
                );
                Err(Sftp::error_code_into_error(locked.sess.raw, sftp_inner.raw, rc).into())
            } else {
                Err(Error::from_errno(ErrorCode::Session(rc)).into())
            }
        } else {
            Ok(rc as usize)
        }
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let locked = self.lock()?;
        let rc = unsafe {
            raw::libssh2_sftp_write(locked.raw, buf.as_ptr() as *const _, buf.len() as size_t)
        };
        if rc < 0 {
            let rc = rc as libc::c_int;
            if let Some(file_inner) = self.inner.as_ref() {
                let sftp_inner = file_inner.sftp.0.as_ref().expect(
                    "We are holding an Arc<SftpInnerDropWrapper>, \
                        so nobody could unset this (set on creation)",
                );
                Err(Sftp::error_code_into_error(locked.sess.raw, sftp_inner.raw, rc).into())
            } else {
                Err(Error::from_errno(ErrorCode::Session(rc)).into())
            }
        } else {
            Ok(rc as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for File {
    /// Move the file handle's internal pointer to an arbitrary location.
    ///
    /// libssh2 implements file pointers as a localized concept to make file
    /// access appear more POSIX like. No packets are exchanged with the server
    /// during a seek operation. The localized file pointer is simply used as a
    /// convenience offset during read/write operations.
    ///
    /// You MUST NOT seek during writing or reading a file with SFTP, as the
    /// internals use outstanding packets and changing the "file position"
    /// during transit will results in badness.
    fn seek(&mut self, how: SeekFrom) -> io::Result<u64> {
        let next = match how {
            SeekFrom::Start(pos) => pos,
            SeekFrom::Current(offset) => {
                let locked = self.lock()?;
                let cur = unsafe { raw::libssh2_sftp_tell64(locked.raw) };
                (cur as i64 + offset) as u64
            }
            SeekFrom::End(offset) => match self.stat() {
                Ok(s) => match s.size {
                    Some(size) => (size as i64 + offset) as u64,
                    None => return Err(io::Error::new(ErrorKind::Other, "no file size available")),
                },
                Err(e) => return Err(io::Error::new(ErrorKind::Other, e)),
            },
        };
        let locked = self.lock()?;
        unsafe { raw::libssh2_sftp_seek64(locked.raw, next) }
        Ok(next)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        // Set ssh2 to blocking if the file was not closed yet (by .close()).
        if let Some(file_inner) = self.inner.take() {
            let sftp_inner = file_inner.sftp.0.as_ref().expect(
                "We are holding an Arc<SftpInnerDropWrapper>, \
                    so nobody could unset this (set on creation)",
            );
            let sess_inner = sftp_inner.sess.lock();
            let was_blocking = sess_inner.is_blocking();
            sess_inner.set_blocking(true);
            // The close statement can go wrong and return an error code, but we are too late
            // in the execution to recover it.
            let _close_handle_result = unsafe { raw::libssh2_sftp_close_handle(file_inner.raw) };
            sess_inner.set_blocking(was_blocking);
        }
    }
}

impl FileStat {
    /// Returns the file type for this filestat.
    pub fn file_type(&self) -> FileType {
        FileType::from_perm(self.perm.unwrap_or(0) as c_ulong)
    }

    /// Returns whether this metadata is for a directory.
    pub fn is_dir(&self) -> bool {
        self.file_type().is_dir()
    }

    /// Returns whether this metadata is for a regular file.
    pub fn is_file(&self) -> bool {
        self.file_type().is_file()
    }

    /// Creates a new instance of a stat from a raw instance.
    pub fn from_raw(raw: &raw::LIBSSH2_SFTP_ATTRIBUTES) -> FileStat {
        fn val<T: Copy>(raw: &raw::LIBSSH2_SFTP_ATTRIBUTES, t: &T, flag: c_ulong) -> Option<T> {
            if raw.flags & flag != 0 {
                Some(*t)
            } else {
                None
            }
        }

        FileStat {
            size: val(raw, &raw.filesize, raw::LIBSSH2_SFTP_ATTR_SIZE),
            uid: val(raw, &raw.uid, raw::LIBSSH2_SFTP_ATTR_UIDGID).map(|s| s as u32),
            gid: val(raw, &raw.gid, raw::LIBSSH2_SFTP_ATTR_UIDGID).map(|s| s as u32),
            perm: val(raw, &raw.permissions, raw::LIBSSH2_SFTP_ATTR_PERMISSIONS).map(|s| s as u32),
            mtime: val(raw, &raw.mtime, raw::LIBSSH2_SFTP_ATTR_ACMODTIME).map(|s| s as u64),
            atime: val(raw, &raw.atime, raw::LIBSSH2_SFTP_ATTR_ACMODTIME).map(|s| s as u64),
        }
    }

    /// Convert this stat structure to its raw representation.
    pub fn raw(&self) -> raw::LIBSSH2_SFTP_ATTRIBUTES {
        fn flag<T>(o: &Option<T>, flag: c_ulong) -> c_ulong {
            if o.is_some() {
                flag
            } else {
                0
            }
        }

        raw::LIBSSH2_SFTP_ATTRIBUTES {
            flags: flag(&self.size, raw::LIBSSH2_SFTP_ATTR_SIZE)
                | flag(&self.uid, raw::LIBSSH2_SFTP_ATTR_UIDGID)
                | flag(&self.gid, raw::LIBSSH2_SFTP_ATTR_UIDGID)
                | flag(&self.perm, raw::LIBSSH2_SFTP_ATTR_PERMISSIONS)
                | flag(&self.atime, raw::LIBSSH2_SFTP_ATTR_ACMODTIME)
                | flag(&self.mtime, raw::LIBSSH2_SFTP_ATTR_ACMODTIME),
            filesize: self.size.unwrap_or(0),
            uid: self.uid.unwrap_or(0) as c_ulong,
            gid: self.gid.unwrap_or(0) as c_ulong,
            permissions: self.perm.unwrap_or(0) as c_ulong,
            atime: self.atime.unwrap_or(0) as c_ulong,
            mtime: self.mtime.unwrap_or(0) as c_ulong,
        }
    }
}

impl FileType {
    /// Test whether this file type represents a directory.
    pub fn is_dir(&self) -> bool {
        self == &FileType::Directory
    }

    /// Test whether this file type represents a regular file.
    pub fn is_file(&self) -> bool {
        self == &FileType::RegularFile
    }

    /// Test whether this file type represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self == &FileType::Symlink
    }

    fn from_perm(perm: c_ulong) -> Self {
        match perm & raw::LIBSSH2_SFTP_S_IFMT {
            raw::LIBSSH2_SFTP_S_IFIFO => FileType::NamedPipe,
            raw::LIBSSH2_SFTP_S_IFCHR => FileType::CharDevice,
            raw::LIBSSH2_SFTP_S_IFDIR => FileType::Directory,
            raw::LIBSSH2_SFTP_S_IFBLK => FileType::BlockDevice,
            raw::LIBSSH2_SFTP_S_IFREG => FileType::RegularFile,
            raw::LIBSSH2_SFTP_S_IFLNK => FileType::Symlink,
            raw::LIBSSH2_SFTP_S_IFSOCK => FileType::Socket,
            other => FileType::Other(other),
        }
    }
}
