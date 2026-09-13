// Usings for openssl function userauth_pubkey_memory()
#[cfg(any(unix, feature = "vendored-openssl", feature = "openssl-on-win32"))]
use libc::size_t;
use libc::{self, c_char, c_int, c_long, c_uint, c_void};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use std::borrow::Cow;
use std::ffi::CString;
use std::ptr::{null, null_mut};
use std::mem;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::path::Path;
use std::slice;
use std::str;
use std::sync::Arc;

use util;
use {raw, ByApplication, DisconnectCode, Error, ErrorCode, HostKeyType};
use {Agent, Channel, HashType, KnownHosts, Listener, MethodType, Sftp};

bitflags! {
    /// Flags which can be used with the session trace method to set
    /// the trace level.
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct TraceFlags: c_int {
        /// Authentication debugging
        const AUTH      = raw::LIBSSH2_TRACE_AUTH;
        /// Connection layer debugging
        const CONN      = raw::LIBSSH2_TRACE_CONN;
        /// Error debugging
        const ERROR     = raw::LIBSSH2_TRACE_ERROR;
        /// Key exchange debugging
        const KEX       = raw::LIBSSH2_TRACE_KEX;
        /// Public Key Debugging
        const PUBLICKEY = raw::LIBSSH2_TRACE_PUBLICKEY;
        /// SCP debugging
        const SCP       = raw::LIBSSH2_TRACE_SCP;
        /// SFTP debugging
        const SFTP      = raw::LIBSSH2_TRACE_SFTP;
        /// Socket low-level debugging
        const SOCKET    = raw::LIBSSH2_TRACE_SOCKET;
        /// Transport layer debugging
        const TRANS     = raw::LIBSSH2_TRACE_TRANS;
    }
}

/// Called by libssh2 to respond to some number of challenges as part of
/// keyboard interactive authentication.
pub trait KeyboardInteractivePrompt {
    /// `username` is the user name to be authenticated. It may not be the
    /// same as the username passed to `Session::userauth_keyboard_interactive`,
    /// and may be empty.
    /// `instructions` is some informational text to be displayed to the user.
    /// `prompts` is a series of prompts (or challenges) that must be responded
    /// to.
    /// The return value should be a Vec that holds one response for each prompt.
    fn prompt<'a>(
        &mut self,
        username: &str,
        instructions: &str,
        prompts: &[Prompt<'a>],
    ) -> Vec<String>;
}

/// A prompt/challenge returned as part of keyboard-interactive authentication
#[derive(Debug)]
pub struct Prompt<'a> {
    /// The label to show when prompting the user
    pub text: Cow<'a, str>,
    /// If true, the response that the user inputs should be displayed
    /// as they type.  If false then treat it as a password entry and
    /// do not display what is typed in response to this prompt.
    pub echo: bool,
}

/// This is a little helper function that is perhaps slightly overkill for the
/// current needs.
/// It saves the current sess->abstract pointer and replaces it with a
/// different values for the duration of the call to the supplied lambda.
/// When the lambda returns, the original abstract value is restored
/// and the result of the lambda is returned.
unsafe fn with_abstract<R, F: FnOnce() -> R>(
    sess: *mut raw::LIBSSH2_SESSION,
    new_value: *mut c_void,
    f: F,
) -> R {
    let abstrakt = raw::libssh2_session_abstract(sess);
    let old_value = *abstrakt;
    *abstrakt = new_value;
    let res = f();
    *abstrakt = old_value;
    res
}

pub(crate) struct SessionInner {
    pub(crate) raw: *mut raw::LIBSSH2_SESSION,
    #[cfg(unix)]
    tcp: Option<Box<dyn AsRawFd>>,
    #[cfg(windows)]
    tcp: Option<Box<dyn AsRawSocket>>,
    freed: bool,
}

// The compiler doesn't know that it is Send safe because of the raw
// pointer inside.  We know that the way that it is used by libssh2
// and this crate is Send safe.
unsafe impl Send for SessionInner {}

/// An SSH session, typically representing one TCP connection.
///
/// All other structures are based on an SSH session and cannot outlive a
/// session. Sessions are created and then have the TCP socket handed to them
/// (via the `set_tcp_stream` method).
///
/// `Session`, and any objects its methods return, hold a reference to the underlying
/// SSH session.  You may clone `Session` to obtain another handle referencing
/// the same session, and create multiple `Channel` and `Stream` objects
/// from that same underlying session, which can all be passed across thread
/// boundaries (they are `Send` and `Sync`).  These are all related objects and
/// are internally synchronized via a `Mutex` to make it safe to pass them
/// around in this way.
///
/// This means that a blocking read from a `Channel` or `Stream` will block
/// all other calls on objects created from the same underlying `Session`.
/// If you need the ability to perform concurrent operations then you will
/// need to create separate `Session` instances, or employ non-blocking mode.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Mutex<SessionInner>>,
}

/// Metadata returned about a remote file when received via `scp`.
pub struct ScpFileStat {
    stat: libc::stat,
}

/// The io direction an application has to wait for in order not to block.
#[derive(Debug, PartialEq)]
pub enum BlockDirections {
    /// No direction blocked.
    None,
    /// Inbound direction blocked.
    Inbound,
    /// Outbound direction blockd.
    Outbound,
    /// Inbound and Outbound direction blocked.
    Both,
}

impl Session {
    /// Initializes an SSH session object.
    ///
    /// This function does not associate the session with a remote connection
    /// just yet. Various configuration options can be set such as the blocking
    /// mode, compression, sigpipe, the banner, etc. To associate this session
    /// with a TCP connection, use the `set_tcp_stream` method pass in an
    /// already-established TCP socket, and then follow up with a call to
    /// `handshake` to perform the ssh protocol handshake.
    pub fn new() -> Result<Session, Error> {
        ::init();
        unsafe {
            let ret = raw::libssh2_session_init_ex(None, None, None, null_mut());
            if ret.is_null() {
                Err(Error::unknown())
            } else {
                Ok(Session {
                    inner: Arc::new(Mutex::new(SessionInner {
                        raw: ret,
                        tcp: None,
                        freed: false,
                    })),
                })
            }
        }
    }

    #[doc(hidden)]
    pub fn raw(&self) -> MappedMutexGuard<'_, raw::LIBSSH2_SESSION> {
        let inner = self.inner();
        MutexGuard::map(inner, |inner| unsafe { &mut *inner.raw })
    }

    /// Set the SSH protocol banner for the local client
    ///
    /// Set the banner that will be sent to the remote host when the SSH session
    /// is started with handshake(). This is optional; a banner
    /// corresponding to the protocol and libssh2 version will be sent by
    /// default.
    pub fn set_banner(&self, banner: &str) -> Result<(), Error> {
        let banner = CString::new(banner)?;
        let inner = self.inner();
        unsafe { inner.rc(raw::libssh2_session_banner_set(inner.raw, banner.as_ptr())) }
    }

    /// Flag indicating whether SIGPIPE signals will be allowed or blocked.
    ///
    /// By default (on relevant platforms) this library will attempt to block
    /// and catch SIGPIPE signals. Setting this flag to `true` will cause
    /// the library to not attempt to block SIGPIPE from the underlying socket
    /// layer.
    pub fn set_allow_sigpipe(&self, block: bool) {
        let inner = self.inner();
        let res = unsafe {
            inner.rc(raw::libssh2_session_flag(
                inner.raw,
                raw::LIBSSH2_FLAG_SIGPIPE as c_int,
                block as c_int,
            ))
        };
        res.unwrap();
    }

    /// Flag indicating whether this library will attempt to negotiate
    /// compression.
    ///
    /// If set - before the connection negotiation is performed - libssh2 will
    /// try to negotiate compression enabling for this connection. By default
    /// libssh2 will not attempt to use compression.
    pub fn set_compress(&self, compress: bool) {
        let inner = self.inner();
        let res = unsafe {
            inner.rc(raw::libssh2_session_flag(
                inner.raw,
                raw::LIBSSH2_FLAG_COMPRESS as c_int,
                compress as c_int,
            ))
        };
        res.unwrap();
    }

    /// Set or clear blocking mode on session
    ///
    /// This will instantly affect any channels associated with this session. If
    /// a read is performed on a session with no data currently available, a
    /// blocking session will wait for data to arrive and return what it
    /// receives. A non-blocking session will return immediately with an empty
    /// buffer. If a write is performed on a session with no room for more data,
    /// a blocking session will wait for room. A non-blocking session will
    /// return immediately without writing anything.
    pub fn set_blocking(&self, blocking: bool) {
        self.inner().set_blocking(blocking);
    }

    /// Returns whether the session was previously set to nonblocking.
    pub fn is_blocking(&self) -> bool {
        self.inner().is_blocking()
    }

    /// Set timeout for blocking functions.
    ///
    /// Set the timeout in milliseconds for how long a blocking the libssh2
    /// function calls may wait until they consider the situation an error and
    /// return an error.
    ///
    /// By default or if you set the timeout to zero, libssh2 has no timeout
    /// for blocking functions.
    pub fn set_timeout(&self, timeout_ms: u32) {
        let timeout_ms = timeout_ms as c_long;
        let inner = self.inner();
        unsafe { raw::libssh2_session_set_timeout(inner.raw, timeout_ms) }
    }

    /// Returns the timeout, in milliseconds, for how long blocking calls may
    /// wait until they time out.
    ///
    /// A timeout of 0 signifies no timeout.
    pub fn timeout(&self) -> u32 {
        let inner = self.inner();
        unsafe { raw::libssh2_session_get_timeout(inner.raw) as u32 }
    }

    /// Begin transport layer protocol negotiation with the connected host.
    ///
    /// You must call this after associating the session with a tcp stream
    /// via the `set_tcp_stream` function.
    pub fn handshake(&mut self) -> Result<(), Error> {
        #[cfg(windows)]
        unsafe fn handshake(
            raw: *mut raw::LIBSSH2_SESSION,
            stream: &dyn AsRawSocket,
        ) -> libc::c_int {
            raw::libssh2_session_handshake(raw, stream.as_raw_socket())
        }

        #[cfg(unix)]
        unsafe fn handshake(raw: *mut raw::LIBSSH2_SESSION, stream: &dyn AsRawFd) -> libc::c_int {
            raw::libssh2_session_handshake(raw, stream.as_raw_fd())
        }

        let inner = self.inner();

        unsafe {
            let stream = inner.tcp.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorCode::Session(raw::LIBSSH2_ERROR_BAD_SOCKET),
                    "use set_tcp_stream() to associate with a TcpStream",
                )
            })?;

            inner.rc(handshake(inner.raw, stream.as_ref()))
        }
    }

    /// The session takes ownership of the stream provided.
    /// You may use the `AsRawFd` (unix) or `AsRawSocket` (windows) traits
    /// to obtain the raw fd later if required.
    ///
    /// It is also highly recommended that the stream provided is not used
    /// concurrently elsewhere for the duration of this session as it may
    /// interfere with the protocol.
    #[cfg(unix)]
    pub fn set_tcp_stream<S: 'static + AsRawFd>(&mut self, stream: S) {
        let mut inner = self.inner();
        let _ = inner.tcp.replace(Box::new(stream));
    }

    /// The session takes ownership of the stream provided.
    /// You may use the tcp_stream() method to obtain the raw socket later.
    ///
    /// It is also highly recommended that the stream provided is not used
    /// concurrently elsewhere for the duration of this session as it may
    /// interfere with the protocol.
    #[cfg(windows)]
    pub fn set_tcp_stream<S: 'static + AsRawSocket>(&mut self, stream: S) {
        let mut inner = self.inner();
        let _ = inner.tcp.replace(Box::new(stream));
    }

    /// Attempt basic password authentication.
    ///
    /// Note that many SSH servers which appear to support ordinary password
    /// authentication actually have it disabled and use Keyboard Interactive
    /// authentication (routed via PAM or another authentication backed)
    /// instead.
    pub fn userauth_password(&self, username: &str, password: &str) -> Result<(), Error> {
        let username = CString::new(username)?;
        let username = username.as_bytes();
        let password = CString::new(password)?;
        let password = password.as_bytes();
        let inner = self.inner();
        inner.rc(unsafe {
            raw::libssh2_userauth_password_ex(
                inner.raw,
                username.as_ptr() as *const _,
                username.len() as c_uint,
                password.as_ptr() as *const _,
                password.len() as c_uint,
                None,
            )
        })
    }

    /// Attempt keyboard interactive authentication.
    ///
    /// You must supply a callback function to
    pub fn userauth_keyboard_interactive<P: KeyboardInteractivePrompt>(
        &self,
        username: &str,
        prompter: &mut P,
    ) -> Result<(), Error> {
        // hold on to your hats, this is a bit involved.
        // The keyboard interactive callback is a bit tricksy, and we want to wrap the
        // raw C types with something a bit safer and more ergonomic.
        // Since the interface is defined in terms of a simple function pointer, wrapping
        // is a bit awkward.
        //
        // The session struct has an abstrakt pointer reserved for
        // the user of the embedding application, and that pointer is passed to the
        // prompt callback. We can use this to store a pointer to some state so that
        // we can manage the conversion.
        //
        // The prompts and responses are defined to be UTF-8, but we use from_utf8_lossy
        // to avoid panics in case the server isn't conformant for whatever reason.
        extern "C" fn prompt<P: KeyboardInteractivePrompt>(
            username: *const c_char,
            username_len: c_int,
            instruction: *const c_char,
            instruction_len: c_int,
            num_prompts: c_int,
            prompts: *const raw::LIBSSH2_USERAUTH_KBDINT_PROMPT,
            responses: *mut raw::LIBSSH2_USERAUTH_KBDINT_RESPONSE,
            abstrakt: *mut *mut c_void,
        ) {
            use std::panic::{catch_unwind, AssertUnwindSafe};
            // Catch panics; we can't let them unwind to C code.
            // There's not much to be done with them though because the
            // signature of the callback doesn't allow reporting an error.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                if prompts.is_null() || responses.is_null() || num_prompts < 0 {
                    return;
                }

                let prompter = unsafe { &mut **(abstrakt as *mut *mut P) };

                let username = if !username.is_null() && username_len >= 0 {
                    let username = unsafe {
                        slice::from_raw_parts(username as *const u8, username_len as usize)
                    };
                    String::from_utf8_lossy(username)
                } else {
                    Cow::Borrowed("")
                };

                let instruction = if !instruction.is_null() && instruction_len >= 0 {
                    let instruction = unsafe {
                        slice::from_raw_parts(instruction as *const u8, instruction_len as usize)
                    };
                    String::from_utf8_lossy(instruction)
                } else {
                    Cow::Borrowed("")
                };

                let prompts = unsafe { slice::from_raw_parts(prompts, num_prompts as usize) };
                let responses =
                    unsafe { slice::from_raw_parts_mut(responses, num_prompts as usize) };

                let prompts: Vec<Prompt> = prompts
                    .iter()
                    .map(|item| {
                        let data = unsafe {
                            slice::from_raw_parts(item.text as *const u8, item.length as usize)
                        };
                        Prompt {
                            text: String::from_utf8_lossy(data),
                            echo: item.echo != 0,
                        }
                    })
                    .collect();

                // libssh2 wants to be able to free(3) the response strings, so allocate
                // storage and copy the responses into appropriately owned memory.
                // We can't simply call strdup(3) here because the rust string types
                // are not NUL terminated.
                fn strdup_string(s: &str) -> *mut c_char {
                    let len = s.len();
                    let ptr = unsafe { libc::malloc(len + 1) as *mut c_char };
                    if !ptr.is_null() {
                        unsafe {
                            ::std::ptr::copy_nonoverlapping(
                                s.as_bytes().as_ptr() as *const c_char,
                                ptr,
                                len,
                            );
                            *ptr.offset(len as isize) = 0;
                        }
                    }
                    ptr
                }

                for (i, response) in (*prompter)
                    .prompt(&username, &instruction, &prompts)
                    .into_iter()
                    .take(prompts.len())
                    .enumerate()
                {
                    let ptr = strdup_string(&response);
                    if !ptr.is_null() {
                        responses[i].length = response.len() as c_uint;
                    } else {
                        responses[i].length = 0;
                    }
                    responses[i].text = ptr;
                }
            }));
        }

        let username = CString::new(username)?;
        let username = username.as_bytes();
        let inner = self.inner();
        unsafe {
            with_abstract(inner.raw, prompter as *mut P as *mut c_void, || {
                inner.rc(raw::libssh2_userauth_keyboard_interactive_ex(
                    inner.raw,
                    username.as_ptr() as *const _,
                    username.len() as c_uint,
                    Some(prompt::<P>),
                ))
            })
        }
    }

    /// Attempt to perform SSH agent authentication.
    ///
    /// This is a helper method for attempting to authenticate the current
    /// connection with the first public key found in an SSH agent. If more
    /// control is needed than this method offers, it is recommended to use
    /// `agent` directly to control how the identity is found.
    pub fn userauth_agent(&self, username: &str) -> Result<(), Error> {
        let mut agent = self.agent()?;
        agent.connect()?;
        agent.list_identities()?;
        let identities = agent.identities()?;
        let identity = match identities.get(0) {
            Some(identity) => identity,
            None => {
                return Err(Error::new(
                    ErrorCode::Session(raw::LIBSSH2_ERROR_INVAL),
                    "no identities found in the ssh agent",
                ))
            }
        };
        agent.userauth(username, &identity)
    }

    /// Attempt public key authentication using a PEM encoded private key file
    /// stored on disk.
    pub fn userauth_pubkey_file(
        &self,
        username: &str,
        pubkey: Option<&Path>,
        privatekey: &Path,
        passphrase: Option<&str>,
    ) -> Result<(), Error> {
        let username = CString::new(username)?;
        let username = username.as_bytes();
        let pubkey = match pubkey {
            Some(s) => Some(CString::new(util::path2bytes(s)?)?),
            None => None,
        };
        let privatekey = CString::new(util::path2bytes(privatekey)?)?;
        let passphrase = match passphrase {
            Some(s) => Some(CString::new(s)?),
            None => None,
        };
        let inner = self.inner();
        inner.rc(unsafe {
            raw::libssh2_userauth_publickey_fromfile_ex(
                inner.raw,
                username.as_ptr() as *const _,
                username.len() as c_uint,
                pubkey.as_ref().map(|s| s.as_ptr()).unwrap_or(null()),
                privatekey.as_ptr(),
                passphrase
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(null()),
            )
        })
    }

    /// Attempt public key authentication using a PEM encoded private key from
    /// memory. Public key is computed from private key if none passed.
    /// This is available with openssl enabled (Required for Unix, or with vendored-openssl or openssl-on-win32 features).
    #[cfg(any(unix, feature = "vendored-openssl", feature = "openssl-on-win32"))]
    pub fn userauth_pubkey_memory(
        &self,
        username: &str,
        pubkeydata: Option<&str>,
        privatekeydata: &str,
        passphrase: Option<&str>,
    ) -> Result<(), Error> {
        let username = CString::new(username)?;
        let username = username.as_bytes();
        let (pubkeydata, pubkeydata_len) = match pubkeydata {
            Some(s) => (Some(CString::new(s)?), s.len()),
            None => (None, 0),
        };
        let privatekeydata_len = privatekeydata.len();
        let privatekeydata = CString::new(privatekeydata)?;
        let passphrase = match passphrase {
            Some(s) => Some(CString::new(s)?),
            None => None,
        };
        let inner = self.inner();
        inner.rc(unsafe {
            raw::libssh2_userauth_publickey_frommemory(
                inner.raw,
                username.as_ptr() as *const _,
                username.len() as size_t,
                pubkeydata
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(null()),
                pubkeydata_len as size_t,
                privatekeydata.as_ptr(),
                privatekeydata_len as size_t,
                passphrase
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(null()),
            )
        })
    }

    // Umm... I wish this were documented in libssh2?
    #[allow(missing_docs)]
    pub fn userauth_hostbased_file(
        &self,
        username: &str,
        publickey: &Path,
        privatekey: &Path,
        passphrase: Option<&str>,
        hostname: &str,
        local_username: Option<&str>,
    ) -> Result<(), Error> {
        let publickey = CString::new(util::path2bytes(publickey)?)?;
        let privatekey = CString::new(util::path2bytes(privatekey)?)?;
        let passphrase = match passphrase {
            Some(s) => Some(CString::new(s)?),
            None => None,
        };
        let local_username = match local_username {
            Some(local) => local,
            None => username,
        };
        let username = CString::new(username)?;
        let username = username.as_bytes();
        let local_username = CString::new(local_username)?;
        let local_username = local_username.as_bytes();
        let inner = self.inner();
        inner.rc(unsafe {
            raw::libssh2_userauth_hostbased_fromfile_ex(
                inner.raw,
                username.as_ptr() as *const _,
                username.len() as c_uint,
                publickey.as_ptr(),
                privatekey.as_ptr(),
                passphrase
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(null()),
                hostname.as_ptr() as *const _,
                hostname.len() as c_uint,
                local_username.as_ptr() as *const _,
                local_username.len() as c_uint,
            )
        })
    }

    /// Indicates whether or not the named session has been successfully
    /// authenticated.
    pub fn authenticated(&self) -> bool {
        let inner = self.inner();
        unsafe { raw::libssh2_userauth_authenticated(inner.raw) != 0 }
    }

    /// Send a SSH_USERAUTH_NONE request to the remote host.
    ///
    /// Unless the remote host is configured to accept none as a viable
    /// authentication scheme (unlikely), it will return SSH_USERAUTH_FAILURE
    /// along with a listing of what authentication schemes it does support. In
    /// the unlikely event that none authentication succeeds, this method with
    /// return an error. This case may be distinguished from a failing case by
    /// examining the return value of the `authenticated` method.
    ///
    /// The return value is a comma-separated string of supported auth schemes,
    /// and may be an empty string.
    pub fn auth_methods(&self, username: &str) -> Result<&str, Error> {
        let len = username.len();
        let username = CString::new(username)?;
        let inner = self.inner();
        unsafe {
            let ret = raw::libssh2_userauth_list(inner.raw, username.as_ptr(), len as c_uint);
            if ret.is_null() {
                match inner.last_error() {
                    Some(err) => Err(err),
                    None => Ok(""),
                }
            } else {
                Ok(str::from_utf8(::opt_bytes(self, ret).unwrap()).unwrap())
            }
        }
    }

    /// Retrieve banner message from server, if available.
    ///
    /// When no such message is sent by server or if no authentication attempt has
    /// been made, this function returns LIBSSH2_ERROR_MISSING_AUTH_BANNER.
    ///
    /// The return value is the userauth banner or None or an Error
    pub fn userauth_banner(&self) -> Result<Option<&str>, Error> {
        let mut userauth_banner = null_mut();
        let inner = self.inner();
        match unsafe { raw::libssh2_userauth_banner(inner.raw, &mut userauth_banner)} {
            0 => {
                unsafe {
                    Ok(::opt_bytes(self, userauth_banner).and_then(|s| str::from_utf8(s).ok()))
                }
            },
            rc => {
                Err(Error::from_errno(ErrorCode::Session(rc)))
            }
        }
    }

    /// Set preferred key exchange method
    ///
    /// The preferences provided are a comma delimited list of preferred methods
    /// to use with the most preferred listed first and the least preferred
    /// listed last. If a method is listed which is not supported by libssh2 it
    /// will be ignored and not sent to the remote host during protocol
    /// negotiation.
    pub fn method_pref(&self, method_type: MethodType, prefs: &str) -> Result<(), Error> {
        let prefs = CString::new(prefs)?;
        let inner = self.inner();
        unsafe {
            inner.rc(raw::libssh2_session_method_pref(
                inner.raw,
                method_type as c_int,
                prefs.as_ptr(),
            ))
        }
    }

    /// Return the currently active algorithms.
    ///
    /// Returns the actual method negotiated for a particular transport
    /// parameter. May return `None` if the session has not yet been started.
    pub fn methods(&self, method_type: MethodType) -> Option<&str> {
        let inner = self.inner();
        unsafe {
            let ptr = raw::libssh2_session_methods(inner.raw, method_type as c_int);
            ::opt_bytes(self, ptr).and_then(|s| str::from_utf8(s).ok())
        }
    }

    /// Get list of supported algorithms.
    pub fn supported_algs(&self, method_type: MethodType) -> Result<Vec<&'static str>, Error> {
        static STATIC: () = ();
        let method_type = method_type as c_int;
        let mut ret = Vec::new();
        let inner = self.inner();
        unsafe {
            let mut ptr = null_mut();
            let rc = raw::libssh2_session_supported_algs(inner.raw, method_type, &mut ptr);
            if rc <= 0 {
                inner.rc(rc)?;
            }
            for i in 0..(rc as isize) {
                let s = ::opt_bytes(&STATIC, *ptr.offset(i)).unwrap();
                let s = str::from_utf8(s).unwrap();
                ret.push(s);
            }
            raw::libssh2_free(inner.raw, ptr as *mut c_void);
        }
        Ok(ret)
    }

    /// Init an ssh-agent handle.
    ///
    /// The returned agent will still need to be connected manually before use.
    pub fn agent(&self) -> Result<Agent, Error> {
        let inner = self.inner();
        unsafe {
            let agent = raw::libssh2_agent_init(inner.raw);
            let err = inner.last_error();
            Agent::from_raw_opt(agent, err, &self.inner)
        }
    }

    /// Init a collection of known hosts for this session.
    ///
    /// Returns the handle to an internal representation of a known host
    /// collection.
    pub fn known_hosts(&self) -> Result<KnownHosts, Error> {
        let inner = self.inner();
        unsafe {
            let ptr = raw::libssh2_knownhost_init(inner.raw);
            let err = inner.last_error();
            KnownHosts::from_raw_opt(ptr, err, &self.inner)
        }
    }

    /// Establish a new session-based channel.
    ///
    /// This method is commonly used to create a channel to execute commands
    /// over or create a new login shell.
    pub fn channel_session(&self) -> Result<Channel, Error> {
        self.channel_open(
            "session",
            raw::LIBSSH2_CHANNEL_WINDOW_DEFAULT as u32,
            raw::LIBSSH2_CHANNEL_PACKET_DEFAULT as u32,
            None,
        )
    }

    /// Tunnel a TCP connection through an SSH session.
    ///
    /// Tunnel a TCP/IP connection through the SSH transport via the remote host
    /// to a third party. Communication from the client to the SSH server
    /// remains encrypted, communication from the server to the 3rd party host
    /// travels in cleartext.
    ///
    /// The optional `src` argument is the host/port to tell the SSH server
    /// where the connection originated from.
    ///
    /// The `Channel` returned represents a connection between this host and the
    /// specified remote host.
    pub fn channel_direct_tcpip(
        &self,
        host: &str,
        port: u16,
        src: Option<(&str, u16)>,
    ) -> Result<Channel, Error> {
        let (shost, sport) = src.unwrap_or(("127.0.0.1", 22));
        let host = CString::new(host)?;
        let shost = CString::new(shost)?;
        let inner = self.inner();
        unsafe {
            let ret = raw::libssh2_channel_direct_tcpip_ex(
                inner.raw,
                host.as_ptr(),
                port as c_int,
                shost.as_ptr(),
                sport as c_int,
            );
            let err = inner.last_error();
            Channel::from_raw_opt(ret, err, &self.inner)
        }
    }

    /// Tunnel a Unix domain socket connection through an SSH session.
    ///
    /// Tunnel a UNIX socket connection through the SSH transport via the remote
    /// host to a third party. Communication from the client to the SSH server
    /// remains encrypted, communication from the server to the 3rd party host
    /// travels in cleartext.
    ///
    /// The optional `src` argument is the host/port to tell the SSH server
    /// where the connection originated from.
    ///
    /// The `Channel` returned represents a connection between this host and the
    /// specified remote host.
    pub fn channel_direct_streamlocal(
        &self,
        socket_path: &str,
        src: Option<(&str, u16)>,
    ) -> Result<Channel, Error> {
        let (shost, sport) = src.unwrap_or(("127.0.0.1", 22));
        let path = CString::new(socket_path)?;
        let shost = CString::new(shost)?;
        let inner = self.inner();
        unsafe {
            let ret = raw::libssh2_channel_direct_streamlocal_ex(
                inner.raw,
                path.as_ptr(),
                shost.as_ptr(),
                sport as c_int,
            );
            let err = inner.last_error();
            Channel::from_raw_opt(ret, err, &self.inner)
        }
    }

    /// Instruct the remote SSH server to begin listening for inbound TCP/IP
    /// connections.
    ///
    /// New connections will be queued by the library until accepted by the
    /// `accept` method on the returned `Listener`.
    pub fn channel_forward_listen(
        &self,
        remote_port: u16,
        host: Option<&str>,
        queue_maxsize: Option<u32>,
    ) -> Result<(Listener, u16), Error> {
        let mut bound_port = 0;
        let host = host.map(|s| CString::new(s)).transpose()?;
        let inner = self.inner();
        unsafe {
            let ret = raw::libssh2_channel_forward_listen_ex(
                inner.raw,
                host
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(null()),
                remote_port as c_int,
                &mut bound_port,
                queue_maxsize.unwrap_or(0) as c_int,
            );
            let err = inner.last_error();
            Listener::from_raw_opt(ret, err, &self.inner).map(|l| (l, bound_port as u16))
        }
    }

    /// Request a file from the remote host via SCP.
    ///
    /// The path specified is a path on the remote host which will attempt to be
    /// sent over the returned channel. Some stat information is also returned
    /// about the remote file to prepare for receiving the file.
    pub fn scp_recv(&self, path: &Path) -> Result<(Channel, ScpFileStat), Error> {
        let path = CString::new(util::path2bytes(path)?)?;
        let inner = self.inner();
        unsafe {
            let mut sb: raw::libssh2_struct_stat = mem::zeroed();
            let ret = raw::libssh2_scp_recv2(inner.raw, path.as_ptr(), &mut sb);
            let err = inner.last_error();
            let mut c = Channel::from_raw_opt(ret, err, &self.inner)?;

            // Hm, apparently when we scp_recv() a file the actual channel
            // itself does not respond well to read_to_end(), and it also sends
            // an extra 0 byte (or so it seems). To work around this we
            // artificially limit the channel to a certain amount of bytes that
            // can be read.
            c.limit_read(sb.st_size as u64);
            Ok((c, ScpFileStat { stat: *sb }))
        }
    }

    /// Send a file to the remote host via SCP.
    ///
    /// The `remote_path` provided will be the remote file name. The `times`
    /// argument is a tuple of (mtime, atime), and will default to the remote
    /// host's current time if not specified.
    ///
    /// The size of the file, `size`, must be known ahead of time before
    /// transmission.
    pub fn scp_send(
        &self,
        remote_path: &Path,
        mode: i32,
        size: u64,
        times: Option<(u64, u64)>,
    ) -> Result<Channel, Error> {
        let path = CString::new(util::path2bytes(remote_path)?)?;
        let (mtime, atime) = times.unwrap_or((0, 0));
        let inner = self.inner();
        unsafe {
            let ret = raw::libssh2_scp_send64(
                inner.raw,
                path.as_ptr(),
                mode as c_int,
                size as i64,
                mtime as libc::time_t,
                atime as libc::time_t,
            );
            let err = inner.last_error();
            Channel::from_raw_opt(ret, err, &self.inner)
        }
    }

    /// Open a channel and initialize the SFTP subsystem.
    ///
    /// Although the SFTP subsystem operates over the same type of channel as
    /// those exported by the Channel API, the protocol itself implements its
    /// own unique binary packet protocol which must be managed with the
    /// methods on `Sftp`.
    pub fn sftp(&self) -> Result<Sftp, Error> {
        let inner = self.inner();
        unsafe {
            let ret = raw::libssh2_sftp_init(inner.raw);
            let err = inner.last_error();
            Sftp::from_raw_opt(ret, err, &self.inner)
        }
    }

    /// Allocate a new channel for exchanging data with the server.
    ///
    /// This is typically not called directly but rather through
    /// `channel_session`, `channel_direct_tcpip`, or `channel_forward_listen`.
    pub fn channel_open(
        &self,
        channel_type: &str,
        window_size: u32,
        packet_size: u32,
        message: Option<&str>,
    ) -> Result<Channel, Error> {
        let channel_type = CString::new(channel_type)?;
        let channel_type = channel_type.as_bytes();
        let message = message.map(|s| CString::new(s)).transpose()?;
        let (message, message_len) = message
            .as_ref()
            .map(|s| (s.as_ptr(), s.as_bytes().len()))
            .unwrap_or((null(), 0));
        let inner = self.inner();
        unsafe {
            let ret = raw::libssh2_channel_open_ex(
                inner.raw,
                channel_type.as_ptr() as *const _,
                channel_type.len() as c_uint,
                window_size as c_uint,
                packet_size as c_uint,
                message,
                message_len as c_uint,
            );
            let err = inner.last_error();
            Channel::from_raw_opt(ret, err, &self.inner)
        }
    }

    /// Get the remote banner
    ///
    /// Once the session has been setup and handshake() has completed
    /// successfully, this function can be used to get the server id from the
    /// banner each server presents.
    ///
    /// May return `None` on invalid utf-8 or if an error has occurred.
    pub fn banner(&self) -> Option<&str> {
        self.banner_bytes().and_then(|s| str::from_utf8(s).ok())
    }

    /// See `banner`.
    ///
    /// Will only return `None` if an error has occurred.
    pub fn banner_bytes(&self) -> Option<&[u8]> {
        let inner = self.inner();
        unsafe { ::opt_bytes(self, raw::libssh2_session_banner_get(inner.raw)) }
    }

    /// Get the remote key.
    ///
    /// Returns `None` if something went wrong.
    pub fn host_key(&self) -> Option<(&[u8], HostKeyType)> {
        let mut len = 0;
        let mut kind = 0;
        let inner = self.inner();
        unsafe {
            let ret = raw::libssh2_session_hostkey(inner.raw, &mut len, &mut kind);
            if ret.is_null() {
                return None;
            }
            let data = slice::from_raw_parts(ret as *const u8, len as usize);
            let kind = match kind {
                raw::LIBSSH2_HOSTKEY_TYPE_RSA => HostKeyType::Rsa,
                raw::LIBSSH2_HOSTKEY_TYPE_DSS => HostKeyType::Dss,
                raw::LIBSSH2_HOSTKEY_TYPE_ECDSA_256 => HostKeyType::Ecdsa256,
                raw::LIBSSH2_HOSTKEY_TYPE_ECDSA_384 => HostKeyType::Ecdsa384,
                raw::LIBSSH2_HOSTKEY_TYPE_ECDSA_521 => HostKeyType::Ecdsa521,
                raw::LIBSSH2_HOSTKEY_TYPE_ED25519 => HostKeyType::Ed25519,
                raw::LIBSSH2_HOSTKEY_TYPE_UNKNOWN => HostKeyType::Unknown,
                _ => HostKeyType::Unknown,
            };
            Some((data, kind))
        }
    }

    /// Returns the computed digest of the remote system's hostkey.
    ///
    /// The bytes returned are the raw hash, and are not printable. If the hash
    /// is not yet available `None` is returned.
    pub fn host_key_hash(&self, hash: HashType) -> Option<&[u8]> {
        let len = match hash {
            HashType::Md5 => 16,
            HashType::Sha1 => 20,
            HashType::Sha256 => 32,
        };
        let inner = self.inner();
        unsafe {
            let ret = raw::libssh2_hostkey_hash(inner.raw, hash as c_int);
            if ret.is_null() {
                None
            } else {
                let ret = ret as *const u8;
                Some(slice::from_raw_parts(ret, len))
            }
        }
    }

    /// Set how often keepalive messages should be sent.
    ///
    /// The want_reply argument indicates whether the keepalive messages should
    /// request a response from the server.
    ///
    /// The interval argument is number of seconds that can pass without any
    /// I/O, use 0 (the default) to disable keepalives. To avoid some busy-loop
    /// corner-cases, if you specify an interval of 1 it will be treated as 2.
    pub fn set_keepalive(&self, want_reply: bool, interval: u32) {
        let inner = self.inner();
        unsafe { raw::libssh2_keepalive_config(inner.raw, want_reply as c_int, interval as c_uint) }
    }

    /// Send a keepalive message if needed.
    ///
    /// Returns how many seconds you can sleep after this call before you need
    /// to call it again.
    pub fn keepalive_send(&self) -> Result<u32, Error> {
        let mut ret = 0;
        let inner = self.inner();
        let rc = unsafe { raw::libssh2_keepalive_send(inner.raw, &mut ret) };
        inner.rc(rc)?;
        Ok(ret as u32)
    }

    /// Terminate the transport layer.
    ///
    /// Send a disconnect message to the remote host associated with session,
    /// along with a reason symbol and a verbose description.
    ///
    /// Note that this does *not* close the underlying socket.
    pub fn disconnect(
        &self,
        reason: Option<DisconnectCode>,
        description: &str,
        lang: Option<&str>,
    ) -> Result<(), Error> {
        let reason = reason.unwrap_or(ByApplication) as c_int;
        let description = CString::new(description)?;
        let lang = CString::new(lang.unwrap_or(""))?;
        let inner = self.inner();
        unsafe {
            inner.rc(raw::libssh2_session_disconnect_ex(
                inner.raw,
                reason,
                description.as_ptr(),
                lang.as_ptr(),
            ))
        }
    }

    /// Returns the blocked io directions that the application needs to wait for.
    ///
    /// This function should be used after an error of type `WouldBlock` is returned to
    /// find out the socket events the application has to wait for.
    pub fn block_directions(&self) -> BlockDirections {
        let inner = self.inner();
        let dir = unsafe { raw::libssh2_session_block_directions(inner.raw) };
        match dir {
            raw::LIBSSH2_SESSION_BLOCK_INBOUND => BlockDirections::Inbound,
            raw::LIBSSH2_SESSION_BLOCK_OUTBOUND => BlockDirections::Outbound,
            x if x == raw::LIBSSH2_SESSION_BLOCK_INBOUND | raw::LIBSSH2_SESSION_BLOCK_OUTBOUND => {
                BlockDirections::Both
            }
            _ => BlockDirections::None,
        }
    }

    fn inner(&self) -> MutexGuard<'_, SessionInner> {
        self.inner.lock()
    }

    /// Sets the trace level for the session.
    ///
    pub fn trace(&self, bitmask: TraceFlags) {
        let inner = self.inner();
        unsafe { let _ = raw::libssh2_trace(inner.raw, bitmask.bits() as c_int); }
    }

    /// Attempts to free the session.
    ///
    /// There are a few cases where this may not succeed:
    /// - If in nonblocking mode, may result in `LIBSSH2_ERROR_EAGAIN` if the
    ///   operation would block.
    /// - If a timeout is set, may result in `LIBSSH2_ERROR_TIMEOUT`.
    /// - If cloned sessions or objects created from this session still exist,
    ///   may result in `LIBSSH2_ERROR_BAD_USE`.
    ///
    /// This happens because `libssh2_session_free` combines freeing memory
    /// with IO to close the session cleanly. Nonblocking callers should call
    /// this function explicitly instead of relying on `drop` - otherwise it
    /// would result in a memory leak if the session fails to free due to
    /// blocking.
    pub fn free(self) -> Result<(), (Self, Error)> {
        let inner = match Arc::try_unwrap(self.inner) {
            Ok(inner) => inner,
            Err(inner) => {
                let err = Error::new(
                    ErrorCode::Session(raw::LIBSSH2_ERROR_BAD_USE),
                    "cannot free session while other handles exist",
                );
                return Err((Session { inner }, err));
            }
        };
        let mut inner = inner.into_inner();
        let rc = unsafe { raw::libssh2_session_free(inner.raw) };
        if rc >= 0 {
            inner.freed = true;
            Ok(())
        } else {
            let err = inner.rc(rc).unwrap_err();
            Err((
                Session {
                    inner: Arc::new(Mutex::new(inner)),
                },
                err,
            ))
        }
    }
}

#[cfg(unix)]
impl AsRawFd for Session {
    fn as_raw_fd(&self) -> RawFd {
        let inner = self.inner();
        match inner.tcp.as_ref() {
            Some(tcp) => tcp.as_raw_fd(),
            None => panic!("tried to obtain raw fd without tcp stream set"),
        }
    }
}

#[cfg(windows)]
impl AsRawSocket for Session {
    fn as_raw_socket(&self) -> RawSocket {
        let inner = self.inner();
        match inner.tcp.as_ref() {
            Some(tcp) => tcp.as_raw_socket(),
            None => panic!("tried to obtain raw socket without tcp stream set"),
        }
    }
}

impl SessionInner {
    /// Translate a return code into a Rust-`Result`.
    pub fn rc(&self, rc: c_int) -> Result<(), Error> {
        if rc >= 0 {
            Ok(())
        } else {
            Err(Error::from_session_error_raw(self.raw, rc))
        }
    }

    pub fn last_error(&self) -> Option<Error> {
        Error::last_session_error_raw(self.raw)
    }

    /// Set or clear blocking mode on session
    pub fn set_blocking(&self, blocking: bool) {
        unsafe { raw::libssh2_session_set_blocking(self.raw, blocking as c_int) }
    }

    /// Returns whether the session was previously set to nonblocking.
    pub fn is_blocking(&self) -> bool {
        unsafe { raw::libssh2_session_get_blocking(self.raw) != 0 }
    }
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        if !self.freed {
            unsafe {
                let _rc = raw::libssh2_session_free(self.raw);
            }
        }
    }
}

impl ScpFileStat {
    /// Returns the size of the remote file.
    pub fn size(&self) -> u64 {
        self.stat.st_size as u64
    }
    /// Returns the listed mode of the remote file.
    pub fn mode(&self) -> i32 {
        self.stat.st_mode as i32
    }
    /// Returns whether the remote file is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode() & (libc::S_IFMT as i32) == (libc::S_IFDIR as i32)
    }
    /// Returns whether the remote file is a regular file.
    pub fn is_file(&self) -> bool {
        self.mode() & (libc::S_IFMT as i32) == (libc::S_IFREG as i32)
    }
}
