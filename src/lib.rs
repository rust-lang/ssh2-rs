//! Rust bindings to libssh2, an SSH client library.
//!
//! This library intends to provide a safe interface to the libssh2 library. It
//! will build the library if it's not available on the local system, and
//! otherwise link to an installed copy.
//!
//! Note that libssh2 only supports SSH *clients*, not SSH *servers*.
//! Additionally it only supports protocol v2, not protocol v1.
//!
//! # Examples
//!
//! ## Inspecting ssh-agent
//!
//! ```no_run
//! use ssh2::Session;
//!
//! // Almost all APIs require a `Session` to be available
//! let sess = Session::new().unwrap();
//! let mut agent = sess.agent().unwrap();
//!
//! // Connect the agent and request a list of identities
//! agent.connect().unwrap();
//! agent.list_identities().unwrap();
//!
//! for identity in agent.identities().unwrap() {
//!     println!("{}", identity.comment());
//!     let pubkey = identity.blob();
//! }
//! ```
//!
//! ## Authenticating with ssh-agent
//!
//! ```no_run
//! use std::net::TcpStream;
//! use ssh2::Session;
//!
//! // Connect to the local SSH server
//! let tcp = TcpStream::connect("127.0.0.1:22").unwrap();
//! let mut sess = Session::new().unwrap();
//! sess.set_tcp_stream(tcp);
//! sess.handshake().unwrap();
//!
//! // Try to authenticate with the first identity in the agent.
//! sess.userauth_agent("username").unwrap();
//!
//! // Make sure we succeeded
//! assert!(sess.authenticated());
//! ```
//!
//! ## Authenticating with a password
//!
//! ```no_run
//! use std::net::TcpStream;
//! use ssh2::Session;
//!
//! // Connect to the local SSH server
//! let tcp = TcpStream::connect("127.0.0.1:22").unwrap();
//! let mut sess = Session::new().unwrap();
//! sess.set_tcp_stream(tcp);
//! sess.handshake().unwrap();
//!
//! sess.userauth_password("username", "password").unwrap();
//! assert!(sess.authenticated());
//! ```
//!
//! ## Run a command
//!
//! ```no_run
//! use std::io::prelude::*;
//! use std::net::TcpStream;
//! use ssh2::Session;
//!
//! // Connect to the local SSH server
//! let tcp = TcpStream::connect("127.0.0.1:22").unwrap();
//! let mut sess = Session::new().unwrap();
//! sess.set_tcp_stream(tcp);
//! sess.handshake().unwrap();
//! sess.userauth_agent("username").unwrap();
//!
//! let mut channel = sess.channel_session().unwrap();
//! channel.exec("ls").unwrap();
//! let mut s = String::new();
//! channel.read_to_string(&mut s).unwrap();
//! println!("{}", s);
//! channel.wait_close().unwrap();
//! println!("{}", channel.exit_status().unwrap());
//! ```
//!
//! ## Upload a file
//!
//! ```no_run
//! use std::io::prelude::*;
//! use std::net::TcpStream;
//! use std::path::Path;
//! use ssh2::Session;
//!
//! // Connect to the local SSH server
//! let tcp = TcpStream::connect("127.0.0.1:22").unwrap();
//! let mut sess = Session::new().unwrap();
//! sess.set_tcp_stream(tcp);
//! sess.handshake().unwrap();
//! sess.userauth_agent("username").unwrap();
//!
//! // Write the file
//! let mut remote_file = sess.scp_send(Path::new("remote"),
//!                                     0o644, 10, None).unwrap();
//! remote_file.write(b"1234567890").unwrap();
//! // Close the channel and wait for the whole content to be transferred
//! remote_file.send_eof().unwrap();
//! remote_file.wait_eof().unwrap();
//! remote_file.close().unwrap();
//! remote_file.wait_close().unwrap();
//! ```
//!
//! ## Download a file
//!
//! ```no_run
//! use std::io::prelude::*;
//! use std::net::TcpStream;
//! use std::path::Path;
//! use ssh2::Session;
//!
//! // Connect to the local SSH server
//! let tcp = TcpStream::connect("127.0.0.1:22").unwrap();
//! let mut sess = Session::new().unwrap();
//! sess.set_tcp_stream(tcp);
//! sess.handshake().unwrap();
//! sess.userauth_agent("username").unwrap();
//!
//! let (mut remote_file, stat) = sess.scp_recv(Path::new("remote")).unwrap();
//! println!("remote file size: {}", stat.size());
//! let mut contents = Vec::new();
//! remote_file.read_to_end(&mut contents).unwrap();
//!
//! // Close the channel and wait for the whole content to be tranferred
//! remote_file.send_eof().unwrap();
//! remote_file.wait_eof().unwrap();
//! remote_file.close().unwrap();
//! remote_file.wait_close().unwrap();
//! ```
//!
//! ## Execute a Netconf XML payload
//!
//! ```no_run
//! use ssh2::{Channel, Session};
//! use std::error::Error;
//! use std::io::prelude::*;
//! use std::net::TcpStream;
//!
//! const HELLO: &str = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">
//!   <capabilities>
//!     <capability>urn:ietf:params:netconf:base:1.1</capability>
//!   </capabilities>
//! </hello>
//! ]]>]]>";
//!
//! const PAYLOAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
//!     <rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.1\" message-id=\"2\">
//!     <cli xmlns=\"http://cisco.com/ns/yang/cisco-nx-os-device\"><mode>EXEC</mode><cmdline>show version</cmdline></cli>
//! </rpc>";
//!
//! fn read(channel: &mut Channel) -> Result<String, Box<dyn Error>> {
//!     let mut result = String::new();
//!     loop {
//!         // If you plan to use this, be aware that reading 1 byte at a time is terribly
//!         // inefficient and should be optimized for your usecase. This is just an example.
//!         let mut buffer = [1u8; 1];
//!         let bytes_read = channel.read(&mut buffer[..])?;
//!         let s = String::from_utf8_lossy(&buffer[..bytes_read]);
//!         result.push_str(&s);
//!         if result.ends_with("]]>]]>") {
//!             println!("Found netconf 1.0 terminator, breaking read loop");
//!             break;
//!         }
//!         if result.ends_with("##") {
//!             println!("Found netconf 1.1 terminator, breaking read loop");
//!             break;
//!         }
//!         if bytes_read == 0 || channel.eof() {
//!             println!("Buffer is empty, SSH channel read terminated");
//!             break;
//!         }
//!     }
//!     Ok(result)
//! }
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let tcp = TcpStream::connect("127.0.0.1:830")?;
//!     let mut sess = Session::new()?;
//!     sess.set_tcp_stream(tcp);
//!     sess.handshake().unwrap();
//!     sess.userauth_password("user", "pass")?;
//!
//!     let mut channel = sess.channel_session()?;
//!     channel.subsystem("netconf")?;
//!     let result = read(&mut channel)?;
//!     println!("Result from connection:\n{}", result);
//!
//!     let payload = format!("{}\n#{}\n{}\n##\n", HELLO, PAYLOAD.len(), PAYLOAD);
//!     let a = channel.write(payload.as_bytes())?;
//!     println!("Written {} bytes payload", a);
//!     let result = read(&mut channel)?;
//!     println!("Result from payload execution:\n{}", result);
//!
//!     channel.send_eof()?;
//!     channel.wait_eof()?;
//!     channel.close()?;
//!     channel.wait_close()?;
//!     Ok(())
//! }
//! ```

#![doc(html_root_url = "https://docs.rs/ssh2")]
#![allow(trivial_numeric_casts)]
#![deny(missing_docs, unused_results)]
#![cfg_attr(test, deny(warnings))]

extern crate libc;
pub extern crate libssh2_sys;
#[macro_use]
extern crate bitflags;
extern crate parking_lot;

use std::ffi::CStr;

use libssh2_sys as raw;

pub use agent::{Agent, PublicKey};
pub use channel::{Channel, ExitSignal, ReadWindow, Stream, WriteWindow};
pub use error::{Error, ErrorCode};
pub use knownhosts::{Host, KnownHosts};
pub use listener::Listener;
use session::SessionInner;
pub use session::{BlockDirections, KeyboardInteractivePrompt, Prompt, ScpFileStat, Session, TraceFlags};
pub use sftp::{File, FileStat, FileType, OpenType};
pub use sftp::{OpenFlags, RenameFlags, Sftp};
pub use DisconnectCode::{AuthCancelledByUser, TooManyConnections};
pub use DisconnectCode::{ByApplication, ConnectionLost, HostKeyNotVerifiable};
pub use DisconnectCode::{CompressionError, KeyExchangeFailed, MacError, Reserved};
pub use DisconnectCode::{HostNotAllowedToConnect, ProtocolError};
pub use DisconnectCode::{IllegalUserName, NoMoreAuthMethodsAvailable};
pub use DisconnectCode::{ProtocolVersionNotSupported, ServiceNotAvailable};

mod agent;
mod channel;
mod error;
mod knownhosts;
mod listener;
mod session;
mod sftp;
mod util;

/// Initialize the libssh2 library.
///
/// This is optional, it is lazily invoked.
pub fn init() {
    raw::init();
}

unsafe fn opt_bytes<'a, T>(_: &'a T, c: *const libc::c_char) -> Option<&'a [u8]> {
    if c.is_null() {
        None
    } else {
        Some(CStr::from_ptr(c).to_bytes())
    }
}

#[allow(missing_docs)]
#[derive(Copy, Clone)]
pub enum DisconnectCode {
    HostNotAllowedToConnect = raw::SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT as isize,
    ProtocolError = raw::SSH_DISCONNECT_PROTOCOL_ERROR as isize,
    KeyExchangeFailed = raw::SSH_DISCONNECT_KEY_EXCHANGE_FAILED as isize,
    Reserved = raw::SSH_DISCONNECT_RESERVED as isize,
    MacError = raw::SSH_DISCONNECT_MAC_ERROR as isize,
    CompressionError = raw::SSH_DISCONNECT_COMPRESSION_ERROR as isize,
    ServiceNotAvailable = raw::SSH_DISCONNECT_SERVICE_NOT_AVAILABLE as isize,
    ProtocolVersionNotSupported = raw::SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED as isize,
    HostKeyNotVerifiable = raw::SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE as isize,
    ConnectionLost = raw::SSH_DISCONNECT_CONNECTION_LOST as isize,
    ByApplication = raw::SSH_DISCONNECT_BY_APPLICATION as isize,
    TooManyConnections = raw::SSH_DISCONNECT_TOO_MANY_CONNECTIONS as isize,
    AuthCancelledByUser = raw::SSH_DISCONNECT_AUTH_CANCELLED_BY_USER as isize,
    NoMoreAuthMethodsAvailable = raw::SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE as isize,
    IllegalUserName = raw::SSH_DISCONNECT_ILLEGAL_USER_NAME as isize,
}

#[allow(missing_docs)]
#[derive(Copy, Clone, Debug)]
pub enum HostKeyType {
    Unknown = raw::LIBSSH2_HOSTKEY_TYPE_UNKNOWN as isize,
    Rsa = raw::LIBSSH2_HOSTKEY_TYPE_RSA as isize,
    Dss = raw::LIBSSH2_HOSTKEY_TYPE_DSS as isize,
    Ecdsa256 = raw::LIBSSH2_HOSTKEY_TYPE_ECDSA_256 as isize,
    Ecdsa384 = raw::LIBSSH2_HOSTKEY_TYPE_ECDSA_384 as isize,
    Ecdsa521 = raw::LIBSSH2_HOSTKEY_TYPE_ECDSA_521 as isize,
    Ed25519 = raw::LIBSSH2_HOSTKEY_TYPE_ED25519 as isize,
}

#[allow(missing_docs)]
#[derive(Copy, Clone)]
pub enum MethodType {
    Kex = raw::LIBSSH2_METHOD_KEX as isize,
    HostKey = raw::LIBSSH2_METHOD_HOSTKEY as isize,
    CryptCs = raw::LIBSSH2_METHOD_CRYPT_CS as isize,
    CryptSc = raw::LIBSSH2_METHOD_CRYPT_SC as isize,
    MacCs = raw::LIBSSH2_METHOD_MAC_CS as isize,
    MacSc = raw::LIBSSH2_METHOD_MAC_SC as isize,
    CompCs = raw::LIBSSH2_METHOD_COMP_CS as isize,
    CompSc = raw::LIBSSH2_METHOD_COMP_SC as isize,
    LangCs = raw::LIBSSH2_METHOD_LANG_CS as isize,
    LangSc = raw::LIBSSH2_METHOD_LANG_SC as isize,
    SignAlgo = raw::LIBSSH2_METHOD_SIGN_ALGO as isize,
}

/// When passed to `Channel::flush_stream`, flushes all extended data
/// substreams.
pub static FLUSH_EXTENDED_DATA: i32 = -1;
/// When passed to `Channel::flush_stream`, flushes all substream.
pub static FLUSH_ALL: i32 = -2;
/// Stream ID of the stderr channel for stream-related methods on `Channel`
pub static EXTENDED_DATA_STDERR: i32 = 1;

#[allow(missing_docs)]
#[derive(Copy, Clone, Debug)]
pub enum HashType {
    Md5 = raw::LIBSSH2_HOSTKEY_HASH_MD5 as isize,
    Sha1 = raw::LIBSSH2_HOSTKEY_HASH_SHA1 as isize,
    Sha256 = raw::LIBSSH2_HOSTKEY_HASH_SHA256 as isize,
}

#[allow(missing_docs)]
#[derive(Copy, Clone, Debug)]
pub enum KnownHostFileKind {
    OpenSSH = raw::LIBSSH2_KNOWNHOST_FILE_OPENSSH as isize,
}

/// Possible results of a call to `KnownHosts::check`
#[derive(Copy, Clone, Debug)]
pub enum CheckResult {
    /// Hosts and keys match
    Match = raw::LIBSSH2_KNOWNHOST_CHECK_MATCH as isize,
    /// Host was found, but the keys didn't match!
    Mismatch = raw::LIBSSH2_KNOWNHOST_CHECK_MISMATCH as isize,
    /// No host match was found
    NotFound = raw::LIBSSH2_KNOWNHOST_CHECK_NOTFOUND as isize,
    /// Something prevented the check to be made
    Failure = raw::LIBSSH2_KNOWNHOST_CHECK_FAILURE as isize,
}

#[allow(missing_docs)]
#[derive(Copy, Clone, Debug)]
pub enum KnownHostKeyFormat {
    Unknown = raw::LIBSSH2_KNOWNHOST_KEY_UNKNOWN as isize,
    Rsa1 = raw::LIBSSH2_KNOWNHOST_KEY_RSA1 as isize,
    SshRsa = raw::LIBSSH2_KNOWNHOST_KEY_SSHRSA as isize,
    SshDss = raw::LIBSSH2_KNOWNHOST_KEY_SSHDSS as isize,
    Ecdsa256 = raw::LIBSSH2_KNOWNHOST_KEY_ECDSA_256 as isize,
    Ecdsa384 = raw::LIBSSH2_KNOWNHOST_KEY_ECDSA_384 as isize,
    Ecdsa521 = raw::LIBSSH2_KNOWNHOST_KEY_ECDSA_521 as isize,
    Ed25519 = raw::LIBSSH2_KNOWNHOST_KEY_ED25519 as isize,
}

impl From<HostKeyType> for KnownHostKeyFormat {
    fn from(host_type: HostKeyType) -> KnownHostKeyFormat {
        match host_type {
            HostKeyType::Unknown => KnownHostKeyFormat::Unknown,
            HostKeyType::Rsa => KnownHostKeyFormat::SshRsa,
            HostKeyType::Dss => KnownHostKeyFormat::SshDss,
            HostKeyType::Ecdsa256 => KnownHostKeyFormat::Ecdsa256,
            HostKeyType::Ecdsa384 => KnownHostKeyFormat::Ecdsa384,
            HostKeyType::Ecdsa521 => KnownHostKeyFormat::Ecdsa521,
            HostKeyType::Ed25519 => KnownHostKeyFormat::Ed25519,
        }
    }
}

/// How to handle extended data streams, such as stderr
#[derive(Copy, Clone, Debug)]
pub enum ExtendedData {
    /// Queue extended data for eventual reading
    Normal = raw::LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL as isize,
    /// Treat extended data and ordinary data the same. Merge all substreams such that calls to
    /// read will pull from all substreams on a first-in/first-out basis.
    Merge = raw::LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE as isize,
    /// Discard all extended data as it arrives.
    Ignore = raw::LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE as isize,
}

/// The modes described in <https://tools.ietf.org/html/rfc4250#section-4.5.2>
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PtyModeOpcode {
    /// Indicates end of options.
    TTY_OP_END = 0,
    /// Interrupt character; 255 if none.  Similarly for the other characters.  Not all of these characters are supported on all systems.
    VINTR = 1,
    /// The quit character (sends SIGQUIT signal on POSIX systems).
    VQUIT = 2,
    /// Erase the character to left of the cursor.
    VERASE = 3,
    /// Kill the current input line.
    VKILL = 4,
    /// End-of-file character (sends EOF from the terminal).
    VEOF = 5,
    /// End-of-line character in addition to carriage return and/or linefeed.
    VEOL = 6,
    /// Additional end-of-line character.
    VEOL2 = 7,
    /// Continues paused output (normally control-Q).
    VSTART = 8,
    /// Pauses output (normally control-S).
    VSTOP = 9,
    /// Suspends the current program.
    VSUSP = 10,
    /// Another suspend character.
    VDSUSP = 11,
    /// Reprints the current input line.
    VREPRINT = 12,
    /// Erases a word left of cursor.
    VWERASE = 13,
    /// Enter the next character typed literally, even if it is a special character
    VLNEXT = 14,
    /// Character to flush output.
    VFLUSH = 15,
    /// Switch to a different shell layer.
    VSWTCH = 16,
    /// Prints system status line (load, command, pid, etc).
    VSTATUS = 17,
    /// Toggles the flushing of terminal output.
    VDISCARD = 18,
    /// The ignore parity flag.  The parameter SHOULD be 0 if this flag is FALSE, and 1 if it is TRUE.
    IGNPAR = 30,
    /// Mark parity and framing errors.
    PARMRK = 31,
    /// Enable checking of parity errors.
    INPCK = 32,
    /// Strip 8th bit off characters.
    ISTRIP = 33,
    /// Map NL into CR on input.
    INLCR = 34,
    /// Ignore CR on input.
    IGNCR = 35,
    /// Map CR to NL on input.
    ICRNL = 36,
    /// Translate uppercase characters to lowercase.
    IUCLC = 37,
    /// Enable output flow control.
    IXON = 38,
    /// Any char will restart after stop.
    IXANY = 39,
    /// Enable input flow control.
    IXOFF = 49,
    /// Ring bell on input queue full.
    IMAXBEL = 41,
    /// Enable signals INTR, QUIT, [D]SUSP.
    ISIG = 50,
    /// Canonicalize input lines.
    ICANON = 51,

    /// Enable input and output of uppercase characters by preceding their lowercase equivalents with "\".
    XCASE = 52,
    /// Enable echoing.
    ECHO = 53,
    /// Visually erase chars.
    ECHOE = 54,
    /// Kill character discards current line.
    ECHOK = 55,
    /// Echo NL even if ECHO is off.
    ECHONL = 56,
    /// Don't flush after interrupt.
    NOFLSH = 57,
    /// Stop background jobs from output.
    TOSTOP = 58,
    /// Enable extensions.
    IEXTEN = 59,
    /// Echo control characters as ^(Char).
    ECHOCTL = 60,
    /// Visual erase for line kill.
    ECHOKE = 61,
    /// Retype pending input.
    PENDIN = 62,
    /// Enable output processing.
    OPOST = 70,
    /// Convert lowercase to uppercase.
    OLCUC = 71,
    /// Map NL to CR-NL.
    ONLCR = 72,
    /// Translate carriage return to newline (output).
    OCRNL = 73,
    /// Translate newline to carriage return-newline (output).
    ONOCR = 74,
    /// Newline performs a carriage return (output).
    ONLRET = 75,
    /// 7 bit mode.
    CS7 = 90,
    /// 8 bit mode.
    CS8 = 91,
    /// Parity enable.
    PARENB = 92,
    /// Odd parity, else even.
    PARODD = 93,

    /// Specifies the input baud rate in bits per second.
    TTY_OP_ISPEED = 128,
    /// Specifies the output baud rate in bits per second.
    TTY_OP_OSPEED = 129,
}

/// An opcode for setting a Pty terminal mode
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExtensiblePtyModeOpcode {
    /// Use one of the modes specified by RFC 4250
    Mode(PtyModeOpcode),
    /// Use a mode not reflected by RFC 4250
    Extended(u8),
}

impl From<PtyModeOpcode> for ExtensiblePtyModeOpcode {
    fn from(op: PtyModeOpcode) -> ExtensiblePtyModeOpcode {
        ExtensiblePtyModeOpcode::Mode(op)
    }
}

impl From<u8> for ExtensiblePtyModeOpcode {
    fn from(op: u8) -> ExtensiblePtyModeOpcode {
        ExtensiblePtyModeOpcode::Extended(op)
    }
}

impl ExtensiblePtyModeOpcode {
    fn as_opcode(&self) -> u8 {
        match self {
            ExtensiblePtyModeOpcode::Mode(m) => *m as u8,
            ExtensiblePtyModeOpcode::Extended(op) => *op,
        }
    }
}

/// Encodes modes for Pty allocation requests.
/// The modes documented in <https://tools.ietf.org/html/rfc4250#section-4.5>
/// are supported.
#[derive(Debug, Clone)]
pub struct PtyModes {
    data: Vec<u8>,
}

impl PtyModes {
    /// Construct a PtyModes instance so that you can specify values for
    /// various modes
    pub fn new() -> Self {
        Self { data: vec![] }
    }

    /// Set a mode to an arbitrary u32 value
    pub fn set_u32<O: Into<ExtensiblePtyModeOpcode>>(&mut self, option: O, value: u32) {
        let data = [
            option.into().as_opcode(),
            ((value >> 24) & 0xff) as u8,
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ];
        self.data.extend_from_slice(&data);
    }

    /// Set a mode to a boolean value
    pub fn set_boolean<O: Into<ExtensiblePtyModeOpcode>>(&mut self, option: O, value: bool) {
        self.set_u32(option, if value { 1 } else { 0 })
    }

    /// Set a mode to a character value.
    /// If the character is None it is set to 255 to indicate that it
    /// is disabled.
    /// While this interface and the protocol accept unicode characters
    /// of up to 32 bits in width, these options likely only work for
    /// characters in the 7-bit ascii range.
    pub fn set_character<O: Into<ExtensiblePtyModeOpcode>>(&mut self, option: O, c: Option<char>) {
        self.set_u32(option, c.map(|c| c as u32).unwrap_or(255))
    }

    /// Finish accumulating modes and return the encoded
    /// byte stream suitable for use in the ssh2 protocol
    pub fn finish(mut self) -> Vec<u8> {
        self.data.push(PtyModeOpcode::TTY_OP_END as u8);
        self.data
    }
}
