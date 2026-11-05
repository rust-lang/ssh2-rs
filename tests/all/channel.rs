use ssh2::Channel;
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::thread;

/// Consume all available stdout and stderr data.
/// It is important to read both if you are using
/// channel.eof() to make assertions that the stream
/// is complete
fn consume_stdio(channel: &mut Channel) -> (String, String) {
    let mut stdout = String::new();
    channel.read_to_string(&mut stdout).unwrap();

    let mut stderr = String::new();
    channel.stderr().read_to_string(&mut stderr).unwrap();

    eprintln!("stdout: {}", stdout);
    eprintln!("stderr: {}", stderr);

    (stdout, stderr)
}

#[test]
fn smoke() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();

    fn must_be_send<T: Send>(_: &T) -> bool {
        true
    }
    assert!(must_be_send(&channel));
    assert!(must_be_send(&channel.stream(0)));

    channel.flush().unwrap();
    channel.exec("true").unwrap();
    consume_stdio(&mut channel);

    channel.wait_eof().unwrap();
    assert!(channel.eof());

    channel.close().unwrap();
    channel.wait_close().unwrap();
    assert_eq!(channel.exit_status().unwrap(), 0);
    assert!(channel.eof());
}

#[test]
fn agent_forward() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.request_auth_agent_forwarding().unwrap();
    channel.exec("echo $SSH_AUTH_SOCK").unwrap();

    let (output, _) = consume_stdio(&mut channel);
    let output = output.trim();
    // make sure that the sock is set
    assert_ne!(output, "");
    // and that it isn't just inherited the one we set for this
    // test environment
    assert_ne!(output, std::env::var("SSH_AUTH_SOCK").unwrap());
}

#[test]
fn bad_smoke() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.flush().unwrap();
    channel.exec("false").unwrap();
    consume_stdio(&mut channel);

    channel.wait_eof().unwrap();
    assert!(channel.eof());

    channel.close().unwrap();
    channel.wait_close().unwrap();
    assert_eq!(channel.exit_status().unwrap(), 1);
    assert!(channel.eof());
}

#[test]
fn reading_data() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("echo foo").unwrap();

    let (output, _) = consume_stdio(&mut channel);
    assert_eq!(output, "foo\n");
}

#[test]
fn handle_extended_data() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel
        .handle_extended_data(ssh2::ExtendedData::Merge)
        .unwrap();
    channel.exec("echo foo >&2").unwrap();
    let (output, _) = consume_stdio(&mut channel);
    // This is an ends_with test because stderr may have several
    // lines of misc output on travis macos hosts; it appears as
    // though the local shell configuration on travis macos is
    // broken and contributes to this :-/
    assert!(output.ends_with("foo\n"));
}

#[test]
fn writing_data() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("read foo && echo $foo").unwrap();
    channel.write_all(b"foo\n").unwrap();

    let (output, _) = consume_stdio(&mut channel);
    assert_eq!(output, "foo\n");
}

#[test]
fn eof() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.adjust_receive_window(10, false).unwrap();
    channel.exec("read foo").unwrap();
    channel.send_eof().unwrap();
    let mut output = String::new();
    channel.read_to_string(&mut output).unwrap();
    assert_eq!(output, "");
}

#[test]
fn shell() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    eprintln!("requesting pty");
    channel.request_pty("xterm", None, None).unwrap();
    eprintln!("shell");
    channel.shell().unwrap();
    let _ = channel.write_all(b"exit\n");
    consume_stdio(&mut channel);
    channel.wait_eof().unwrap();
    eprintln!("close");
    channel.close().unwrap();
    channel.wait_close().unwrap();
    eprintln!("done");
}

#[test]
fn setenv() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    let _ = channel.setenv("FOO", "BAR");
    channel.close().unwrap();
}

#[test]
fn direct() {
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = a.local_addr().unwrap();
    let t = thread::spawn(move || {
        let mut s = a.accept().unwrap().0;
        let mut b = [0, 0, 0];
        s.read(&mut b).unwrap();
        assert_eq!(b, [1, 2, 3]);
        s.write_all(&[4, 5, 6]).unwrap();
    });
    let sess = ::authed_session();
    let mut channel = sess
        .channel_direct_tcpip("127.0.0.1", addr.port(), None)
        .unwrap();
    channel.write_all(&[1, 2, 3]).unwrap();
    let mut r = [0, 0, 0];
    channel.read(&mut r).unwrap();
    assert_eq!(r, [4, 5, 6]);
    t.join().ok().unwrap();
}

#[cfg(all(unix))]
#[test]
fn direct_stream_local() {
    use std::os::unix::net::UnixListener;

    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("ssh2-rs-test.sock");
    let a = UnixListener::bind(&path).unwrap();
    let t = thread::spawn(move || {
        let mut s = a.accept().unwrap().0;
        let mut b = [0, 0, 0];
        s.read(&mut b).unwrap();
        assert_eq!(b, [1, 2, 3]);
        s.write_all(&[4, 5, 6]).unwrap();
    });
    let sess = ::authed_session();
    let mut channel = sess
        .channel_direct_streamlocal(path.to_str().unwrap(), None)
        .unwrap();
    channel.write_all(&[1, 2, 3]).unwrap();
    let mut r = [0, 0, 0];
    channel.read(&mut r).unwrap();
    assert_eq!(r, [4, 5, 6]);
    t.join().ok().unwrap();
}

#[test]
fn forward() {
    let sess = ::authed_session();
    let (mut listen, port) = sess.channel_forward_listen(39249, None, None).unwrap();
    let t = thread::spawn(move || {
        let mut s = TcpStream::connect(&("127.0.0.1", port)).unwrap();
        let mut b = [0, 0, 0];
        s.read(&mut b).unwrap();
        assert_eq!(b, [1, 2, 3]);
        s.write_all(&[4, 5, 6]).unwrap();
    });

    let mut channel = listen.accept().unwrap();
    channel.write_all(&[1, 2, 3]).unwrap();
    let mut r = [0, 0, 0];
    channel.read(&mut r).unwrap();
    assert_eq!(r, [4, 5, 6]);
    t.join().ok().unwrap();
}

#[test]
fn drop_nonblocking() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let sess = ::authed_session();
    sess.set_blocking(false);

    thread::spawn(move || {
        let _s = listener.accept().unwrap();
    });

    let _ = sess.channel_direct_tcpip("127.0.0.1", addr.port(), None);
    drop(sess);
}

#[test]
fn nonblocking_before_exit_code() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.send_eof().unwrap();
    let mut output = String::new();

    channel.exec("sleep 1; echo foo").unwrap();
    sess.set_blocking(false);
    assert!(channel.read_to_string(&mut output).is_err());
    {
        use std::thread;
        use std::time::Duration;
        thread::sleep(Duration::from_millis(1500));
    }
    sess.set_blocking(true);
    assert!(channel.read_to_string(&mut output).is_ok());

    channel.wait_eof().unwrap();
    channel.close().unwrap();
    channel.wait_close().unwrap();
    assert_eq!(output, "foo\n");
    assert!(channel.exit_status().unwrap() == 0);
}

#[test]
fn exit_code_ignores_other_errors() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("true").unwrap();
    channel.wait_eof().unwrap();
    channel.close().unwrap();
    channel.wait_close().unwrap();
    let longdescription: String = ::std::iter::repeat('a').take(300).collect();
    assert!(sess.disconnect(None, &longdescription, None).is_err()); // max len == 256
    assert!(channel.exit_status().unwrap() == 0);
}

#[test]
fn pty_modes_are_propagated() {
    let sess = ::authed_session();
    let mut channel = sess.channel_session().unwrap();
    eprintln!("requesting pty");

    let mut mode = ssh2::PtyModes::new();
    // intr is typically CTRL-C; setting it to unmodified `y`
    // should be very high signal that it took effect
    mode.set_character(ssh2::PtyModeOpcode::VINTR, Some('y'));

    channel.request_pty("xterm", Some(mode), None).unwrap();
    channel.exec("stty -a").unwrap();

    let (out, _err) = consume_stdio(&mut channel);
    channel.close().unwrap();

    // This may well be linux specific
    assert!(out.contains("intr = y"), "mode was propagated");
}
