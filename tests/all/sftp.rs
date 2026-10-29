use std::fs::{self, File};
use std::io::prelude::*;
use tempfile::TempDir;

#[test]
fn smoke() {
    let sess = ::authed_session();
    sess.sftp().unwrap();
}

#[test]
fn ops() {
    let td = TempDir::new().unwrap();
    File::create(&td.path().join("foo")).unwrap();
    fs::create_dir(&td.path().join("bar")).unwrap();

    let sess = ::authed_session();
    let sftp = sess.sftp().unwrap();
    let path = td.path().join("bar");
    let path_str: &str = path.to_str().unwrap();
    sftp.opendir(&path).unwrap();
    sftp.opendir(path_str).unwrap();
    let mut foo = sftp.open(&td.path().join("foo")).unwrap();
    sftp.mkdir(&td.path().join("bar2"), 0o755).unwrap();
    assert!(fs::metadata(&td.path().join("bar2"))
        .map(|m| m.is_dir())
        .unwrap_or(false));
    sftp.rmdir(&td.path().join("bar2")).unwrap();

    sftp.create(&td.path().join("foo5"))
        .unwrap()
        .write_all(b"foo")
        .unwrap();
    let mut v = Vec::new();
    File::open(&td.path().join("foo5"))
        .unwrap()
        .read_to_end(&mut v)
        .unwrap();
    assert_eq!(v, b"foo");

    assert_eq!(sftp.stat(&td.path().join("foo")).unwrap().size, Some(0));
    v.clear();
    foo.read_to_end(&mut v).unwrap();
    assert_eq!(v, Vec::new());

    sftp.symlink(&td.path().join("foo"), &td.path().join("foo2"))
        .unwrap();
    let readlink = sftp.readlink(&td.path().join("foo2")).unwrap();
    assert!(readlink == td.path().join("foo"));
    let realpath = sftp.realpath(&td.path().join("foo2")).unwrap();
    assert_eq!(realpath, td.path().join("foo").canonicalize().unwrap());

    let path = td.path();
    let path_str: &str = path.to_str().unwrap();
    let files = sftp.readdir(path).unwrap();
    let files_from_str = sftp.readdir(path_str).unwrap();
    for (f1, f2) in files.iter().zip(files_from_str.iter()) {
        assert_eq!(f1, f2);
    }
}

#[test]
fn not_found() {
    let td = TempDir::new().unwrap();

    let sess = ::authed_session();
    let sftp = sess.sftp().unwrap();

    // Can't use unwrap_err here since File does not impl Debug.
    let err = sftp
        .opendir(&td.path().join("nonexistent"))
        .err()
        .expect("open nonexistent dir");
    assert_eq!(err.to_string(), "[SFTP(2)] no such file");

    let io_err: std::io::Error = err.into();
    assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(io_err.to_string(), "no such file");

    let err = sftp
        .stat(&td.path().join("nonexistent"))
        .err()
        .expect("stat nonexistent");
    assert_eq!(err.to_string(), "[SFTP(2)] no such file");
    let io_err: std::io::Error = err.into();
    assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(io_err.to_string(), "no such file");
}

#[test]
fn nonblocking_shutdown_can_be_retried() {
    use ssh2::{ErrorCode, Session};
    use std::env;
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    // Pause server replies so that shutdown deterministically needs another read.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut client, _) = listener.accept().unwrap();
    let mut server = ::socket();
    let mut client_read = client.try_clone().unwrap();
    let mut server_write = server.try_clone().unwrap();
    let requests = thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut server_write);
        let _ = server_write.shutdown(Shutdown::Write);
    });
    let replies = Arc::new(Mutex::new(()));
    let reply_gate = replies.clone();
    let responses = thread::spawn(move || {
        let mut buf = [0; 8192];
        while let Ok(n) = server.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _gate = reply_gate.lock().unwrap();
            if client.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = client.shutdown(Shutdown::Write);
    });

    let mut sess = Session::new().unwrap();
    socket.set_nonblocking(true).unwrap();
    sess.set_tcp_stream(socket);
    sess.handshake().unwrap();
    let mut agent = sess.agent().unwrap();
    agent.connect().unwrap();
    agent.list_identities().unwrap();
    agent
        .userauth(&env::var("USER").unwrap(), &agent.identities().unwrap()[0])
        .unwrap();
    drop(agent);
    let mut sftp = sess.sftp().unwrap();

    let paused = replies.lock().unwrap();
    sess.set_blocking(false);
    let would_block = ErrorCode::Session(ssh2::libssh2_sys::LIBSSH2_ERROR_EAGAIN);
    assert_eq!(sftp.shutdown().unwrap_err().code(), would_block);
    assert_eq!(sftp.shutdown().unwrap_err().code(), would_block);
    drop(paused);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match sftp.shutdown() {
            Ok(()) => break,
            Err(e) => {
                assert_eq!(e.code(), would_block);
                assert!(Instant::now() < deadline, "shutdown did not complete");
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
    assert_eq!(
        sftp.shutdown().unwrap_err().code(),
        ErrorCode::Session(ssh2::libssh2_sys::LIBSSH2_ERROR_BAD_USE)
    );
    sess.set_blocking(true);
    sess.sftp().unwrap();
    drop(sftp);
    drop(sess);
    requests.join().unwrap();
    responses.join().unwrap();
}

#[test]
fn shutdown_with_open_file_keeps_sftp_usable() {
    let sess = ::authed_session();
    let mut sftp = sess.sftp().unwrap();
    let td = TempDir::new().unwrap();
    let file = sftp.create(&td.path().join("open")).unwrap();
    assert_eq!(
        sftp.shutdown().unwrap_err().code(),
        ssh2::ErrorCode::Session(ssh2::libssh2_sys::LIBSSH2_ERROR_BAD_USE)
    );
    sftp.stat(&td.path().join("open")).unwrap();
    drop(file);
    sftp.shutdown().unwrap();
}
