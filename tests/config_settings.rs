//! Exercise encrypted persistence through the real Windows server process.
#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/config-tests")
            .join(format!("{:016x}", u64::from_le_bytes(nonce)));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vncfree-server"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("VNC_") {
                command.env_remove(key);
            }
        }
        command.env("APPDATA", &self.0);
        command.stdout(Stdio::null()).stderr(Stdio::piped());
        command
    }

    fn config(&self) -> PathBuf {
        self.0.join("vncfree/server.cfg")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/config-tests");
        if self.0.starts_with(root) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn authenticate(command: &mut Command, port: u16, password: &str) {
    let mut server = Server(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            let mut error = String::new();
            server
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut error)
                .unwrap();
            panic!("server exited {status}: {error}");
        }
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            Err(error) => panic!("server did not listen: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut version = [0; 12];
    stream.read_exact(&mut version).unwrap();
    assert_eq!(&version, b"RFB 003.008\n");
    stream.write_all(&version).unwrap();
    let mut security = [0; 2];
    stream.read_exact(&mut security).unwrap();
    assert_eq!(security, [1, 2], "saved VNC_TLS=off is applied");
    stream.write_all(&[2]).unwrap();
    let mut challenge = [0; 16];
    stream.read_exact(&mut challenge).unwrap();
    vncfree::vnc_des(&mut challenge, password);
    stream.write_all(&challenge).unwrap();
    let mut result = [0; 4];
    stream.read_exact(&mut result).unwrap();
    assert_eq!(result, [0; 4], "password accepted");
}

#[test]
fn settings_and_password_survive_restart_with_explicit_overrides() {
    let fixture = Fixture::new();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    authenticate(
        fixture
            .command()
            .args(["--password", "saved123", "--headless"])
            .env("VNC_PASSWORD", "ignored")
            .env("VNC_BIND", format!("127.0.0.1:{port}"))
            .env("VNC_TLS", "off"),
        port,
        "saved123",
    );
    let encrypted = std::fs::read(fixture.config()).unwrap();
    assert!(!encrypted.windows(8).any(|b| b == b"saved123"));
    assert!(!encrypted.windows(8).any(|b| b == b"VNC_BIND"));
    // Explicit headless launch without VNC_* variables: password, binding and
    // TLS mode must all come from the encrypted configuration.
    authenticate(fixture.command().arg("--headless"), port, "saved123");
    authenticate(
        fixture
            .command()
            .arg("--headless")
            .env("VNC_PASSWORD", "envpass"),
        port,
        "envpass",
    );
    // Empty values mean no password supplied, preserving the stored one.
    authenticate(
        fixture
            .command()
            .args(["--password="])
            .env("VNC_PASSWORD", ""),
        port,
        "envpass",
    );
    authenticate(fixture.command().arg("--headless"), port, "envpass");
}

#[test]
fn corrupted_config_is_reported_and_preserved() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.config().parent().unwrap()).unwrap();
    std::fs::write(fixture.config(), b"corrupted settings").unwrap();
    let output = fixture.command().arg("--headless").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not load"));
    assert_eq!(
        std::fs::read(fixture.config()).unwrap(),
        b"corrupted settings"
    );
}

#[test]
fn autostart_helper_dispatch_does_not_read_the_password_config() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.config().parent().unwrap()).unwrap();
    std::fs::write(fixture.config(), b"not decryptable under another account").unwrap();
    let output = fixture
        .command()
        .args(["--autostart-helper", "invalid-action", "DOMAIN\\user"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(windows::Win32::Foundation::E_INVALIDARG.0)
    );
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("administrator task update failed"));
    assert!(!message.contains("could not load"));
    assert_eq!(
        std::fs::read(fixture.config()).unwrap(),
        b"not decryptable under another account"
    );
}
