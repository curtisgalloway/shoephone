// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! CLI-side behavior that does not need the daemon in the loop: per-host
//! session keys, atomic certificate writes, and how transport failures map
//! onto exit codes.

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use shoephone::client::Client;
use shoephone::exit::Status;
use shoephone::session::Session;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shoephone-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn for_host_gives_distinct_keys_under_expected_paths() {
    let base = scratch("distinct-hosts");
    let a = Session::for_host(base.clone(), "host-a").unwrap();
    let b = Session::for_host(base.clone(), "host-b").unwrap();
    assert_eq!(a.dir(), base.join("hosts").join("host-a"));
    assert_eq!(b.dir(), base.join("hosts").join("host-b"));
    assert_eq!(a.key_path(), base.join("hosts/host-a/session_ed25519"));
    assert_eq!(b.key_path(), base.join("hosts/host-b/session_ed25519"));

    let key_a = a.public_key().unwrap();
    let key_b = b.public_key().unwrap();
    assert!(key_a.starts_with("ssh-ed25519 "));
    assert!(key_b.starts_with("ssh-ed25519 "));
    assert_ne!(key_a, key_b, "each host must get its own keypair");
    assert!(a.key_path().exists());
    assert!(b.key_path().exists());

    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn for_host_refuses_unsafe_host_names() {
    let base = scratch("unsafe-hosts");
    assert!(Session::for_host(base.clone(), "../x").is_err());
    assert!(Session::for_host(base.clone(), "a/b").is_err());
    assert!(Session::for_host(base.clone(), ".hidden").is_err());
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn write_certificate_is_atomic_and_leaves_no_tmp_file() {
    let base = scratch("atomic-cert");
    let session = Session::for_host(base.clone(), "web01").unwrap();
    session.public_key().unwrap();
    session
        .write_certificate("  ssh-ed25519-cert-v01@openssh.com AAAAsomefakecert  ")
        .unwrap();

    let cert_path = session.cert_path();
    let content = std::fs::read_to_string(&cert_path).unwrap();
    assert_eq!(
        content,
        "ssh-ed25519-cert-v01@openssh.com AAAAsomefakecert\n"
    );

    let leftovers: Vec<_> = std::fs::read_dir(cert_path.parent().unwrap())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "leftover tmp files: {leftovers:?}");

    std::fs::remove_dir_all(&base).unwrap();
}

/// A timeout after the connection is already open is ambiguous: the daemon
/// may have received and acted on the request before the response never
/// arrived.
#[test]
fn timeout_after_connecting_is_retry_unknown() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            // Accept and hold the connection open, but never write a
            // response, so the client's request eventually times out
            // waiting for one.
            let mut stream = stream;
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            std::thread::sleep(Duration::from_secs(5));
        }
    });

    let client = Client::with_timeout(&format!("http://{addr}"), Duration::from_millis(300));
    let err = client.status().unwrap_err();
    assert_eq!(err.status(), Status::RetryUnknown);
}

/// Nothing listening at all fails the connection outright: the daemon was
/// never reached, so this is unambiguous.
#[test]
fn refused_connection_is_unreachable() {
    let client = Client::new("http://127.0.0.1:1");
    let err = client.status().unwrap_err();
    assert_eq!(err.status(), Status::Unreachable);
}
