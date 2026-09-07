// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The user CA: turns a [`grant::Certificate`] into an OpenSSH certificate.
//!
//! This is the only module that touches key material. It is deliberately
//! small: load an ed25519 CA key from a root-only file, canonicalize the
//! public keys the CLI sends, and sign what [`grant::Grants::issue`] already
//! decided. Every field on the certificate comes from the grant; nothing here
//! makes a policy decision.

use std::fmt;
use std::path::Path;

use ssh_key::certificate::{Builder, CertType};
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, Fingerprint, HashAlg, LineEnding, PrivateKey, PublicKey};

use crate::grant;

/// Random bytes from the operating system, for [`grant::Grants`].
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl grant::Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        OsRng.fill_bytes(buf);
    }
}

#[derive(Debug)]
pub enum Error {
    /// The CA file could not be read.
    Io(std::io::Error),
    /// The key is not one this daemon accepts (only unencrypted ed25519).
    Unsupported(String),
    /// A key or certificate failed to parse or sign.
    Key(ssh_key::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "key file: {e}"),
            Error::Unsupported(why) => write!(f, "unsupported key: {why}"),
            Error::Key(e) => write!(f, "ssh key: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ssh_key::Error> for Error {
    fn from(e: ssh_key::Error) -> Self {
        Error::Key(e)
    }
}

/// Parse an OpenSSH public key line and return it in canonical form:
/// `ssh-ed25519 <base64>`, no comment, no surrounding whitespace. The grant
/// machine compares keys as strings, so the daemon must canonicalize every
/// key before it reaches [`grant::Grants::request`] or
/// [`grant::Grants::issue`], or a comment change would look like a new key.
pub fn canonical_public_key(line: &str) -> Result<String, Error> {
    let key = PublicKey::from_openssh(line.trim())?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(Error::Unsupported(format!(
            "{} keys are not accepted; use ed25519",
            key.algorithm()
        )));
    }
    let bare = PublicKey::from(key.key_data().clone());
    Ok(bare.to_openssh()?)
}

/// The SHA-256 fingerprint of a public key line, for the approve page.
pub fn fingerprint(line: &str) -> Result<Fingerprint, Error> {
    Ok(PublicKey::from_openssh(line.trim())?.fingerprint(HashAlg::Sha256))
}

/// The user certificate authority.
pub struct UserCa {
    key: PrivateKey,
}

impl fmt::Debug for UserCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserCa")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl UserCa {
    /// Load the CA from an unencrypted OpenSSH private key file. The daemon
    /// runs headless, so the file must not carry a passphrase; the disk
    /// encryption under it is the protection at rest.
    pub fn from_openssh_file(path: &Path) -> Result<Self, Error> {
        let pem = std::fs::read(path).map_err(Error::Io)?;
        Self::from_openssh(&pem)
    }

    pub fn from_openssh(pem: &[u8]) -> Result<Self, Error> {
        let key = PrivateKey::from_openssh(pem)?;
        if key.is_encrypted() {
            return Err(Error::Unsupported(
                "the CA key is passphrase-protected; a headless signer cannot use it".into(),
            ));
        }
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(Error::Unsupported(format!(
                "CA key is {}; only ed25519 is accepted",
                key.algorithm()
            )));
        }
        Ok(Self { key })
    }

    /// Generate a fresh ed25519 CA. Used by the enrollment command at the
    /// failsafe host's console, never by anything the agent can reach.
    pub fn generate(comment: &str) -> Result<Self, Error> {
        let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
        key.set_comment(comment);
        Ok(Self { key })
    }

    /// Write the private key, unencrypted, for the enrollment command. The
    /// caller is responsible for the file's mode and owner.
    pub fn write_openssh_file(&self, path: &Path) -> Result<(), Error> {
        let pem = self.key.to_openssh(LineEnding::LF)?;
        write_new_private(path, pem.as_bytes())
    }

    /// The line that goes in every host's `TrustedUserCAKeys` file.
    pub fn public_key_line(&self) -> Result<String, Error> {
        Ok(self.key.public_key().to_openssh()?)
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint(HashAlg::Sha256)
    }

    /// Sign what the grant machine decided. The certificate carries exactly
    /// one principal, the serial the grant assigned, and a key id that names
    /// the host and serial so sshd's auth log attributes the session.
    pub fn sign(
        &self,
        cert: &grant::Certificate,
        host: &str,
    ) -> Result<ssh_key::Certificate, Error> {
        let subject = PublicKey::from_openssh(&cert.public_key)?;
        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            subject.key_data().clone(),
            unix(cert.valid_after),
            unix(cert.valid_before),
        )?;
        builder
            .serial(cert.serial)?
            .cert_type(CertType::User)?
            .key_id(format!("shoephone:{host}:{}", cert.serial))?
            .valid_principal(cert.principal.clone())?
            // The minimum for an interactive admin session. Agent and X11
            // forwarding stay off: forwarding the session's agent to a host
            // would lend that host every key in it. Port forwarding is off
            // until a real need shows up; widen deliberately, here.
            .extension("permit-pty", "")?;
        Ok(builder.sign(&self.key)?)
    }
}

/// Create a private key file that did not exist before, mode 0600, never
/// following a symlink and never truncating. A check-then-write with a
/// truncating open has a window in which a planted symlink or a racing
/// second run replaces the key; `create_new` closes it.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path).map_err(Error::Io)?;
    f.write_all(bytes).map_err(Error::Io)?;
    f.sync_all().map_err(Error::Io)
}

fn unix(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn subject() -> PrivateKey {
        let mut k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        k.set_comment("session@laptop");
        k
    }

    fn grant_cert(subject_line: &str) -> grant::Certificate {
        let after = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        grant::Certificate {
            serial: 7,
            principal: "agent-admin:web01".to_owned(),
            public_key: subject_line.to_owned(),
            valid_after: after,
            valid_before: after + Duration::from_secs(15 * 60),
            window_ends_at: after + Duration::from_secs(60 * 60),
        }
    }

    #[test]
    fn canonical_form_drops_comment_and_whitespace() {
        let k = subject();
        let with_comment = k.public_key().to_openssh().unwrap();
        assert!(with_comment.ends_with(" session@laptop"));
        let canon = canonical_public_key(&format!("  {with_comment}\n")).unwrap();
        assert!(!canon.contains("session@laptop"));
        assert!(canon.starts_with("ssh-ed25519 "));
        assert_eq!(canonical_public_key(&canon).unwrap(), canon, "idempotent");
        assert!(canonical_public_key("ssh-ed25519 notbase64").is_err());
        assert_eq!(
            fingerprint(&canon).unwrap(),
            k.public_key().fingerprint(HashAlg::Sha256)
        );
    }

    #[test]
    fn signs_exactly_what_the_grant_decided() {
        let ca = UserCa::generate("shoephone user CA").unwrap();
        let subject = subject();
        let line = canonical_public_key(&subject.public_key().to_openssh().unwrap()).unwrap();
        let wanted = grant_cert(&line);
        let cert = ca.sign(&wanted, "web01").unwrap();

        assert_eq!(cert.serial(), 7);
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(cert.valid_principals(), ["agent-admin:web01"]);
        assert_eq!(cert.key_id(), "shoephone:web01:7");
        assert_eq!(cert.valid_after_time(), wanted.valid_after);
        assert_eq!(cert.valid_before_time(), wanted.valid_before);
        assert_eq!(cert.public_key(), subject.public_key().key_data());
        assert!(cert.critical_options().is_empty());
        assert_eq!(cert.extensions().keys().collect::<Vec<_>>(), ["permit-pty"]);

        let fp = ca.fingerprint();
        cert.validate_at(1_800_000_000 + 60, [&fp]).unwrap();
        assert!(
            cert.validate_at(1_800_000_000 + 15 * 60 + 1, [&fp])
                .is_err(),
            "expired"
        );
        let other = UserCa::generate("impostor").unwrap();
        assert!(
            cert.validate_at(1_800_000_000 + 60, [&other.fingerprint()])
                .is_err()
        );

        let text = cert.to_openssh().unwrap();
        assert!(text.starts_with("ssh-ed25519-cert-v01@openssh.com "));
        let parsed = ssh_key::Certificate::from_openssh(&text).unwrap();
        assert_eq!(parsed.serial(), 7);

        if let Ok(dir) = std::env::var("SHOEPHONE_TEST_DUMP") {
            let dir = Path::new(&dir);
            std::fs::write(dir.join("ca.pub"), ca.public_key_line().unwrap()).unwrap();
            std::fs::write(dir.join("id-cert.pub"), text).unwrap();
        }
    }

    #[test]
    fn ca_file_round_trips_and_rejects_the_wrong_material() {
        let ca = UserCa::generate("shoephone user CA").unwrap();
        let dir = std::env::temp_dir().join(format!("shoephone-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("user_ca");
        ca.write_openssh_file(&path).unwrap();
        let again = UserCa::from_openssh_file(&path).unwrap();
        assert_eq!(again.fingerprint(), ca.fingerprint());
        assert!(
            matches!(ca.write_openssh_file(&path), Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists),
            "never overwrites an existing key"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            again.public_key_line().unwrap(),
            ca.public_key_line().unwrap()
        );
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(matches!(
            UserCa::from_openssh_file(Path::new("/nonexistent/user_ca")),
            Err(Error::Io(_))
        ));
        assert!(matches!(
            UserCa::from_openssh(b"not a key"),
            Err(Error::Key(_))
        ));
    }
}
