// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The session key on the agent's machine and its trip into ssh-agent.
//!
//! One ed25519 keypair per user, generated on first use, mode 0600, in a
//! state directory. It is useless without a certificate, and every
//! certificate is bound to it; that is the whole point of sending the
//! public key with the request. The certificate lands next to it as
//! `<key>-cert.pub`, which is where ssh looks, and both go into the
//! session's ssh-agent with a lifetime that ends when the certificate does.

use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

#[derive(Debug, Clone)]
pub struct Session {
    dir: PathBuf,
}

impl Session {
    /// `$SHOEPHONE_STATE_DIR`, else `$XDG_STATE_HOME/shoephone`, else
    /// `~/.local/state/shoephone`.
    pub fn default_dir() -> Result<PathBuf, String> {
        if let Some(d) = std::env::var_os("SHOEPHONE_STATE_DIR") {
            return Ok(PathBuf::from(d));
        }
        if let Some(d) = std::env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(d).join("shoephone"));
        }
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        Ok(PathBuf::from(home).join(".local/state/shoephone"))
    }

    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn key_path(&self) -> PathBuf {
        self.dir.join("session_ed25519")
    }

    pub fn public_key_path(&self) -> PathBuf {
        self.dir.join("session_ed25519.pub")
    }

    pub fn cert_path(&self) -> PathBuf {
        self.dir.join("session_ed25519-cert.pub")
    }

    /// The public key line, generating the keypair if this is the first
    /// use. Never overwrites an existing key.
    pub fn public_key(&self) -> Result<String, String> {
        let key_path = self.key_path();
        if !key_path.exists() {
            std::fs::create_dir_all(&self.dir)
                .map_err(|e| format!("creating {}: {e}", self.dir.display()))?;
            restrict(&self.dir, 0o700)?;
            let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
                .map_err(|e| format!("generating session key: {e}"))?;
            key.set_comment("shoephone session");
            key.write_openssh_file(&key_path, LineEnding::LF)
                .map_err(|e| format!("writing {}: {e}", key_path.display()))?;
            restrict(&key_path, 0o600)?;
            let pub_path = self.public_key_path();
            key.public_key()
                .write_openssh_file(&pub_path)
                .map_err(|e| format!("writing {}: {e}", pub_path.display()))?;
        }
        let pub_path = self.public_key_path();
        let line = std::fs::read_to_string(&pub_path)
            .map_err(|e| format!("reading {}: {e}", pub_path.display()))?;
        Ok(line.trim().to_owned())
    }

    pub fn write_certificate(&self, line: &str) -> Result<(), String> {
        let path = self.cert_path();
        std::fs::write(&path, format!("{}\n", line.trim()))
            .map_err(|e| format!("writing {}: {e}", path.display()))
    }

    pub fn remove_certificate(&self) {
        let _ = std::fs::remove_file(self.cert_path());
    }

    /// Load key and certificate into the session's ssh-agent for
    /// `lifetime_secs`. ssh-add picks up `<key>-cert.pub` on its own. Call
    /// [`Session::remove_from_agent`] before writing a new certificate,
    /// or the agent keeps the previous one as a second identity.
    pub fn add_to_agent(&self, lifetime_secs: u64) -> Result<(), String> {
        let lifetime = lifetime_secs.max(1).to_string();
        let out = Command::new("ssh-add")
            .args(["-q", "-t", &lifetime])
            .arg(self.key_path())
            .output()
            .map_err(|e| format!("running ssh-add: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "ssh-add failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    /// Remove key and certificate from the agent. Missing entries are fine.
    /// `ssh-add -d <key>` removes the key and the `<key>-cert.pub` beside
    /// it in one call (measured with OpenSSH 10.3); the second call catches
    /// a certificate the first one did not see.
    pub fn remove_from_agent(&self) {
        for path in [self.key_path(), self.cert_path()] {
            if path.exists() {
                let _ = Command::new("ssh-add")
                    .args(["-q", "-d"])
                    .arg(path)
                    .output();
            }
        }
    }

    /// Whether an agent is reachable at all. `ssh-add -l` exits 0 with
    /// keys, 1 with none, 2 when it cannot talk to an agent.
    pub fn agent_reachable() -> Result<(), String> {
        if std::env::var_os("SSH_AUTH_SOCK").is_none() {
            return Err("SSH_AUTH_SOCK is not set; no ssh-agent for this session".into());
        }
        let out = Command::new("ssh-add")
            .arg("-l")
            .output()
            .map_err(|e| format!("running ssh-add: {e}"))?;
        match out.status.code() {
            Some(0) | Some(1) => Ok(()),
            _ => Err(format!(
                "ssh-add cannot reach the agent: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )),
        }
    }
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_generates_a_key_and_never_replaces_it() {
        let dir = std::env::temp_dir().join(format!("shoephone-session-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Session::new(dir.clone());
        let first = s.public_key().unwrap();
        assert!(first.starts_with("ssh-ed25519 "));
        assert!(first.ends_with("shoephone session"));
        let again = s.public_key().unwrap();
        assert_eq!(first, again);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(s.key_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        s.write_certificate("ssh-ed25519-cert-v01@openssh.com AAAA")
            .unwrap();
        assert!(s.cert_path().exists());
        s.remove_certificate();
        assert!(!s.cert_path().exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
