// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! `shoephoned` configuration, one TOML file, read once at startup.
//!
//! Everything here is estate-specific and lives on the failsafe host. The
//! principal table is the only place hosts are named; a request for a host
//! that is not in it is refused before anything else happens.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::grant::Policy;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the daemon listens on. Plain HTTP: put a TLS-terminating
    /// reverse proxy in front of it, because WebAuthn only works from a
    /// secure context and `rp_origin` below must match what the phone sees.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Root-only directory for enrolled devices, the enrollment code, and
    /// the ledger.
    pub state_dir: PathBuf,
    /// The user CA private key, unencrypted, root-only. Created by
    /// `shoephoned init-ca`.
    pub ca_key: PathBuf,
    /// WebAuthn relying-party id: the hostname the approve page is served
    /// from, without scheme or port.
    pub rp_id: String,
    /// The full origin the phone loads the page from, e.g.
    /// `https://approve.example.internal`.
    pub rp_origin: String,
    /// Shown on the security key's registration prompt.
    #[serde(default = "default_rp_name")]
    pub rp_name: String,
    /// host -> principal. A certificate for `host` carries exactly this
    /// principal, and the host's `AuthorizedPrincipalsFile` lists only it.
    pub principals: BTreeMap<String, String>,
    #[serde(default)]
    pub policy: PolicyConfig,
}

/// Overrides for [`Policy`], in minutes. Anything omitted keeps the default.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub default_window_minutes: Option<u64>,
    pub max_window_minutes: Option<u64>,
    pub cert_ttl_minutes: Option<u64>,
    pub pending_ttl_minutes: Option<u64>,
    pub max_requests_per_hour: Option<usize>,
    pub base_cooldown_minutes: Option<u64>,
    pub max_cooldown_minutes: Option<u64>,
}

fn default_listen() -> String {
    "127.0.0.1:7391".to_owned()
}

fn default_rp_name() -> String {
    "shoephone".to_owned()
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let config: Config =
            toml::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.principals.is_empty() {
            return Err("principals table is empty; the daemon would sign for no host".into());
        }
        for (host, principal) in &self.principals {
            for (what, value) in [("host", host), ("principal", principal)] {
                if value.is_empty() || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
                    return Err(format!("{what} {value:?} contains whitespace or is empty"));
                }
            }
        }
        if self.rp_id.contains('/') || self.rp_id.contains(':') {
            return Err(format!("rp_id {:?} must be a bare hostname", self.rp_id));
        }
        if !self.rp_origin.starts_with("https://")
            && !self.rp_origin.starts_with("http://localhost")
        {
            return Err(format!(
                "rp_origin {:?} must be https (WebAuthn requires a secure context)",
                self.rp_origin
            ));
        }
        let policy = self.policy();
        if policy.cert_ttl > policy.max_window || policy.default_window > policy.max_window {
            return Err("policy: cert_ttl and default_window must not exceed max_window".into());
        }
        Ok(())
    }

    pub fn policy(&self) -> Policy {
        let d = Policy::default();
        let mins = |m: Option<u64>, fallback: Duration| {
            m.map(|m| Duration::from_secs(m * 60)).unwrap_or(fallback)
        };
        let p = &self.policy;
        Policy {
            default_window: mins(p.default_window_minutes, d.default_window),
            max_window: mins(p.max_window_minutes, d.max_window),
            cert_ttl: mins(p.cert_ttl_minutes, d.cert_ttl),
            pending_ttl: mins(p.pending_ttl_minutes, d.pending_ttl),
            max_requests_per_hour: p.max_requests_per_hour.unwrap_or(d.max_requests_per_hour),
            base_cooldown: mins(p.base_cooldown_minutes, d.base_cooldown),
            max_cooldown: mins(p.max_cooldown_minutes, d.max_cooldown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
state_dir = "/var/lib/shoephone"
ca_key = "/var/lib/shoephone/user_ca"
rp_id = "approve.example.internal"
rp_origin = "https://approve.example.internal"

[principals]
web01 = "agent-admin:web01"
"#;

    #[test]
    fn minimal_config_parses_with_defaults() {
        let c: Config = toml::from_str(MINIMAL).unwrap();
        c.validate().unwrap();
        assert_eq!(c.listen, "127.0.0.1:7391");
        assert_eq!(c.policy(), Policy::default());
    }

    #[test]
    fn overrides_and_validation() {
        let text =
            format!("{MINIMAL}\n[policy]\nmax_window_minutes = 120\ncert_ttl_minutes = 10\n");
        let c: Config = toml::from_str(&text).unwrap();
        c.validate().unwrap();
        assert_eq!(c.policy().max_window, Duration::from_secs(7200));
        assert_eq!(c.policy().cert_ttl, Duration::from_secs(600));

        let bad = MINIMAL.replace("https://", "http://");
        let c: Config = toml::from_str(&bad).unwrap();
        assert!(c.validate().unwrap_err().contains("https"));

        let bad = MINIMAL.replace("agent-admin:web01", "agent admin");
        let c: Config = toml::from_str(&bad).unwrap();
        assert!(c.validate().unwrap_err().contains("whitespace"));

        assert!(toml::from_str::<Config>(&format!("{MINIMAL}\nsurprise = 1\n")).is_err());
    }
}
