// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The content-free push to the approver's phone.
//!
//! When a request arrives, a window opens, or a window is killed, the
//! daemon POSTs a fixed message to an ntfy-style topic the operator runs.
//! The payload never carries the host, the scope, or anything else from the
//! request: the phone opens the approve page and fetches the state from the
//! daemon. A forged or replayed push at worst opens the page onto an empty
//! list.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use ureq::Agent;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    /// The topic URL, e.g. `https://ntfy.example.internal/shoephone`.
    pub url: String,
    /// Bearer token for a protected topic. Optional.
    #[serde(default)]
    pub token: Option<String>,
    /// Where the notification takes the phone; normally `rp_origin`.
    #[serde(default)]
    pub click: Option<String>,
}

/// What the phone is told. Each variant is one fixed sentence; nothing
/// from the request or the grant is ever interpolated into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// A request is pending and the person should open the page.
    RequestWaiting,
    /// A window opened. Every enrolled device hears this, so an approval
    /// tapped on one device is visible on all of them.
    WindowOpened,
    /// A window was killed from the page.
    WindowKilled,
}

impl Push {
    fn body(self) -> &'static str {
        match self {
            Push::RequestWaiting => "A request is waiting for your approval.",
            Push::WindowOpened => "An authorization is now active.",
            Push::WindowKilled => "An authorization was terminated.",
        }
    }

    /// Only the request interrupts; the other two are for the record.
    fn priority(self) -> &'static str {
        match self {
            Push::RequestWaiting => "high",
            Push::WindowOpened | Push::WindowKilled => "default",
        }
    }

    fn tags(self) -> &'static str {
        match self {
            Push::RequestWaiting => "phone",
            Push::WindowOpened => "unlock",
            Push::WindowKilled => "no_entry",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Notifier {
    agent: Agent,
    config: NotifyConfig,
}

impl Notifier {
    pub fn new(config: NotifyConfig) -> Self {
        let agent: Agent = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(5)))
            .build()
            .into();
        Self { agent, config }
    }

    /// Fire one push. Failures are reported, never retried: a missed push
    /// costs the person a glance at the page, and a request times out on
    /// its own.
    pub fn send(&self, push: Push) -> Result<(), String> {
        let mut req = self
            .agent
            .post(&self.config.url)
            .header("Title", "shoephone")
            .header("Priority", push.priority())
            .header("Tags", push.tags());
        if let Some(t) = &self.config.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        if let Some(c) = &self.config.click {
            req = req.header("Click", c);
        }
        let resp = req
            .send(push.body())
            .map_err(|e| format!("push to {}: {e}", self.config.url))?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("push to {}: HTTP {status}", self.config.url))
        }
    }
}

/// APNs, spoken directly: one HTTP/2 POST per device token, authenticated
/// with an ES256 token minted from the developer account's `.p8` key. The
/// payload is content-free, like the topic push; the app fetches what is
/// pending when it opens. Delivery is best effort and the loop never
/// depends on it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApnsConfig {
    /// The `.p8` auth key from the developer portal, root-only on disk.
    pub key_file: PathBuf,
    /// The key's id, shown beside it in the portal.
    pub key_id: String,
    /// The developer team id.
    pub team_id: String,
    /// The app's bundle id.
    pub topic: String,
    /// Use the sandbox gateway. True for a development-signed app, which
    /// is what an app installed from Xcode is; false for App Store and
    /// TestFlight builds.
    #[serde(default)]
    pub sandbox: bool,
}

/// What became of one push to one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    /// Apple says the token is dead; the app registers a fresh one on
    /// its next launch.
    Unregistered,
    Failed(String),
}

pub struct Apns {
    client: reqwest::Client,
    config: ApnsConfig,
    key: EncodingKey,
    /// The bearer token and when it was minted. Apple asks that one be
    /// reused for at least twenty minutes and refuses any older than an
    /// hour, so this is regenerated at fifty.
    bearer: Mutex<Option<(String, SystemTime)>>,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    iat: u64,
}

const BEARER_LIFETIME: Duration = Duration::from_secs(50 * 60);

impl Apns {
    pub fn new(config: ApnsConfig) -> Result<Self, String> {
        let pem = std::fs::read(&config.key_file)
            .map_err(|e| format!("apns key_file {}: {e}", config.key_file.display()))?;
        let key = EncodingKey::from_ec_pem(&pem)
            .map_err(|e| format!("apns key_file {}: {e}", config.key_file.display()))?;
        // reqwest is built without a crypto provider so that it shares
        // ring with ureq instead of dragging in a second one; someone has
        // to say so once per process, and "already installed" is fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("apns client: {e}"))?;
        Ok(Self {
            client,
            config,
            key,
            bearer: Mutex::new(None),
        })
    }

    pub fn gateway(&self) -> &'static str {
        if self.config.sandbox {
            "https://api.sandbox.push.apple.com"
        } else {
            "https://api.push.apple.com"
        }
    }

    pub fn topic(&self) -> &str {
        &self.config.topic
    }

    /// The JWT for the `authorization` header, minted or reused.
    pub fn bearer(&self, now: SystemTime) -> Result<String, String> {
        let mut cached = self.bearer.lock().expect("apns bearer lock");
        if let Some((token, minted)) = &*cached
            && now.duration_since(*minted).unwrap_or(Duration::MAX) < BEARER_LIFETIME
        {
            return Ok(token.clone());
        }
        let iat = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.config.key_id.clone());
        let claims = Claims {
            iss: self.config.team_id.clone(),
            iat,
        };
        let token = jsonwebtoken::encode(&header, &claims, &self.key)
            .map_err(|e| format!("apns jwt: {e}"))?;
        *cached = Some((token.clone(), now));
        Ok(token)
    }

    /// The notification body: a title, one sentence, a sound. Nothing about
    /// the request itself. A waiting request is time-sensitive so it
    /// breaks through a Focus; the other two are ordinary.
    pub fn payload(push: Push) -> serde_json::Value {
        let level = match push {
            Push::RequestWaiting => "time-sensitive",
            Push::WindowOpened | Push::WindowKilled => "active",
        };
        serde_json::json!({
            "aps": {
                "alert": { "title": "shoephone", "body": push.body() },
                "sound": "default",
                "interruption-level": level,
            }
        })
    }

    pub async fn send(&self, push: Push, token: &str) -> Delivery {
        let bearer = match self.bearer(SystemTime::now()) {
            Ok(b) => b,
            Err(e) => return Delivery::Failed(e),
        };
        let url = format!("{}/3/device/{token}", self.gateway());
        let priority = match push {
            Push::RequestWaiting => "10",
            Push::WindowOpened | Push::WindowKilled => "5",
        };
        let sent = self
            .client
            .post(&url)
            .bearer_auth(bearer)
            .header("apns-topic", &self.config.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", priority)
            .header("apns-collapse-id", push.tags())
            .json(&Self::payload(push))
            .send()
            .await;
        match sent {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                match status {
                    200 => Delivery::Sent,
                    410 => Delivery::Unregistered,
                    400 if body.contains("BadDeviceToken") => Delivery::Unregistered,
                    _ => Delivery::Failed(format!("apns HTTP {status}: {body}")),
                }
            }
            Err(e) => Delivery::Failed(format!("apns: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;

    /// Accept one connection, answer 200, and hand back the raw request.
    fn receive_one(listener: TcpListener) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = sock.read(&mut buf).unwrap();
                raw.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&raw);
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let len = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if raw.len() >= head_end + 4 + len {
                        break;
                    }
                }
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            String::from_utf8_lossy(&raw).into_owned()
        })
    }

    #[test]
    fn every_push_is_fixed_text_with_the_headers_and_nothing_else() {
        for (push, body) in [
            (
                Push::RequestWaiting,
                "A request is waiting for your approval.",
            ),
            (Push::WindowOpened, "An authorization is now active."),
            (Push::WindowKilled, "An authorization was terminated."),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let receiver = receive_one(listener);
            let n = Notifier::new(NotifyConfig {
                url: format!("http://127.0.0.1:{port}/shoephone"),
                token: Some("s3cret-token".into()),
                click: Some("https://approve.example.internal".into()),
            });
            n.send(push).unwrap();
            let raw = receiver.join().unwrap();
            assert!(raw.starts_with("POST /shoephone HTTP/1.1\r\n"), "{raw}");
            assert!(raw.ends_with(body), "{raw}");
            let lower = raw.to_ascii_lowercase();
            assert!(lower.contains("\r\ntitle: shoephone\r\n"), "{raw}");
            assert!(
                lower.contains("\r\nauthorization: bearer s3cret-token\r\n"),
                "{raw}"
            );
            assert!(
                lower.contains("\r\nclick: https://approve.example.internal\r\n"),
                "{raw}"
            );
            assert!(
                lower.contains(&format!("\r\npriority: {}\r\n", push.priority())),
                "{raw}"
            );
            // The property that matters: no request detail ever rides along.
            for leak in ["web01", "agent-admin", "scope", "nonce", "serial"] {
                assert!(!lower.contains(leak), "{leak} in push: {raw}");
            }
        }
    }

    #[test]
    fn non_2xx_is_an_error_and_a_closed_port_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            sock.write_all(
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        });
        let n = Notifier::new(NotifyConfig {
            url: format!("http://127.0.0.1:{port}/shoephone"),
            token: None,
            click: None,
        });
        assert!(
            n.send(Push::RequestWaiting)
                .unwrap_err()
                .contains("HTTP 403")
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let n = Notifier::new(NotifyConfig {
            url: format!("http://127.0.0.1:{port}/shoephone"),
            token: None,
            click: None,
        });
        assert!(n.send(Push::WindowOpened).is_err());
    }

    const TEST_P8: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+oKoPfDu7DflZp9l\nfOKPyvzrLjlwKeVXUXXgQCY5nr2hRANCAAS5mnKOiUa2BySN8XGctQKpHZYocfQ/\nWsawjDiBH7HeZz2NDpnF/f3x2j2+VT0soQ250J0rZngMDhnfYg2YrC2H\n-----END PRIVATE KEY-----\n";

    fn apns(dir: &std::path::Path) -> Apns {
        let key_file = dir.join("apns.p8");
        std::fs::write(&key_file, TEST_P8).unwrap();
        Apns::new(ApnsConfig {
            key_file,
            key_id: "ABC123DEFG".into(),
            team_id: "TEAM000000".into(),
            topic: "example.app".into(),
            sandbox: true,
        })
        .unwrap()
    }

    fn b64url_json(part: &str) -> serde_json::Value {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn bearer_is_es256_with_kid_and_iss_and_is_reused_for_fifty_minutes() {
        let dir = std::env::temp_dir().join(format!("shoephone-apns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = apns(&dir);
        let now = SystemTime::now();
        let first = a.bearer(now).unwrap();
        let parts: Vec<&str> = first.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header = b64url_json(parts[0]);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "ABC123DEFG");
        let claims = b64url_json(parts[1]);
        assert_eq!(claims["iss"], "TEAM000000");
        assert!(claims["iat"].as_u64().unwrap() > 1_700_000_000);

        assert_eq!(a.bearer(now + Duration::from_secs(49 * 60)).unwrap(), first);
        assert_ne!(a.bearer(now + Duration::from_secs(51 * 60)).unwrap(), first);
        assert_eq!(a.gateway(), "https://api.sandbox.push.apple.com");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn payload_is_content_free_and_only_a_request_is_time_sensitive() {
        let p = Apns::payload(Push::RequestWaiting);
        assert_eq!(p["aps"]["interruption-level"], "time-sensitive");
        assert_eq!(p["aps"]["alert"]["title"], "shoephone");
        assert!(p.to_string().contains("waiting"));
        assert_eq!(
            Apns::payload(Push::WindowKilled)["aps"]["interruption-level"],
            "active"
        );
        let keys: Vec<&str> = p["aps"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["alert", "interruption-level", "sound"]);
    }
}
