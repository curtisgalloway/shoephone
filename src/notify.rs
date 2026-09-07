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

use std::time::Duration;

use serde::Deserialize;
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
            Push::WindowOpened => "A window was opened.",
            Push::WindowKilled => "A window was killed.",
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
            (Push::WindowOpened, "A window was opened."),
            (Push::WindowKilled, "A window was killed."),
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
}
