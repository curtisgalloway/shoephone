// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The content-free push to the approver's phone.
//!
//! When a request arrives the daemon POSTs a fixed message to an ntfy-style
//! topic the operator runs. The payload never carries the host, the scope,
//! or anything else from the request: the phone opens the approve page and
//! fetches the pending request from the daemon. A forged or replayed push
//! at worst opens the page onto an empty list.

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

    /// Fire the push. Failures are reported, never retried: a missed push
    /// costs the person a glance at the page, and the request times out on
    /// its own.
    pub fn request_waiting(&self) -> Result<(), String> {
        let mut req = self
            .agent
            .post(&self.config.url)
            .header("Title", "shoephone")
            .header("Priority", "high")
            .header("Tags", "phone");
        if let Some(t) = &self.config.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        if let Some(c) = &self.config.click {
            req = req.header("Click", c);
        }
        let resp = req
            .send("A request is waiting for your approval.")
            .map_err(|e| format!("push to {}: {e}", self.config.url))?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(format!("push to {}: HTTP {status}", self.config.url))
        }
    }
}
