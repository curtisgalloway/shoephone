// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! shoephone: phone-approved, short-lived SSH certificates for coding agents.
//!
//! The crate is shared by two binaries. `shoephone` is the grant CLI an agent
//! session runs to request escalation; `shoephoned` is the daemon on the
//! failsafe host that holds the SSH user CA, shows the approver the enforced
//! scope, verifies the approver's signature over that scope, and signs a
//! certificate. Everything security-relevant is server-side: the daemon
//! enforces the window, the per-host principal, the rate cap and the nonce,
//! and treats every byte the CLI sends as untrusted.

pub mod exit;
