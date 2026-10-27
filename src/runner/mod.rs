// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The runner: the host that holds Terraform credentials and polls the
//! daemon: its config and state, the review worker, the executor, and the
//! poll loop that ties them together (`run`).

pub mod client;
pub mod config;
pub mod exec;
pub mod journal;
pub mod plan;
pub mod review;
pub mod run;
pub mod schema;
pub mod state;
pub mod tree;

/// The runner's trust-policy version: what a trust approval and the pinned
/// execution context commit to.
pub const POLICY_VERSION: u32 = 1;
