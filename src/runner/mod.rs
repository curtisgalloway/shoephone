// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The runner: the host that holds Terraform credentials and polls the
//! daemon. This module is the skeleton: config parsing and the state layout.

pub mod config;
pub mod state;
pub mod tree;
