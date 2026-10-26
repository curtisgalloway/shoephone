// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The scopes an approver signs for Terraform trust and apply grants.
//!
//! Same discipline as [`crate::grant::Scope`]: the bytes are versioned and
//! line-oriented, the approver's device signs the SHA-256 of them (see
//! [`challenge_of`]), and the nonce is the last line so a signature over a
//! scope cannot be replayed under another nonce. Every field is newline-free
//! by construction; digests are lowercase hex SHA-256, and `none` stands for
//! an absent digest. The shared vectors in
//! `tests/fixtures/job-scope-vectors.json` pin these formats for the app.

use std::fmt::Write as _;

/// SHA-256 of `bytes`: the WebAuthn challenge for a scope's signed bytes.
pub fn challenge_of(bytes: &[u8]) -> [u8; 32] {
    use ssh_key::sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// What the approver trusts when they approve a Terraform code change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustScope {
    pub project: String,
    /// Digest of the previously trusted candidate, if any.
    pub baseline: Option<String>,
    pub candidate: String,
    pub diff: String,
    pub schema: String,
    pub policy_version: u32,
    pub files_changed: u32,
    pub lines_added: u32,
    pub lines_removed: u32,
    pub schema_changed: bool,
}

impl TrustScope {
    /// The exact bytes the approver's device signs, ending in the nonce.
    pub fn bytes_to_sign(&self, nonce: &str) -> Vec<u8> {
        format!(
            "shoephone-trust-v1\nproject={}\nbaseline={}\ncandidate={}\ndiff={}\n\
             schema={}\npolicy={}\nfiles={}\nadded={}\nremoved={}\n\
             schema_changed={}\nnonce={}\n",
            self.project,
            self.baseline.as_deref().unwrap_or("none"),
            self.candidate,
            self.diff,
            self.schema,
            self.policy_version,
            self.files_changed,
            self.lines_added,
            self.lines_removed,
            u8::from(self.schema_changed),
            nonce,
        )
        .into_bytes()
    }
}

/// Whether the previously applied state is known to match the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineStatus {
    None,
    Applied,
    Uncertain,
}

impl BaselineStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Applied => "applied",
            Self::Uncertain => "uncertain",
        }
    }
}

/// Planned changes by kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub create: u32,
    pub update: u32,
    pub replace: u32,
    pub delete: u32,
}

/// What the approver permits when they approve a Terraform apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyScope {
    pub project: String,
    pub revision: String,
    pub schema: String,
    pub manifest: String,
    pub baseline_manifest: Option<String>,
    pub baseline_status: BaselineStatus,
    pub plan: String,
    pub destructive: bool,
    pub counts: Counts,
    /// Digest of [`address_text`].
    pub addresses: String,
}

impl ApplyScope {
    /// The exact bytes the approver's device signs, ending in the nonce.
    pub fn bytes_to_sign(&self, nonce: &str) -> Vec<u8> {
        format!(
            "shoephone-apply-v1\nproject={}\nrevision={}\nschema={}\nmanifest={}\n\
             baseline_manifest={}\nbaseline_status={}\nplan={}\ndestructive={}\n\
             create={}\nupdate={}\nreplace={}\ndelete={}\naddresses={}\nnonce={}\n",
            self.project,
            self.revision,
            self.schema,
            self.manifest,
            self.baseline_manifest.as_deref().unwrap_or("none"),
            self.baseline_status.as_str(),
            self.plan,
            u8::from(self.destructive),
            self.counts.create,
            self.counts.update,
            self.counts.replace,
            self.counts.delete,
            self.addresses,
            nonce,
        )
        .into_bytes()
    }
}

/// One planned change's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Create,
    Update,
    Replace,
    Delete,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Replace => "replace",
            Self::Delete => "delete",
        }
    }
}

/// One `"{action} {address}\n"` line per change, in the order given.
pub fn address_text(changes: &[(Action, String)]) -> String {
    let mut out = String::new();
    for (action, address) in changes {
        let _ = writeln!(out, "{} {}", action.as_str(), address);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_text_is_one_line_per_change() {
        let text = address_text(&[
            (Action::Create, "a.b".into()),
            (Action::Replace, "c.d[0]".into()),
            (Action::Delete, "e.f".into()),
            (Action::Update, "g.h".into()),
        ]);
        assert_eq!(text, "create a.b\nreplace c.d[0]\ndelete e.f\nupdate g.h\n");
        assert_eq!(address_text(&[]), "");
    }
}
