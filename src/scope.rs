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

fn clean(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(char::is_control)
}

fn digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn opt_digest(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(digest)
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
    /// True when every field is safe to put on a line of the signed bytes:
    /// the project is non-empty with no control characters, and every digest
    /// is exactly 64 lowercase hex characters. Without this, a field holding
    /// a newline could forge another line and two scopes would sign alike.
    pub fn is_well_formed(&self) -> bool {
        clean(&self.project)
            && opt_digest(&self.baseline)
            && digest(&self.candidate)
            && digest(&self.diff)
            && digest(&self.schema)
    }

    /// The exact bytes the approver's device signs, ending in the nonce.
    pub fn bytes_to_sign(&self, nonce: &str) -> Vec<u8> {
        debug_assert!(self.is_well_formed());
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
    /// True when every field is safe to put on a line of the signed bytes;
    /// see [`TrustScope::is_well_formed`].
    pub fn is_well_formed(&self) -> bool {
        clean(&self.project)
            && digest(&self.revision)
            && digest(&self.schema)
            && digest(&self.manifest)
            && opt_digest(&self.baseline_manifest)
            && digest(&self.plan)
            && digest(&self.addresses)
    }

    /// The exact bytes the approver's device signs, ending in the nonce.
    pub fn bytes_to_sign(&self, nonce: &str) -> Vec<u8> {
        debug_assert!(self.is_well_formed());
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

/// One `"{action} {address}\n"` line per change, in the order given. `None`
/// if any address is empty or contains a control character, since it could
/// then forge a line of the text.
pub fn address_text(changes: &[(Action, String)]) -> Option<String> {
    let mut out = String::new();
    for (action, address) in changes {
        if !clean(address) {
            return None;
        }
        let _ = writeln!(out, "{} {}", action.as_str(), address);
    }
    Some(out)
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
        assert_eq!(
            text.as_deref(),
            Some("create a.b\nreplace c.d[0]\ndelete e.f\nupdate g.h\n")
        );
        assert_eq!(address_text(&[]).as_deref(), Some(""));
    }

    #[test]
    fn address_with_newline_is_refused() {
        assert_eq!(
            address_text(&[(Action::Create, "a.b\nupdate x".into())]),
            None
        );
        assert_eq!(address_text(&[(Action::Create, String::new())]), None);
    }

    fn trust() -> TrustScope {
        TrustScope {
            project: "p".into(),
            baseline: None,
            candidate: "a".repeat(64),
            diff: "b".repeat(64),
            schema: "c".repeat(64),
            policy_version: 1,
            files_changed: 1,
            lines_added: 1,
            lines_removed: 0,
            schema_changed: false,
        }
    }

    #[test]
    fn scope_with_newline_in_project_is_not_well_formed() {
        assert!(trust().is_well_formed());
        let mut t = trust();
        t.project = "x\nbaseline=none".into();
        assert!(!t.is_well_formed());
        t.project = String::new();
        assert!(!t.is_well_formed());
    }

    #[test]
    fn scope_with_short_digest_is_not_well_formed() {
        let mut t = trust();
        t.candidate = "abc".into();
        assert!(!t.is_well_formed());
        let mut t = trust();
        t.baseline = Some("A".repeat(64));
        assert!(!t.is_well_formed());
    }
}
