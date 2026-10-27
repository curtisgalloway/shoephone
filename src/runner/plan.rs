// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! Reads `terraform show -json <planfile>` into the change list the approver
//! signs, and turns `terraform -json` diagnostic streams into failure
//! categories. Diagnostic text can carry credentials, so only resource
//! addresses ever cross into a [`Failure`].

use crate::job::Failure;
use crate::scope::{Action, Counts};

/// The longest resource address the runner accepts.
const MAX_ADDRESS_CHARS: usize = 512;
/// The most addresses a failure carries.
const MAX_FAILURE_ADDRESSES: usize = 50;

/// The single source for the scope's counts, destructive flag and address
/// text. A `Summary` that exists has valid address text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub counts: Counts,
    pub changes: Vec<(Action, String)>,
    pub destructive: bool,
}

impl Summary {
    /// The signed address text for the changes.
    pub fn address_text(&self) -> Option<String> {
        crate::scope::address_text(&self.changes)
    }
}

/// Which Terraform step a diagnostic stream came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Init,
    Plan,
    Apply,
}

fn refuse(category: &str) -> Failure {
    Failure {
        category: category.to_string(),
        addresses: Vec::new(),
        detail: None,
    }
}

/// Maps a Terraform action list. `Ok(None)` is a change to skip; an
/// unrecognized list is an error, never a silent skip.
fn map_actions(value: Option<&serde_json::Value>) -> Result<Option<Action>, Failure> {
    let list: Vec<&str> = value
        .and_then(|v| v.as_array())
        .map(|a| a.iter().map(|x| x.as_str().unwrap_or("")).collect())
        .ok_or_else(|| refuse("plan_unknown_action"))?;
    match list.as_slice() {
        ["create"] => Ok(Some(Action::Create)),
        ["update"] => Ok(Some(Action::Update)),
        ["delete"] => Ok(Some(Action::Delete)),
        ["delete", "create"] | ["create", "delete"] => Ok(Some(Action::Replace)),
        ["no-op"] | ["read"] => Ok(None),
        _ => Err(refuse("plan_unknown_action")),
    }
}

fn rank(action: Action) -> u8 {
    match action {
        Action::Delete => 0,
        Action::Replace => 1,
        Action::Create => 2,
        Action::Update => 3,
    }
}

/// Reads `terraform show -json` output into the change list. Resource
/// changes and non-no-op output changes both count.
pub fn summarize(show_json: &str) -> Result<Summary, Failure> {
    let root: serde_json::Value =
        serde_json::from_str(show_json).map_err(|_| refuse("plan_unreadable"))?;
    let mut changes: Vec<(Action, String)> = Vec::new();
    if let Some(list) = root.get("resource_changes") {
        let list = list.as_array().ok_or_else(|| refuse("plan_unreadable"))?;
        for rc in list {
            let Some(action) = map_actions(rc.get("change").and_then(|c| c.get("actions")))? else {
                continue;
            };
            let address = rc
                .get("address")
                .and_then(|a| a.as_str())
                .ok_or_else(|| refuse("plan_address_refused"))?;
            if address.chars().count() > MAX_ADDRESS_CHARS {
                return Err(refuse("plan_address_refused"));
            }
            changes.push((action, address.to_string()));
        }
    }
    if let Some(outputs) = root.get("output_changes") {
        let outputs = outputs
            .as_object()
            .ok_or_else(|| refuse("plan_unreadable"))?;
        for (name, oc) in outputs {
            let Some(action) = map_actions(oc.get("actions"))? else {
                continue;
            };
            let address = format!("output.{name}");
            if address.chars().count() > MAX_ADDRESS_CHARS {
                return Err(refuse("plan_address_refused"));
            }
            changes.push((action, address));
        }
    }
    changes.sort_by(|a, b| (rank(a.0), &a.1).cmp(&(rank(b.0), &b.1)));
    if crate::scope::address_text(&changes).is_none() {
        return Err(refuse("plan_address_refused"));
    }
    let mut counts = Counts {
        create: 0,
        update: 0,
        replace: 0,
        delete: 0,
    };
    for (action, _) in &changes {
        match action {
            Action::Create => counts.create += 1,
            Action::Update => counts.update += 1,
            Action::Replace => counts.replace += 1,
            Action::Delete => counts.delete += 1,
        }
    }
    let destructive = counts.delete > 0 || counts.replace > 0;
    Ok(Summary {
        counts,
        changes,
        destructive,
    })
}

/// Turns a `terraform -json` diagnostic stream into a failure. Keeps only
/// each diagnostic's `address`; no summary, detail or file name is copied.
pub fn categorize(diagnostics_jsonl: &str, phase: Phase) -> Failure {
    let mut addresses = std::collections::BTreeSet::new();
    for line in diagnostics_jsonl.lines() {
        let Ok(serde_json::Value::Object(obj)) = serde_json::from_str(line) else {
            continue;
        };
        let address = obj
            .get("diagnostic")
            .and_then(|d| d.get("address"))
            .and_then(|a| a.as_str());
        if let Some(a) = address
            && !a.is_empty()
            && a.chars().count() <= MAX_ADDRESS_CHARS
        {
            addresses.insert(a.to_string());
        }
    }
    let category = match phase {
        Phase::Init => "init_failed",
        Phase::Plan => "plan_failed",
        Phase::Apply => "apply_failed",
    };
    Failure {
        category: category.to_string(),
        addresses: addresses.into_iter().take(MAX_FAILURE_ADDRESSES).collect(),
        detail: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPLACE: &str = include_str!("../../tests/fixtures/plan/replace.json");
    const MIXED: &str = include_str!("../../tests/fixtures/plan/mixed.json");
    const CREATE_ONLY: &str = include_str!("../../tests/fixtures/plan/create_only.json");
    const UNKNOWN: &str = include_str!("../../tests/fixtures/plan/unknown_action.json");
    const DIAGS: &str = include_str!("../../tests/fixtures/plan/diagnostics.jsonl");

    #[test]
    fn replace_in_either_order_counts_as_replace() {
        let s = summarize(REPLACE).unwrap();
        assert_eq!(s.counts.replace, 2);
        assert_eq!(s.counts.create + s.counts.delete + s.counts.update, 0);
        assert!(s.changes.iter().all(|(a, _)| *a == Action::Replace));
    }

    #[test]
    fn no_op_and_read_are_skipped() {
        let s = summarize(MIXED).unwrap();
        assert!(s.changes.iter().all(|(_, a)| a != "null_resource.n"));
        assert!(s.changes.iter().all(|(_, a)| !a.starts_with("data.")));
        assert!(s.changes.iter().all(|(_, a)| a != "output.o2"));
    }

    #[test]
    fn changes_are_ordered_and_outputs_included() {
        let s = summarize(MIXED).unwrap();
        let want: Vec<(Action, String)> = vec![
            (Action::Delete, "null_resource.d".into()),
            (Action::Replace, "null_resource.a".into()),
            (Action::Create, "null_resource.c".into()),
            (Action::Update, "null_resource.u".into()),
            (Action::Update, "output.o1".into()),
        ];
        assert_eq!(s.changes, want);
        assert_eq!(s.counts.update, 2);
        assert_eq!(
            s.address_text().unwrap(),
            "delete null_resource.d\nreplace null_resource.a\ncreate null_resource.c\nupdate null_resource.u\nupdate output.o1\n"
        );
    }

    #[test]
    fn destructive_set_by_delete_or_replace() {
        assert!(summarize(MIXED).unwrap().destructive);
        assert!(summarize(REPLACE).unwrap().destructive);
        assert!(!summarize(CREATE_ONLY).unwrap().destructive);
        let del = r#"{"resource_changes":[{"address":"a.b","change":{"actions":["delete"]}}]}"#;
        assert!(summarize(del).unwrap().destructive);
    }

    #[test]
    fn unknown_action_refuses() {
        let f = summarize(UNKNOWN).unwrap_err();
        assert_eq!(f.category, "plan_unknown_action");
        let f =
            summarize(r#"{"resource_changes":[{"address":"a.b","change":{"actions":["frob"]}}]}"#)
                .unwrap_err();
        assert_eq!(f.category, "plan_unknown_action");
    }

    #[test]
    fn forbidden_or_long_address_refuses() {
        for addr in ["a.b\\nc", "a\\u202eb", "", &"x".repeat(513)] {
            let json = format!(
                r#"{{"resource_changes":[{{"address":"{addr}","change":{{"actions":["create"]}}}}]}}"#
            );
            let f = summarize(&json).unwrap_err();
            assert_eq!(f.category, "plan_address_refused", "{addr:?}");
        }
        let ok = "x".repeat(512);
        let json = format!(
            r#"{{"resource_changes":[{{"address":"{ok}","change":{{"actions":["create"]}}}}]}}"#
        );
        assert!(summarize(&json).unwrap().address_text().is_some());
    }

    #[test]
    fn malformed_json_refuses() {
        assert_eq!(summarize("nope").unwrap_err().category, "plan_unreadable");
        assert_eq!(summarize("{}").unwrap().changes.len(), 0);
    }

    #[test]
    fn categorize_keeps_address_drops_text() {
        let f = categorize(DIAGS, Phase::Plan);
        assert_eq!(f.category, "plan_failed");
        assert_eq!(
            f.addresses,
            vec![
                "module.net.aws_x.b[\"k\"]".to_string(),
                "null_resource.a".to_string()
            ]
        );
        assert_eq!(f.detail, None);
        let dbg = format!("{f:?}");
        assert!(!dbg.contains("LEAKME"));
        assert!(!dbg.contains("main.tf"));
    }

    #[test]
    fn categorize_phases_and_cap() {
        assert_eq!(categorize("", Phase::Init).category, "init_failed");
        assert_eq!(categorize("", Phase::Apply).category, "apply_failed");
        assert!(categorize("", Phase::Apply).addresses.is_empty());
        let many: String = (0..80)
            .map(|i| format!("{{\"diagnostic\":{{\"address\":\"r.a{i:02}\"}}}}\n"))
            .collect();
        assert_eq!(categorize(&many, Phase::Apply).addresses.len(), 50);
    }
}
