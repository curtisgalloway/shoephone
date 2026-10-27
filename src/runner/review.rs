// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! Trust review: what the credential-free review worker computes from an
//! uploaded checkout.
//!
//! The operator reads the full diff of the execution input (every file
//! Terraform will read for one project) against the trusted revision. The
//! SHA-256 of the diff text is signed into the trust scope, so the text must
//! be byte for byte reproducible: the review worker builds it from an
//! unpacked archive (modes from the archive headers) and `diff-digest` builds
//! it from the operator's own checkout (modes from permission bits), and both
//! must agree. Nothing here reads secrets or the runner config.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use hcl::edit::expr::{Expression, TraversalOperator};
use hcl::edit::repr::Span;
use hcl::edit::structure::{Attribute, Block, Body};
use hcl::edit::visit::{Visit, visit_expr};
use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};
use ssh_key::sha2::{Digest, Sha256};

use crate::api::TrustScopeWire;
use crate::job::Failure;
use crate::runner::config::ProjectConfig;
use crate::runner::schema::{self, Schema};
use crate::runner::state::write_atomic;
use crate::runner::tree::{self, Tree, shown};
use crate::scope::TrustScope;

/// Header modes (or normalized disk modes), keyed by `/`-separated path.
pub type Modes = BTreeMap<String, u32>;

/// A rendered diff larger than this is not shown; the operator verifies its
/// digest with `diff-digest` instead.
pub const MAX_SHOWN_DIFF: usize = 256 * 1024;

fn fail(category: &str, detail: impl Into<String>) -> Failure {
    Failure {
        category: category.to_string(),
        addresses: Vec::new(),
        detail: Some(detail.into()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A reviewer warning: information for the operator, never a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Warning {
    Provisioner {
        file: String,
        line: u32,
    },
    ExternalData {
        file: String,
        line: u32,
    },
    HttpData {
        file: String,
        line: u32,
    },
    Import {
        file: String,
        line: u32,
    },
    Nonsensitive {
        file: String,
        line: u32,
    },
    ProviderFunction {
        file: String,
        line: u32,
    },
    LocalFileRead {
        file: String,
        line: u32,
    },
    /// An agent-settable (schema) variable reaches `into`, one of
    /// `secret_selector`, `file_path`, `count`, `for_each`, `condition`.
    SchemaVariableSteers {
        file: String,
        line: u32,
        variable: String,
        into: String,
    },
}

/// The result of a trust review.
#[derive(Debug)]
pub struct Review {
    pub scope: TrustScope,
    /// `None` when the diff is external (too large to show).
    pub diff: Option<String>,
    /// The command the operator runs in their own checkout; empty when the
    /// diff is shown.
    pub verify_command: String,
    pub warnings: Vec<Warning>,
}

// ---------------------------------------------------------------------
// The diff

#[derive(Debug)]
struct Rendered {
    text: String,
    files_changed: u32,
    added: u32,
    removed: u32,
}

/// Reads a file of the tree and checks it against the digest recorded when
/// the tree was built.
fn read_checked(tree: &Tree, rel: &str) -> Result<Vec<u8>, Failure> {
    let bytes = read_file(tree, rel)?;
    match tree.files.get(rel) {
        Some(f) if f.sha256 == sha256_hex(&bytes) => Ok(bytes),
        _ => Err(fail(
            "input_changed",
            format!("{} changed while it was reviewed", shown(rel)),
        )),
    }
}

fn read_file(tree: &Tree, rel: &str) -> Result<Vec<u8>, Failure> {
    let abs = rel.split('/').fold(tree.root.clone(), |p, c| p.join(c));
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&abs)
        .map_err(|e| fail("review_read_failed", format!("{}: {e}", shown(rel))))?;
    let mut out = Vec::new();
    f.read_to_end(&mut out)
        .map_err(|e| fail("review_read_failed", format!("{}: {e}", shown(rel))))?;
    Ok(out)
}

fn mode_text(mode: u32) -> String {
    format!("{:06o}", 0o100000 | mode)
}

fn render(base: Option<&Tree>, cand: &Tree) -> Result<Rendered, Failure> {
    let empty = BTreeMap::new();
    let old_files = base.map_or(&empty, |t| &t.files);
    let paths: BTreeSet<&String> = old_files.keys().chain(cand.files.keys()).collect();
    let mut r = Rendered {
        text: String::new(),
        files_changed: 0,
        added: 0,
        removed: 0,
    };
    for path in paths {
        let old = old_files.get(path);
        let new = cand.files.get(path);
        if let (Some(o), Some(n)) = (old, new)
            && o.sha256 == n.sha256
            && o.mode == n.mode
        {
            continue;
        }
        r.files_changed += 1;
        let name = shown(path);
        let _ = writeln!(
            r.text,
            "diff --git {} {}",
            if old.is_some() {
                format!("a/{name}")
            } else {
                "/dev/null".to_string()
            },
            if new.is_some() {
                format!("b/{name}")
            } else {
                "/dev/null".to_string()
            },
        );
        match (old, new) {
            (None, Some(n)) => {
                let _ = writeln!(r.text, "new file mode {}", mode_text(n.mode));
            }
            (Some(o), None) => {
                let _ = writeln!(r.text, "deleted file mode {}", mode_text(o.mode));
            }
            (Some(o), Some(n)) if o.mode != n.mode => {
                let _ = writeln!(r.text, "old mode {}", mode_text(o.mode));
                let _ = writeln!(r.text, "new mode {}", mode_text(n.mode));
            }
            _ => {}
        }
        let side = |present: bool, prefix: &str| {
            if present {
                format!("{prefix}/{name}")
            } else {
                "/dev/null".to_string()
            }
        };
        let (a, b) = (side(old.is_some(), "a"), side(new.is_some(), "b"));
        let _ = writeln!(r.text, "--- {a}");
        let _ = writeln!(r.text, "+++ {b}");
        if old.map(|o| &o.sha256) == new.map(|n| &n.sha256) {
            continue;
        }
        let old_bytes = match (base, old) {
            (Some(t), Some(_)) => read_checked(t, path)?,
            _ => Vec::new(),
        };
        let new_bytes = match new {
            Some(_) => read_checked(cand, path)?,
            None => Vec::new(),
        };
        match (str::from_utf8(&old_bytes), str::from_utf8(&new_bytes)) {
            (Ok(o), Ok(n)) => {
                let diff = TextDiff::from_lines(o, n);
                for change in diff.iter_all_changes() {
                    match change.tag() {
                        ChangeTag::Insert => r.added += 1,
                        ChangeTag::Delete => r.removed += 1,
                        ChangeTag::Equal => {}
                    }
                }
                for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
                    let _ = write!(r.text, "{hunk}");
                }
            }
            _ => {
                let side = |f: Option<&tree::FileEntry>| {
                    f.map_or("none".to_string(), |f| f.sha256.clone())
                };
                let _ = writeln!(
                    r.text,
                    "Binary file {name} changed (sha256 {} -> {})",
                    side(old),
                    side(new)
                );
            }
        }
    }
    Ok(r)
}

// ---------------------------------------------------------------------
// Warnings

fn line_of(text: &str, span: Option<std::ops::Range<usize>>) -> u32 {
    let Some(span) = span else { return 0 };
    let end = span.start.min(text.len());
    let n = text.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count();
    u32::try_from(n + 1).unwrap_or(u32::MAX)
}

/// Collects `var.NAME` references (by `.NAME` or `["NAME"]`) to schema variables.
struct VarRefs<'a> {
    schema: &'a BTreeSet<String>,
    found: BTreeSet<String>,
}

impl Visit for VarRefs<'_> {
    fn visit_expr(&mut self, expr: &Expression) {
        if let Expression::Traversal(t) = expr
            && let Expression::Variable(v) = &t.expr
            && v.as_str() == "var"
        {
            let name = match t.operators.first().map(|o| o.value()) {
                Some(TraversalOperator::GetAttr(id)) => Some(id.as_str().to_string()),
                Some(TraversalOperator::Index(Expression::String(s))) => Some(s.value().clone()),
                _ => None,
            };
            if let Some(n) = name.filter(|n| self.schema.contains(n)) {
                self.found.insert(n);
            }
        }
        visit_expr(self, expr);
    }
}

fn refs_in(schema: &BTreeSet<String>, expr: &Expression) -> BTreeSet<String> {
    let mut v = VarRefs {
        schema,
        found: BTreeSet::new(),
    };
    v.visit_expr(expr);
    v.found
}

const FILE_FUNCTIONS: [&str; 4] = ["file", "filebase64", "templatefile", "filebase64sha256"];

struct Scan<'a> {
    file: &'a str,
    text: &'a str,
    schema: &'a BTreeSet<String>,
    out: Vec<Warning>,
}

impl Scan<'_> {
    fn steers(&mut self, vars: BTreeSet<String>, into: &str, line: u32) {
        for variable in vars {
            self.out.push(Warning::SchemaVariableSteers {
                file: self.file.to_string(),
                line,
                variable,
                into: into.to_string(),
            });
        }
    }

    fn body(&mut self, body: &Body, onepassword: bool) {
        for attr in body.attributes() {
            self.attr(attr, onepassword);
        }
        for block in body.blocks() {
            self.block(block, onepassword);
        }
    }

    fn block(&mut self, block: &Block, parent_onepassword: bool) {
        let line = line_of(self.text, block.span());
        let kind = block.ident.as_str();
        let first = block.labels.first().map(|l| l.as_str());
        let file = self.file.to_string();
        match (kind, first) {
            ("provisioner", _) => self.out.push(Warning::Provisioner { file, line }),
            ("import", _) => self.out.push(Warning::Import { file, line }),
            ("data", Some("external")) => self.out.push(Warning::ExternalData { file, line }),
            ("data", Some("http")) => self.out.push(Warning::HttpData { file, line }),
            ("data", Some("local_file" | "local_sensitive_file")) => {
                self.out.push(Warning::LocalFileRead { file, line })
            }
            _ => {}
        }
        let onepassword =
            parent_onepassword || (kind == "data" && first == Some("onepassword_item"));
        self.body(&block.body, onepassword);
    }

    fn attr(&mut self, attr: &Attribute, onepassword: bool) {
        let line = line_of(self.text, attr.span());
        let vars = refs_in(self.schema, &attr.value);
        match attr.key.as_str() {
            "count" => self.steers(vars.clone(), "count", line),
            "for_each" => self.steers(vars.clone(), "for_each", line),
            "source_file" => {
                self.out.push(Warning::LocalFileRead {
                    file: self.file.to_string(),
                    line,
                });
                self.steers(vars.clone(), "file_path", line);
            }
            _ => {}
        }
        if onepassword {
            self.steers(vars, "secret_selector", line);
        }
        let mut exprs = ExprScan {
            scan: self,
            attr_line: line,
        };
        exprs.visit_expr(&attr.value);
    }
}

/// Walks one attribute's expression for function calls and conditionals.
struct ExprScan<'s, 'a> {
    scan: &'s mut Scan<'a>,
    attr_line: u32,
}

impl Visit for ExprScan<'_, '_> {
    fn visit_expr(&mut self, expr: &Expression) {
        let line = {
            let l = line_of(self.scan.text, expr.span());
            if l == 0 { self.attr_line } else { l }
        };
        let file = self.scan.file.to_string();
        match expr {
            Expression::FuncCall(call) => {
                let name = call.name.name.as_str();
                if call.name.is_namespaced() {
                    self.scan.out.push(Warning::ProviderFunction { file, line });
                } else if name == "nonsensitive" {
                    self.scan.out.push(Warning::Nonsensitive { file, line });
                } else if FILE_FUNCTIONS.contains(&name) {
                    self.scan.out.push(Warning::LocalFileRead { file, line });
                    if let Some(first) = call.args.get(0) {
                        let vars = refs_in(self.scan.schema, first);
                        self.scan.steers(vars, "file_path", line);
                    }
                }
            }
            Expression::Conditional(c) => {
                let mut vars = refs_in(self.scan.schema, &c.cond_expr);
                vars.extend(refs_in(self.scan.schema, &c.true_expr));
                vars.extend(refs_in(self.scan.schema, &c.false_expr));
                self.scan.steers(vars, "condition", line);
            }
            _ => {}
        }
        visit_expr(self, expr);
    }
}

fn scan_warnings(cand: &Tree, schema_names: &BTreeSet<String>) -> Result<Vec<Warning>, Failure> {
    let mut out = Vec::new();
    for path in cand.files.keys().filter(|p| p.ends_with(".tf")) {
        let bytes = read_file(cand, path)?;
        let text = String::from_utf8(bytes)
            .map_err(|_| fail("hcl_parse_failed", format!("{} is not UTF-8", shown(path))))?;
        let body: Body = text
            .parse()
            .map_err(|_| fail("hcl_parse_failed", format!("cannot parse {}", shown(path))))?;
        let shown_path = shown(path);
        let mut scan = Scan {
            file: &shown_path,
            text: &text,
            schema: schema_names,
            out: Vec::new(),
        };
        scan.body(&body, false);
        out.extend(scan.out);
    }
    let mut seen = BTreeSet::new();
    out.retain(|w| seen.insert(serde_json::to_string(w).unwrap_or_default()));
    Ok(out)
}

// ---------------------------------------------------------------------
// Review

/// Where the project's schema file sits in the checkout, and its text.
fn schema_text(tree: &Tree, project_path: &str, schema_file: &str) -> Result<String, Failure> {
    let parts = tree::join_within(&[], project_path)
        .and_then(|p| tree::join_within(&p, schema_file))
        .ok_or_else(|| fail("schema_missing", "the schema path leaves the checkout"))?;
    let rel = parts.join("/");
    if !tree.files.contains_key(&rel) {
        return Err(fail("schema_missing", "the project has no schema file"));
    }
    String::from_utf8(read_file(tree, &rel)?)
        .map_err(|_| fail("schema_invalid", "the schema is not valid for this version"))
}

fn shell_word(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The command the operator runs to reproduce the diff digest. The
/// placeholders stand for the operator's own checkouts.
pub fn verify_command(baseline_digest: Option<&str>, project_path: &str) -> String {
    format!(
        "shoephone-runner diff-digest {} {} <candidate-checkout> {}",
        baseline_digest.unwrap_or("none"),
        if baseline_digest.is_some() {
            "<baseline-checkout>"
        } else {
            "-"
        },
        shell_word(project_path)
    )
}

/// Review `candidate` against `baseline`. Each checkout comes with the modes
/// its files had in the archive (see [`tree::unpack`]).
pub fn review(
    baseline: Option<(&Path, &Modes)>,
    candidate: (&Path, &Modes),
    project: &str,
    cfg: &ProjectConfig,
    policy_version: u32,
) -> Result<Review, Failure> {
    let base_tree = baseline
        .map(|(dir, modes)| tree::execution_input(dir, &cfg.path, modes))
        .transpose()?;
    let cand_tree = tree::execution_input(candidate.0, &cfg.path, candidate.1)?;

    let cand_schema_text = schema_text(&cand_tree, &cfg.path, &cfg.schema_file)?;
    let parsed: Schema = schema::parse_schema(&cand_schema_text)?;
    let runner_vars: BTreeSet<String> = cfg.variables.keys().cloned().collect();
    schema::disjoint(&parsed, &runner_vars)?;
    let schema_names: BTreeSet<String> = parsed.names().map(str::to_string).collect();

    let schema_changed = match &base_tree {
        None => true,
        Some(b) => schema_text(b, &cfg.path, &cfg.schema_file)
            .map(|t| t != cand_schema_text)
            .unwrap_or(true),
    };

    let rendered = render(base_tree.as_ref(), &cand_tree)?;
    let warnings = scan_warnings(&cand_tree, &schema_names)?;
    let baseline_digest = base_tree.as_ref().map(tree::digest);
    let scope = TrustScope {
        project: project.to_string(),
        baseline: baseline_digest.clone(),
        candidate: tree::digest(&cand_tree),
        diff: sha256_hex(rendered.text.as_bytes()),
        schema: sha256_hex(cand_schema_text.as_bytes()),
        policy_version,
        files_changed: rendered.files_changed,
        lines_added: rendered.added,
        lines_removed: rendered.removed,
        schema_changed,
    };
    if !scope.is_well_formed() {
        return Err(fail("review_malformed", "the review scope is malformed"));
    }
    let external = rendered.text.len() > MAX_SHOWN_DIFF;
    Ok(Review {
        scope,
        verify_command: if external {
            verify_command(baseline_digest.as_deref(), &cfg.path)
        } else {
            String::new()
        },
        diff: (!external).then_some(rendered.text),
        warnings,
    })
}

/// The `diff-digest` verb: recompute the candidate digest and the diff
/// digest from checkouts on disk (modes from permission bits). Refuses
/// unless the baseline checkout's digest equals `baseline_digest`.
pub fn diff_digest(
    baseline_digest: Option<&str>,
    baseline: Option<&Path>,
    candidate: &Path,
    project_path: &str,
) -> Result<(String, String), Failure> {
    let base_tree = baseline
        .map(|dir| tree::execution_input_from_disk(dir, project_path))
        .transpose()?;
    let actual = base_tree.as_ref().map(tree::digest);
    if actual.as_deref() != baseline_digest {
        return Err(fail(
            "baseline_mismatch",
            "the baseline checkout does not match the baseline digest",
        ));
    }
    let cand = tree::execution_input_from_disk(candidate, project_path)?;
    let rendered = render(base_tree.as_ref(), &cand)?;
    Ok((tree::digest(&cand), sha256_hex(rendered.text.as_bytes())))
}

// ---------------------------------------------------------------------
// The review worker

/// `job-dir/request.json`. The project config arrives reduced to the
/// variable names the runner supplies; the worker never sees secrets.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub baseline_dir: Option<String>,
    pub candidate_dir: String,
    pub project: String,
    pub policy_version: u32,
    /// Terraform root module path inside the checkout.
    pub project_path: String,
    pub schema_file: String,
    /// Names of the runner-supplied variables.
    pub variables: Vec<String>,
    /// Archive header modes (what `unpack` returned). Absent only when
    /// there is no baseline.
    #[serde(default)]
    pub baseline_modes: Option<Modes>,
    pub candidate_modes: Modes,
}

#[derive(Debug, Serialize)]
struct FailureOut {
    category: String,
    addresses: Vec<String>,
    detail: Option<String>,
}

/// `job-dir/review.json`: either the review or a failure.
#[derive(Debug, Serialize)]
struct ReviewOut {
    scope: Option<TrustScopeWire>,
    diff: Option<String>,
    verify_command: Option<String>,
    warnings: Vec<Warning>,
    failure: Option<FailureOut>,
}

fn run_request(req: &Request) -> Result<Review, Failure> {
    let cfg = ProjectConfig {
        path: req.project_path.clone(),
        terraform_version: String::new(),
        backend_config: BTreeMap::new(),
        env: BTreeMap::new(),
        variables: req
            .variables
            .iter()
            .map(|v| {
                (
                    v.clone(),
                    crate::runner::config::Source::Value(String::new()),
                )
            })
            .collect(),
        schema_file: req.schema_file.clone(),
    };
    let cand_dir = Path::new(&req.candidate_dir);
    let base = req
        .baseline_dir
        .as_deref()
        .map(Path::new)
        .zip(req.baseline_modes.as_ref());
    review(
        base,
        (cand_dir, &req.candidate_modes),
        &req.project,
        &cfg,
        req.policy_version,
    )
}

/// `review-worker <job-dir>`: read `request.json`, write `review.json`.
/// Returns the failure when the review is refused; the failure is also
/// written to `review.json`.
pub fn review_worker(job_dir: &Path) -> Result<(), WorkerError> {
    let text = std::fs::read_to_string(job_dir.join("request.json"))
        .map_err(|e| WorkerError::Request(format!("cannot read request.json: {e}")))?;
    let req: Request = serde_json::from_str(&text)
        .map_err(|e| WorkerError::Request(format!("request.json: {e}")))?;
    if req.baseline_dir.is_some() != req.baseline_modes.is_some() {
        return Err(WorkerError::Request(
            "request.json: baseline_dir and baseline_modes go together".to_string(),
        ));
    }
    let (out, result) = match run_request(&req).and_then(|r| {
        if r.scope.baseline.is_some() && r.scope.files_changed == 0 {
            Err(fail("no_changes", "the candidate equals the baseline"))
        } else {
            Ok(r)
        }
    }) {
        Ok(r) => {
            let s = &r.scope;
            (
                ReviewOut {
                    scope: Some(TrustScopeWire {
                        project: s.project.clone(),
                        baseline: s.baseline.clone(),
                        candidate: s.candidate.clone(),
                        diff: s.diff.clone(),
                        schema: s.schema.clone(),
                        policy_version: s.policy_version,
                        files_changed: s.files_changed,
                        lines_added: s.lines_added,
                        lines_removed: s.lines_removed,
                        schema_changed: s.schema_changed,
                    }),
                    diff: r.diff,
                    verify_command: Some(r.verify_command).filter(|c| !c.is_empty()),
                    warnings: r.warnings,
                    failure: None,
                },
                Ok(()),
            )
        }
        Err(f) => (
            ReviewOut {
                scope: None,
                diff: None,
                verify_command: None,
                warnings: Vec::new(),
                failure: Some(FailureOut {
                    category: f.category.clone(),
                    addresses: f.addresses.clone(),
                    detail: f.detail.clone(),
                }),
            },
            Err(WorkerError::Refused(f)),
        ),
    };
    let bytes = serde_json::to_vec(&out).map_err(|e| WorkerError::Request(e.to_string()))?;
    write_atomic(&job_dir.join("review.json"), &bytes)
        .map_err(|e| WorkerError::Request(format!("cannot write review.json: {e}")))?;
    result
}

/// Why `review-worker` did not produce a review.
#[derive(Debug)]
pub enum WorkerError {
    /// The request could not be read or the result not written.
    Request(String),
    /// The review was refused; `review.json` records why.
    Refused(Failure),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const SCHEMA: &str = "[variables.region]\ntype = \"string\"\npattern = \"[a-z]+\"\n";

    fn cfg(vars: &[&str]) -> ProjectConfig {
        ProjectConfig {
            path: "infra".to_string(),
            terraform_version: "1.9.8".to_string(),
            backend_config: Default::default(),
            env: Default::default(),
            variables: vars
                .iter()
                .map(|v| {
                    (
                        v.to_string(),
                        crate::runner::config::Source::Value(String::new()),
                    )
                })
                .collect(),
            schema_file: "shoephone-schema.toml".to_string(),
        }
    }

    /// A checkout with the given `(path, content, header mode)` files, and
    /// the header modes as `unpack` would return them. On disk the files
    /// carry the mode too, as an operator's checkout does.
    fn checkout(files: &[(&str, &str, u32)]) -> (tempfile::TempDir, Modes) {
        let dir = tempfile::tempdir().unwrap();
        let mut modes = Modes::new();
        for (path, content, mode) in files {
            let abs = dir.path().join(path);
            std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
            std::fs::write(&abs, content).unwrap();
            std::fs::set_permissions(&abs, std::fs::Permissions::from_mode(*mode)).unwrap();
            modes.insert(path.to_string(), *mode);
        }
        (dir, modes)
    }

    fn base_files<'a>(main: &'a str, schema: &'a str) -> Vec<(&'a str, &'a str, u32)> {
        vec![
            ("infra/main.tf", main, 0o644),
            ("infra/shoephone-schema.toml", schema, 0o644),
        ]
    }

    fn run(
        baseline: Option<&(tempfile::TempDir, Modes)>,
        cand: &(tempfile::TempDir, Modes),
    ) -> Result<Review, Failure> {
        review(
            baseline.map(|b| (b.0.path(), &b.1)),
            (cand.0.path(), &cand.1),
            "demo",
            &cfg(&[]),
            1,
        )
    }

    #[test]
    fn first_trust_diffs_against_empty() {
        let c = checkout(&base_files("resource \"a\" \"b\" {}\n", SCHEMA));
        let r = run(None, &c).unwrap();
        let diff = r.diff.clone().unwrap();
        assert!(
            diff.contains("--- /dev/null\n+++ b/infra/main.tf\n"),
            "{diff}"
        );
        assert!(diff.contains("new file mode 100644\n"));
        assert!(diff.contains("+resource \"a\" \"b\" {}\n"));
        assert!(diff.ends_with('\n'));
        assert_eq!(r.scope.baseline, None);
        assert_eq!(r.scope.files_changed, 2);
        assert_eq!(r.scope.lines_added, 4);
        assert_eq!(r.scope.lines_removed, 0);
        assert!(r.scope.schema_changed);
        assert!(r.scope.is_well_formed());
        assert_eq!(r.scope.diff, sha256_hex(diff.as_bytes()));
        assert!(r.verify_command.is_empty());
    }

    #[test]
    fn mode_change_is_shown() {
        let b = checkout(&base_files("x = 1\n", SCHEMA));
        let mut files = base_files("x = 1\n", SCHEMA);
        files[0].2 = 0o755;
        let c = checkout(&files);
        let r = run(Some(&b), &c).unwrap();
        let diff = r.diff.unwrap();
        assert!(
            diff.contains("old mode 100644\nnew mode 100755\n"),
            "{diff}"
        );
        assert_eq!(r.scope.files_changed, 1);
        assert!(!r.scope.schema_changed);
    }

    #[test]
    fn oversized_diff_is_marked_external() {
        let b = checkout(&base_files("x = 1\n", SCHEMA));
        let big = "# padding line\n".repeat(20_000);
        let c = checkout(&base_files(&big, SCHEMA));
        let r = run(Some(&b), &c).unwrap();
        assert!(r.diff.is_none());
        assert!(r.scope.is_well_formed());
        assert_eq!(r.scope.baseline.as_deref().map(str::len), Some(64));
        let want = format!(
            "shoephone-runner diff-digest {} <baseline-checkout> <candidate-checkout> infra",
            r.scope.baseline.as_ref().unwrap()
        );
        assert_eq!(r.verify_command, want);
        let first = run(None, &c).unwrap();
        assert!(
            first
                .verify_command
                .starts_with("shoephone-runner diff-digest none - <candidate-checkout> infra")
        );
    }

    #[test]
    fn diff_digest_matches_verify_command_output() {
        let b = checkout(&[
            ("infra/main.tf", "a = 1\nb = 2\n", 0o644),
            ("infra/shoephone-schema.toml", SCHEMA, 0o644),
            ("infra/run.sh", "echo hi\n", 0o644),
            ("infra/bin.dat", "\u{0}", 0o644),
        ]);
        let c = checkout(&[
            ("infra/main.tf", "a = 1\nb = 3\n", 0o644),
            ("infra/shoephone-schema.toml", SCHEMA, 0o644),
            ("infra/run.sh", "echo hi\n", 0o755),
            ("infra/new.tf", "c = 1", 0o644),
        ]);
        let r = run(Some(&b), &c).unwrap();
        let base_digest = r.scope.baseline.clone().unwrap();
        let (cand, diff) =
            diff_digest(Some(&base_digest), Some(b.0.path()), c.0.path(), "infra").unwrap();
        assert_eq!(cand, r.scope.candidate);
        assert_eq!(diff, r.scope.diff);
        let err = diff_digest(Some(&"0".repeat(64)), Some(b.0.path()), c.0.path(), "infra");
        assert_eq!(err.unwrap_err().category, "baseline_mismatch");
        let err = diff_digest(None, Some(b.0.path()), c.0.path(), "infra");
        assert_eq!(err.unwrap_err().category, "baseline_mismatch");
        let first = run(None, &c).unwrap();
        let (cand, diff) = diff_digest(None, None, c.0.path(), "infra").unwrap();
        assert_eq!((cand, diff), (first.scope.candidate, first.scope.diff));
    }

    #[test]
    fn binary_files_show_digests_not_bytes() {
        let c = checkout(&[
            ("infra/main.tf", "x = 1\n", 0o644),
            ("infra/shoephone-schema.toml", SCHEMA, 0o644),
        ]);
        std::fs::write(c.0.path().join("infra/blob.bin"), [0xff, 0xfe, 0x00]).unwrap();
        let mut modes = c.1.clone();
        modes.insert("infra/blob.bin".to_string(), 0o644);
        let r = review(None, (c.0.path(), &modes), "demo", &cfg(&[]), 1).unwrap();
        let diff = r.diff.unwrap();
        assert!(
            diff.contains("Binary file infra/blob.bin changed"),
            "{diff}"
        );
        assert!(diff.contains(&sha256_hex(&[0xff, 0xfe, 0x00])));
    }

    #[test]
    fn schema_change_sets_flag() {
        let b = checkout(&base_files("x = 1\n", SCHEMA));
        let c = checkout(&base_files(
            "x = 1\n",
            "[variables.region]\ntype = \"string\"\npattern = \"[a-z]{2}\"\n",
        ));
        let r = run(Some(&b), &c).unwrap();
        assert!(r.scope.schema_changed);
        assert_ne!(Some(r.scope.schema.clone()), None);
        let same = run(Some(&b), &b).unwrap();
        assert!(!same.scope.schema_changed);
        assert_eq!(same.scope.files_changed, 0);
        assert_eq!(same.diff.as_deref(), Some(""));
    }

    fn warnings_for(main: &str) -> Vec<Warning> {
        let c = checkout(&base_files(main, SCHEMA));
        run(None, &c).unwrap().warnings
    }

    #[test]
    fn provisioner_is_warned() {
        let w = warnings_for(
            "resource \"a\" \"b\" {\n  provisioner \"local-exec\" {\n    command = \"true\"\n  }\n}\n",
        );
        assert!(
            w.contains(&Warning::Provisioner {
                file: "infra/main.tf".into(),
                line: 2
            }),
            "{w:?}"
        );
    }

    #[test]
    fn other_constructs_are_warned() {
        let w = warnings_for(
            "data \"external\" \"e\" {}\ndata \"http\" \"h\" {}\nimport {\n}\nlocals {\n  a = nonsensitive(x)\n  b = provider::p::f(1)\n  c = file(\"x\")\n}\n",
        );
        for want in [
            Warning::ExternalData {
                file: "infra/main.tf".into(),
                line: 1,
            },
            Warning::HttpData {
                file: "infra/main.tf".into(),
                line: 2,
            },
            Warning::Import {
                file: "infra/main.tf".into(),
                line: 3,
            },
            Warning::Nonsensitive {
                file: "infra/main.tf".into(),
                line: 6,
            },
            Warning::ProviderFunction {
                file: "infra/main.tf".into(),
                line: 7,
            },
            Warning::LocalFileRead {
                file: "infra/main.tf".into(),
                line: 8,
            },
        ] {
            assert!(w.contains(&want), "{want:?} in {w:?}");
        }
    }

    fn steers(variable: &str, into: &str, line: u32) -> Warning {
        Warning::SchemaVariableSteers {
            file: "infra/main.tf".into(),
            line,
            variable: variable.into(),
            into: into.into(),
        }
    }

    #[test]
    fn var_in_count_is_warned() {
        let w = warnings_for(
            "resource \"a\" \"b\" {\n  count = var.region == \"x\" ? 1 : 0\n  for_each = toset([var.region])\n  other = var.unknown\n}\n",
        );
        assert!(w.contains(&steers("region", "count", 2)), "{w:?}");
        assert!(w.contains(&steers("region", "condition", 2)), "{w:?}");
        assert!(w.contains(&steers("region", "for_each", 3)), "{w:?}");
        assert!(!w.iter().any(
            |x| matches!(x, Warning::SchemaVariableSteers { variable, .. } if variable == "unknown")
        ));
    }

    #[test]
    fn var_in_onepassword_lookup_is_warned() {
        let w = warnings_for(
            "data \"onepassword_item\" \"i\" {\n  title = \"${var.region}-item\"\n}\nresource \"f\" \"g\" {\n  source_file = var.region\n  c = templatefile(var.region, {})\n}\n",
        );
        assert!(w.contains(&steers("region", "secret_selector", 2)), "{w:?}");
        assert!(w.contains(&steers("region", "file_path", 5)), "{w:?}");
        assert!(w.contains(&steers("region", "file_path", 6)), "{w:?}");
    }

    #[test]
    fn schema_overlap_refuses_review() {
        let c = checkout(&base_files("x = 1\n", SCHEMA));
        let err = review(None, (c.0.path(), &c.1), "demo", &cfg(&["region"]), 1).unwrap_err();
        assert_eq!(err.category, "schema_overlaps_runner_variables");
        assert_eq!(err.addresses, vec!["region".to_string()]);
    }

    #[test]
    fn content_cannot_forge_a_file_header() {
        let mut bf = base_files("x = 1\n", SCHEMA);
        bf.push(("infra/notes.txt", "-- a/infra/x.tf\nkeep\n", 0o644));
        let mut cf = base_files("x = 1\n", SCHEMA);
        cf.push((
            "infra/notes.txt",
            "++ b/other\ndiff --git a/x b/x\nkeep\n",
            0o644,
        ));
        let (b, c) = (checkout(&bf), checkout(&cf));
        let diff = run(Some(&b), &c).unwrap().diff.unwrap();
        let headers: Vec<&str> = diff
            .lines()
            .filter(|l| l.starts_with("diff --git "))
            .collect();
        assert_eq!(
            headers,
            vec!["diff --git a/infra/notes.txt b/infra/notes.txt"],
            "{diff}"
        );
        let first = run(None, &c).unwrap().diff.unwrap();
        assert!(first.contains("diff --git /dev/null b/infra/notes.txt\n"));
    }

    #[test]
    fn changed_file_is_refused() {
        let c = checkout(&base_files("x = 1\n", SCHEMA));
        let tree = tree::execution_input(c.0.path(), "infra", &c.1).unwrap();
        std::fs::write(c.0.path().join("infra/main.tf"), "x = 2\n").unwrap();
        assert_eq!(render(None, &tree).unwrap_err().category, "input_changed");
    }

    fn tar_gz(entries: &[(&str, &str, u32)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (path, content, mode) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(*mode);
            h.set_cksum();
            b.append_data(&mut h, path, content.as_bytes()).unwrap();
        }
        let raw = b.into_inner().unwrap();
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut e, &raw).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn unpacked_archive_and_disk_checkout_agree() {
        let files = [
            ("infra/main.tf", "x = 1\n", 0o755),
            ("infra/shoephone-schema.toml", SCHEMA, 0o644),
        ];
        let un = tempfile::tempdir().unwrap();
        let modes = tree::unpack(&tar_gz(&files), un.path(), &tree::Limits::default()).unwrap();
        let r = review(None, (un.path(), &modes), "demo", &cfg(&[]), 1).unwrap();
        let disk = checkout(&files);
        let (cand, diff) = diff_digest(None, None, disk.0.path(), "infra").unwrap();
        assert_eq!(cand, r.scope.candidate);
        assert_eq!(diff, r.scope.diff);
        assert!(r.diff.unwrap().contains("new file mode 100755"));
    }

    fn write_request(job: &Path, body: serde_json::Value) {
        std::fs::write(job.join("request.json"), body.to_string()).unwrap();
    }

    #[test]
    fn review_worker_writes_review_json() {
        let c = checkout(&base_files("x = 1\n", SCHEMA));
        let job = tempfile::tempdir().unwrap();
        write_request(
            job.path(),
            serde_json::json!({
                "baseline_dir": null, "candidate_dir": c.0.path(), "project": "demo",
                "policy_version": 1, "project_path": "infra",
                "schema_file": "shoephone-schema.toml", "variables": [],
                "candidate_modes": c.1,
            }),
        );
        review_worker(job.path()).unwrap();
        let out: serde_json::Value =
            serde_json::from_slice(&std::fs::read(job.path().join("review.json")).unwrap())
                .unwrap();
        assert_eq!(out["scope"]["project"], "demo");
        assert_eq!(out["scope"]["files_changed"], 2);
        assert!(out["diff"].as_str().unwrap().contains("diff --git"));
        assert!(out["failure"].is_null());
    }

    #[test]
    fn review_worker_requires_modes_and_refuses_no_changes() {
        let c = checkout(&base_files("x = 1\n", SCHEMA));
        let job = tempfile::tempdir().unwrap();
        let mut req = serde_json::json!({
            "baseline_dir": null, "candidate_dir": c.0.path(), "project": "demo",
            "policy_version": 1, "project_path": "infra",
            "schema_file": "shoephone-schema.toml", "variables": [],
        });
        write_request(job.path(), req.clone());
        assert!(matches!(
            review_worker(job.path()),
            Err(WorkerError::Request(_))
        ));
        assert!(!job.path().join("review.json").exists());

        req["candidate_modes"] = serde_json::json!(c.1);
        req["baseline_dir"] = serde_json::json!(c.0.path());
        write_request(job.path(), req.clone());
        assert!(
            matches!(review_worker(job.path()), Err(WorkerError::Request(_))),
            "baseline needs modes"
        );
        req["baseline_modes"] = serde_json::json!(c.1);
        write_request(job.path(), req);
        match review_worker(job.path()) {
            Err(WorkerError::Refused(f)) => assert_eq!(f.category, "no_changes"),
            other => panic!("{other:?}"),
        }
        let out: serde_json::Value =
            serde_json::from_slice(&std::fs::read(job.path().join("review.json")).unwrap())
                .unwrap();
        assert_eq!(out["failure"]["category"], "no_changes");
    }

    #[test]
    fn root_project_with_git_directory_verifies() {
        let c = checkout(&[
            ("main.tf", "x = 1\n", 0o644),
            ("shoephone-schema.toml", SCHEMA, 0o644),
            (".git/HEAD", "ref\n", 0o644),
        ]);
        let (cand, diff) = diff_digest(None, None, c.0.path(), ".").unwrap();
        let mut modes = c.1.clone();
        modes.retain(|k, _| !k.starts_with(".git"));
        let mut cf = cfg(&[]);
        cf.path = ".".to_string();
        let r = review(None, (c.0.path(), &modes), "demo", &cf, 1).unwrap();
        assert_eq!((cand, diff), (r.scope.candidate, r.scope.diff));
    }

    #[test]
    fn missing_schema_is_refused() {
        let c = checkout(&[("infra/main.tf", "x = 1\n", 0o644)]);
        let err = review(None, (c.0.path(), &c.1), "demo", &cfg(&[]), 1).unwrap_err();
        assert_eq!(err.category, "schema_missing");
    }
}
