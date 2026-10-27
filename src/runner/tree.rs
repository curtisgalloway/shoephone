// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The agent's archive, unpacked under bounds, and the execution input
//! read out of it.
//!
//! The archive is hostile: it comes from an agent and is the first thing the
//! runner parses. [`unpack`] never trusts a tar header for a size; it counts
//! the bytes it actually writes. The execution input is every file Terraform
//! will read for one project, and [`digest`] is its identity.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use ssh_key::sha2::{Digest, Sha256};

use crate::job::Failure;

/// The bounds on an uploaded archive.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Largest compressed archive, in bytes.
    pub compressed_bytes: u64,
    /// Most bytes written to disk.
    pub unpacked_bytes: u64,
    /// Most entries (files and directories).
    pub files: usize,
    /// Longest the unpack may take.
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            compressed_bytes: 16 * 1024 * 1024,
            unpacked_bytes: 64 * 1024 * 1024,
            files: 10_000,
            timeout: Duration::from_secs(60),
        }
    }
}

/// One file of the execution input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub mode: u32,
    pub sha256: String,
    pub size: u64,
}

/// The execution input: every file Terraform will read for one project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub root: PathBuf,
    /// Keyed by `/`-separated path relative to the checkout.
    pub files: BTreeMap<String, FileEntry>,
}

fn fail(category: &str, detail: impl Into<String>) -> Failure {
    Failure {
        category: category.to_string(),
        addresses: Vec::new(),
        detail: Some(detail.into()),
    }
}

/// A path made safe to show: control characters become `?`.
fn shown(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[derive(Clone, Copy)]
enum Stop {
    TooLarge,
    Timeout,
}

/// Counts every decompressed byte and enforces the deadline on each read, so
/// a bomb that never writes a file (padding, skipped entries) still stops.
struct Guarded<R> {
    inner: R,
    seen: u64,
    cap: u64,
    deadline: Instant,
    stop: Rc<Cell<Option<Stop>>>,
}

impl<R: Read> Read for Guarded<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() > self.deadline {
            self.stop.set(Some(Stop::Timeout));
            return Err(io::Error::other("deadline"));
        }
        let n = self.inner.read(buf)?;
        self.seen += n as u64;
        if self.seen > self.cap {
            self.stop.set(Some(Stop::TooLarge));
            return Err(io::Error::other("too large"));
        }
        Ok(n)
    }
}

enum Refusal {
    Entry(String),
    Stop(Stop),
    Other(Failure),
}

impl Refusal {
    fn into_failure(self, limits: &Limits) -> Failure {
        match self {
            Refusal::Entry(d) => fail("archive_entry_refused", d),
            Refusal::Stop(Stop::TooLarge) => fail("archive_too_large", "unpacked bound exceeded"),
            Refusal::Stop(Stop::Timeout) => fail(
                "archive_timeout",
                format!("unpack took longer than {} s", limits.timeout.as_secs()),
            ),
            Refusal::Other(f) => f,
        }
    }
}

/// Validates an entry path and returns its normal components.
fn clean_path(raw: &[u8]) -> Result<Vec<String>, String> {
    if raw.iter().any(|&b| b < 0x20 || b == 0x7f) {
        return Err("path contains a control character".into());
    }
    let s = std::str::from_utf8(raw).map_err(|_| "path is not UTF-8".to_string())?;
    let mut parts = Vec::new();
    for c in Path::new(s).components() {
        match c {
            Component::Normal(p) => parts.push(p.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => {
                return Err(format!(
                    "path {} is absolute or leaves the archive",
                    shown(s)
                ));
            }
        }
    }
    Ok(parts)
}

/// Unpacks a gzip tar into `into`, which must exist and be empty.
///
/// Refuses anything but regular files and directories. Directories are made
/// 0700 and files 0600, or 0700 when the archive set an execute bit.
pub fn unpack(archive: &[u8], into: &Path, limits: &Limits) -> Result<(), Failure> {
    if archive.len() as u64 > limits.compressed_bytes {
        return Err(fail("archive_too_large", "compressed bound exceeded"));
    }
    let start = Instant::now();
    let stop = Rc::new(Cell::new(None));
    let slack = (limits.files as u64).saturating_mul(1024) + 1024 * 1024;
    let guarded = Guarded {
        inner: flate2::read::GzDecoder::new(archive),
        seen: 0,
        cap: limits.unpacked_bytes.saturating_add(slack),
        deadline: start + limits.timeout,
        stop: Rc::clone(&stop),
    };
    run_unpack(guarded, into, limits, start, &stop).map_err(|r| r.into_failure(limits))
}

fn run_unpack<R: Read>(
    reader: R,
    into: &Path,
    limits: &Limits,
    start: Instant,
    stop: &Rc<Cell<Option<Stop>>>,
) -> Result<(), Refusal> {
    let malformed = |e: io::Error| match stop.get() {
        Some(s) => Refusal::Stop(s),
        None => Refusal::Other(fail(
            "archive_malformed",
            format!("unreadable archive: {e}"),
        )),
    };
    let mut tar = tar::Archive::new(reader);
    let mut count = 0usize;
    let mut written = 0u64;
    let mut seen_files: BTreeSet<Vec<String>> = BTreeSet::new();
    for entry in tar.entries().map_err(malformed)? {
        if start.elapsed() > limits.timeout {
            return Err(Refusal::Stop(Stop::Timeout));
        }
        let mut entry = entry.map_err(malformed)?;
        let kind = entry.header().entry_type();
        if kind.is_pax_global_extensions() {
            continue;
        }
        count += 1;
        if count > limits.files {
            return Err(Refusal::Stop(Stop::TooLarge));
        }
        let raw = entry.path_bytes().into_owned();
        let parts = clean_path(&raw).map_err(Refusal::Entry)?;
        if !(kind.is_file() || kind.is_dir()) {
            return Err(Refusal::Entry(format!(
                "entry {} is not a regular file or directory",
                shown(&String::from_utf8_lossy(&raw))
            )));
        }
        if parts.is_empty() {
            continue;
        }
        let dest = parts.iter().fold(into.to_path_buf(), |p, c| p.join(c));
        let shown_path = shown(&parts.join("/"));
        if kind.is_dir() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dest)
                .map_err(|e| Refusal::Entry(format!("cannot create {shown_path}: {e}")))?;
            continue;
        }
        if !seen_files.insert(parts.clone()) {
            return Err(Refusal::Entry(format!("duplicate entry {shown_path}")));
        }
        let executable = entry
            .header()
            .mode()
            .map(|m| m & 0o111 != 0)
            .unwrap_or(false);
        if let Some(parent) = dest.parent() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| Refusal::Entry(format!("cannot create {shown_path}: {e}")))?;
        }
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if executable { 0o700 } else { 0o600 })
            .custom_flags(libc::O_NOFOLLOW)
            .open(&dest)
            .map_err(|e| Refusal::Entry(format!("cannot create {shown_path}: {e}")))?;
        let mut chunk = [0u8; 64 * 1024];
        loop {
            if start.elapsed() > limits.timeout {
                return Err(Refusal::Stop(Stop::Timeout));
            }
            let n = entry.read(&mut chunk).map_err(malformed)?;
            if n == 0 {
                break;
            }
            written += n as u64;
            if written > limits.unpacked_bytes {
                return Err(Refusal::Stop(Stop::TooLarge));
            }
            out.write_all(&chunk[..n])
                .map_err(|e| Refusal::Other(fail("archive_write_failed", e.to_string())))?;
        }
    }
    Ok(())
}

/// Names Terraform would read as state, plans or implicit variable values.
fn refused_input(name: &str) -> Option<&'static str> {
    if name.ends_with(".tf.json") {
        return Some("tf_json_refused");
    }
    let state = name.contains(".tfstate");
    let plan = name.ends_with(".tfplan");
    let vars = matches!(name, "terraform.tfvars" | "terraform.tfvars.json")
        || name.ends_with(".auto.tfvars")
        || name.ends_with(".auto.tfvars.json");
    (state || plan || vars).then_some("input_file_refused")
}

/// Lexically joins `rel` onto `base` (both relative to the checkout) and
/// returns None when the result leaves the checkout.
fn join_within(base: &[String], rel: &str) -> Option<Vec<String>> {
    let mut out = base.to_vec();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(p) => out.push(p.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop()?;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The local module directories a directory's `.tf` files reference.
fn module_dirs(checkout: &Path, dir: &[String]) -> Result<Vec<Vec<String>>, Failure> {
    let abs = dir.iter().fold(checkout.to_path_buf(), |p, c| p.join(c));
    let mut found = Vec::new();
    let mut names: Vec<String> = fs::read_dir(&abs)
        .map_err(|e| fail("module_missing", format!("{}: {e}", shown(&dir.join("/")))))?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".tf"))
        .collect();
    names.sort();
    for name in names {
        let shown_file = shown(
            &dir.iter()
                .chain([&name])
                .cloned()
                .collect::<Vec<_>>()
                .join("/"),
        );
        let text = fs::read_to_string(abs.join(&name))
            .map_err(|_| fail("hcl_parse_failed", format!("cannot read {shown_file}")))?;
        let body = hcl::parse(&text)
            .map_err(|_| fail("hcl_parse_failed", format!("cannot parse {shown_file}")))?;
        for block in body.blocks().filter(|b| b.identifier() == "module") {
            let source = block
                .body()
                .attributes()
                .find(|a| a.key() == "source")
                .map(|a| a.expr());
            let literal = match source {
                Some(hcl::Expression::String(s)) => Some(s.as_str()),
                _ => None,
            };
            let Some(src) = literal.filter(|s| s.starts_with("./") || s.starts_with("../")) else {
                return Err(fail(
                    "module_not_local",
                    format!("a module in {shown_file} has a non-local source"),
                ));
            };
            let target = join_within(dir, src).ok_or_else(|| {
                fail(
                    "module_outside_checkout",
                    format!("a module in {shown_file} leaves the checkout"),
                )
            })?;
            found.push(target);
        }
    }
    Ok(found)
}

fn walk(
    checkout: &Path,
    dir: &[String],
    files: &mut BTreeMap<String, FileEntry>,
) -> Result<(), Failure> {
    let abs = dir.iter().fold(checkout.to_path_buf(), |p, c| p.join(c));
    let mut entries: Vec<_> = fs::read_dir(&abs)
        .map_err(|e| fail("module_missing", format!("{}: {e}", shown(&dir.join("/")))))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let Ok(name) = e.file_name().into_string() else {
            return Err(fail("input_file_refused", "a file name is not UTF-8"));
        };
        let mut path = dir.to_vec();
        path.push(name.clone());
        let rel = path.join("/");
        let meta = fs::symlink_metadata(e.path())
            .map_err(|err| fail("input_file_refused", format!("{}: {err}", shown(&rel))))?;
        if meta.is_dir() {
            if name == ".terraform" {
                return Err(fail(
                    "input_file_refused",
                    format!("{} is refused", shown(&rel)),
                ));
            }
            walk(checkout, &path, files)?;
            continue;
        }
        if !meta.is_file() {
            return Err(fail(
                "input_file_refused",
                format!("{} is not a regular file", shown(&rel)),
            ));
        }
        if let Some(category) = refused_input(&name) {
            return Err(fail(category, format!("{} is refused", shown(&rel))));
        }
        if files.contains_key(&rel) {
            continue;
        }
        let mut hasher = Sha256::new();
        let mut f = fs::File::open(e.path())
            .map_err(|err| fail("input_file_refused", format!("{}: {err}", shown(&rel))))?;
        io::copy(&mut f, &mut hasher)
            .map_err(|err| fail("input_file_refused", format!("{}: {err}", shown(&rel))))?;
        files.insert(
            rel,
            FileEntry {
                mode: meta.mode() & 0o777,
                sha256: hasher
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                size: meta.len(),
            },
        );
    }
    Ok(())
}

/// Collects every file Terraform will read for `project_path`: the project
/// directory plus every local module directory it reaches, transitively.
pub fn execution_input(checkout: &Path, project_path: &str) -> Result<Tree, Failure> {
    let project = join_within(&[], project_path).ok_or_else(|| {
        fail(
            "module_outside_checkout",
            "the project path leaves the checkout",
        )
    })?;
    let mut files = BTreeMap::new();
    let mut visited: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut queue = vec![project];
    while let Some(dir) = queue.pop() {
        if !visited.insert(dir.clone()) {
            continue;
        }
        queue.extend(module_dirs(checkout, &dir)?);
        walk(checkout, &dir, &mut files)?;
    }
    Ok(Tree {
        root: checkout.to_path_buf(),
        files,
    })
}

/// SHA-256 over the sorted `"{path}\0{mode:o}\0{sha256}\n"` lines.
pub fn digest(tree: &Tree) -> String {
    let mut hasher = Sha256::new();
    for (path, f) in &tree.files {
        hasher.update(format!("{path}\0{:o}\0{}\n", f.mode, f.sha256).as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    /// A tar entry written by hand, so a hostile name or type can be built.
    fn raw_entry(out: &mut Vec<u8>, name: &str, kind: u8, mode: u32, data: &[u8]) {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        h[136..147].copy_from_slice(b"00000000000");
        h[148..156].copy_from_slice(b"        ");
        h[156] = kind;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend_from_slice(data);
        out.extend(std::iter::repeat_n(0u8, (512 - data.len() % 512) % 512));
    }

    fn gz(mut tar: Vec<u8>) -> Vec<u8> {
        tar.extend_from_slice(&[0u8; 1024]);
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&tar).unwrap();
        e.finish().unwrap()
    }

    fn archive(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut t = Vec::new();
        for (n, c) in entries {
            raw_entry(&mut t, n, b'0', 0o644, c.as_bytes());
        }
        gz(t)
    }

    fn unpacked(entries: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        unpack(&archive(entries), dir.path(), &Limits::default()).unwrap();
        dir
    }

    #[test]
    fn symlink_entry_is_refused() {
        let mut t = Vec::new();
        raw_entry(&mut t, "link", b'2', 0o777, b"");
        let dir = tempfile::tempdir().unwrap();
        let err = unpack(&gz(t), dir.path(), &Limits::default()).unwrap_err();
        assert_eq!(err.category, "archive_entry_refused");
        assert!(!dir.path().join("link").exists());
    }

    #[test]
    fn dotdot_entry_is_refused() {
        let mut t = Vec::new();
        raw_entry(&mut t, "a/../../evil", b'0', 0o644, b"x");
        let dir = tempfile::tempdir().unwrap();
        let err = unpack(&gz(t), dir.path(), &Limits::default()).unwrap_err();
        assert_eq!(err.category, "archive_entry_refused");
        let mut t = Vec::new();
        raw_entry(&mut t, "/etc/evil", b'0', 0o644, b"x");
        let err = unpack(&gz(t), dir.path(), &Limits::default()).unwrap_err();
        assert_eq!(err.category, "archive_entry_refused");
    }

    #[test]
    fn duplicate_and_control_character_paths_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let err = unpack(
            &archive(&[("a.tf", "1"), ("a.tf", "2")]),
            dir.path(),
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(err.category, "archive_entry_refused");
        let dir = tempfile::tempdir().unwrap();
        let err = unpack(
            &archive(&[("a\u{1}.tf", "1")]),
            dir.path(),
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(err.category, "archive_entry_refused");
    }

    #[test]
    fn too_many_files_is_refused() {
        let entries: Vec<(String, &str)> = (0..5).map(|i| (format!("f{i}"), "x")).collect();
        let refs: Vec<(&str, &str)> = entries.iter().map(|(n, c)| (n.as_str(), *c)).collect();
        let limits = Limits {
            files: 3,
            ..Limits::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let err = unpack(&archive(&refs), dir.path(), &limits).unwrap_err();
        assert_eq!(err.category, "archive_too_large");
    }

    #[test]
    fn unpacked_size_bound_holds_for_small_gzip_bomb() {
        let zeros = vec![b'a'; 4 * 1024 * 1024];
        let mut t = Vec::new();
        raw_entry(&mut t, "big", b'0', 0o644, &zeros);
        let bomb = gz(t);
        assert!(bomb.len() < 64 * 1024, "the bomb should compress small");
        let limits = Limits {
            unpacked_bytes: 1024 * 1024,
            ..Limits::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let err = unpack(&bomb, dir.path(), &limits).unwrap_err();
        assert_eq!(err.category, "archive_too_large");
        let on_disk = fs::metadata(dir.path().join("big"))
            .map(|m| m.len())
            .unwrap_or(0);
        assert!(on_disk <= 1024 * 1024);
    }

    #[test]
    fn compressed_bound_and_timeout_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let limits = Limits {
            compressed_bytes: 10,
            ..Limits::default()
        };
        let err = unpack(&archive(&[("a", "x")]), dir.path(), &limits).unwrap_err();
        assert_eq!(err.category, "archive_too_large");
        let limits = Limits {
            timeout: Duration::ZERO,
            ..Limits::default()
        };
        std::thread::sleep(Duration::from_millis(5));
        let err = unpack(&archive(&[("a", "x")]), dir.path(), &limits).unwrap_err();
        assert_eq!(err.category, "archive_timeout");
    }

    #[test]
    fn modes_are_normalized_on_disk() {
        let mut t = Vec::new();
        raw_entry(&mut t, "d/run.sh", b'0', 0o755, b"x");
        raw_entry(&mut t, "d/plain", b'0', 0o666, b"x");
        let dir = tempfile::tempdir().unwrap();
        unpack(&gz(t), dir.path(), &Limits::default()).unwrap();
        let mode = |p: &str| fs::metadata(dir.path().join(p)).unwrap().mode() & 0o777;
        assert_eq!(mode("d"), 0o700);
        assert_eq!(mode("d/run.sh"), 0o700);
        assert_eq!(mode("d/plain"), 0o600);
    }

    const LOCAL: &str = "module \"m\" {\n  source = \"./sub\"\n}\n";

    #[test]
    fn non_local_module_is_refused() {
        for src in [
            "hashicorp/consul/aws",
            "git::https://example.com/x.git",
            "${var.x}/sub",
        ] {
            let tf = format!("module \"m\" {{\n  source = \"{src}\"\n}}\n");
            let dir = unpacked(&[("p/main.tf", &tf)]);
            let err = execution_input(dir.path(), "p").unwrap_err();
            assert_eq!(err.category, "module_not_local", "{src}");
        }
        let dir = unpacked(&[("p/main.tf", "module \"m\" {\n  source = var.s\n}\n")]);
        let err = execution_input(dir.path(), "p").unwrap_err();
        assert_eq!(err.category, "module_not_local");
    }

    #[test]
    fn module_leaving_the_checkout_is_refused() {
        let tf = "module \"m\" {\n  source = \"../../x\"\n}\n";
        let dir = unpacked(&[("p/main.tf", tf)]);
        let err = execution_input(dir.path(), "p").unwrap_err();
        assert_eq!(err.category, "module_outside_checkout");
    }

    #[test]
    fn local_module_outside_project_dir_is_included() {
        let tf = "module \"net\" {\n  source = \"../../modules/net\"\n}\n";
        let dir = unpacked(&[
            ("env/prod/main.tf", tf),
            (
                "modules/net/main.tf",
                LOCAL.replace("./sub", "../leaf").as_str(),
            ),
            ("modules/leaf/main.tf", "# leaf\n"),
            ("modules/unused/main.tf", "# unused\n"),
        ]);
        let tree = execution_input(dir.path(), "env/prod").unwrap();
        let keys: Vec<&str> = tree.files.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "env/prod/main.tf",
                "modules/leaf/main.tf",
                "modules/net/main.tf"
            ]
        );
    }

    #[test]
    fn auto_tfvars_json_is_refused() {
        for name in [
            "x.auto.tfvars.json",
            "x.auto.tfvars",
            "terraform.tfvars",
            "terraform.tfvars.json",
            "terraform.tfstate",
            "terraform.tfstate.backup",
            "out.tfplan",
        ] {
            let dir = unpacked(&[("p/main.tf", "# x\n"), (&format!("p/{name}"), "{}")]);
            let err = execution_input(dir.path(), "p").unwrap_err();
            assert_eq!(err.category, "input_file_refused", "{name}");
        }
        let dir = unpacked(&[("p/main.tf", "# x\n"), ("p/.terraform/x", "x")]);
        let err = execution_input(dir.path(), "p").unwrap_err();
        assert_eq!(err.category, "input_file_refused");
        let dir = unpacked(&[("p/main.tf", "# x\n"), ("p/a.tf.json", "{}")]);
        let err = execution_input(dir.path(), "p").unwrap_err();
        assert_eq!(err.category, "tf_json_refused");
    }

    #[test]
    fn digest_changes_with_mode_and_content() {
        let a = unpacked(&[("p/main.tf", "# one\n")]);
        let base = digest(&execution_input(a.path(), "p").unwrap());
        let b = unpacked(&[("p/main.tf", "# two\n")]);
        assert_ne!(base, digest(&execution_input(b.path(), "p").unwrap()));
        let mut t = Vec::new();
        raw_entry(&mut t, "p/main.tf", b'0', 0o755, b"# one\n");
        let c = tempfile::tempdir().unwrap();
        unpack(&gz(t), c.path(), &Limits::default()).unwrap();
        assert_ne!(base, digest(&execution_input(c.path(), "p").unwrap()));
        let again = unpacked(&[("p/main.tf", "# one\n")]);
        assert_eq!(base, digest(&execution_input(again.path(), "p").unwrap()));
    }

    #[test]
    fn digest_ignores_files_outside_execution_input() {
        let a = unpacked(&[("p/main.tf", "# one\n"), ("README.md", "a")]);
        let b = unpacked(&[
            ("p/main.tf", "# one\n"),
            ("other/x", "b"),
            ("README.md", "c"),
        ]);
        assert_eq!(
            digest(&execution_input(a.path(), "p").unwrap()),
            digest(&execution_input(b.path(), "p").unwrap())
        );
    }

    #[test]
    fn digest_line_format_is_exact() {
        let tree = Tree {
            root: PathBuf::new(),
            files: BTreeMap::from([(
                "p/a.tf".to_string(),
                FileEntry {
                    mode: 0o600,
                    sha256: "ab".into(),
                    size: 1,
                },
            )]),
        };
        let expected: String = Sha256::digest(b"p/a.tf\x00600\x00ab\n")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest(&tree), expected);
    }
}
