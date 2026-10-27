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
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
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

/// Characters that never belong in a path the agent controls: controls
/// (C0 and C1) and the bidi and invisible formatting set, which can make one
/// path read as another.
pub(crate) fn is_hostile_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{61c}' | '\u{ad}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}'
            | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{feff}' | '\u{e0000}'..='\u{e007f}')
}

/// A path made safe to show: hostile characters become `?` and the text is
/// cut to 256 characters.
pub(crate) fn shown(path: &str) -> String {
    const MAX: usize = 256;
    let mut out: String = path
        .chars()
        .take(MAX)
        .map(|c| if is_hostile_char(c) { '?' } else { c })
        .collect();
    if path.chars().nth(MAX).is_some() {
        out.push('\u{2026}');
    }
    out
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
        if Instant::now() >= self.deadline {
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

/// Longest path (in characters) the runner accepts, so a path shown to the
/// approver is never cut.
pub const MAX_PATH_CHARS: usize = 255;

/// Validates an entry path and returns its normal components.
fn clean_path(raw: &[u8]) -> Result<Vec<String>, String> {
    let s = std::str::from_utf8(raw).map_err(|_| "path is not UTF-8".to_string())?;
    if s.chars().any(is_hostile_char) {
        return Err("path contains a control or invisible character".into());
    }
    if s.chars().count() > MAX_PATH_CHARS {
        return Err(format!("path is longer than {MAX_PATH_CHARS} characters"));
    }
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
    if parts.first().is_some_and(|p| p == ".git") {
        return Err("a .git entry at the archive root is refused".into());
    }
    Ok(parts)
}

/// Unpacks a gzip tar into `into` and returns each file's mode.
///
/// The caller passes a fresh, private, empty directory and discards it on any
/// error: a refused archive can leave earlier entries behind. Refuses
/// anything but regular files and directories. Every file is written 0600 and
/// every directory 0700, whatever the umask. The returned map holds the mode
/// the archive asked for, normalized to 0o755 (owner-execute set) or 0o644,
/// keyed by `/`-separated path; that, not the disk, is what the digest sees.
pub fn unpack(
    archive: &[u8],
    into: &Path,
    limits: &Limits,
) -> Result<BTreeMap<String, u32>, Failure> {
    require_empty(into)?;
    if archive.len() as u64 > limits.compressed_bytes {
        return Err(fail("archive_too_large", "compressed bound exceeded"));
    }
    let start = Instant::now();
    let stop = Rc::new(Cell::new(None));
    let slack = (limits.files as u64).saturating_mul(3 * 1024) + 1024 * 1024;
    let guarded = Guarded {
        inner: flate2::read::GzDecoder::new(archive),
        seen: 0,
        cap: limits.unpacked_bytes.saturating_add(slack),
        deadline: start + limits.timeout,
        stop: Rc::clone(&stop),
    };
    run_unpack(guarded, into, limits, start, &stop).map_err(|r| r.into_failure(limits))
}

fn require_empty(dir: &Path) -> Result<(), Failure> {
    let mut entries = fs::read_dir(dir)
        .map_err(|_| fail("archive_write_failed", "the target directory is unreadable"))?;
    if entries.next().is_some() {
        return Err(fail(
            "archive_write_failed",
            "the target directory is not empty",
        ));
    }
    Ok(())
}

/// Creates `parts` under `root` one directory at a time, each 0700 whatever
/// the umask. Fails if a component exists and is not a directory.
fn make_dirs(root: &Path, parts: &[String]) -> io::Result<PathBuf> {
    let mut p = root.to_path_buf();
    for c in parts {
        p.push(c);
        match DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if !fs::symlink_metadata(&p)?.is_dir() {
                    return Err(e);
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(p)
}

/// Creates a new file, 0600 whatever the umask, never following a link.
fn create_private(path: &Path) -> io::Result<fs::File> {
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(f)
}

fn run_unpack<R: Read>(
    reader: R,
    into: &Path,
    limits: &Limits,
    start: Instant,
    stop: &Rc<Cell<Option<Stop>>>,
) -> Result<BTreeMap<String, u32>, Refusal> {
    let malformed = |_: io::Error| match stop.get() {
        Some(s) => Refusal::Stop(s),
        None => Refusal::Other(fail("archive_malformed", "the archive could not be read")),
    };
    let mut modes = BTreeMap::new();
    let mut tar = tar::Archive::new(reader);
    let mut count = 0usize;
    let mut written = 0u64;
    let mut seen_files: BTreeSet<Vec<String>> = BTreeSet::new();
    for entry in tar.entries().map_err(malformed)? {
        if start.elapsed() >= limits.timeout {
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
        let shown_path = shown(&parts.join("/"));
        let cannot = |e: io::Error| Refusal::Entry(format!("cannot create {shown_path}: {e}"));
        if kind.is_dir() {
            make_dirs(into, &parts).map_err(cannot)?;
            continue;
        }
        if !seen_files.insert(parts.clone()) {
            return Err(Refusal::Entry(format!("duplicate entry {shown_path}")));
        }
        let executable = entry
            .header()
            .mode()
            .map(|m| m & 0o100 != 0)
            .unwrap_or(false);
        let (name, parent) = parts.split_last().expect("a file has a name");
        let dir = make_dirs(into, parent).map_err(cannot)?;
        let mut out = create_private(&dir.join(name)).map_err(cannot)?;
        modes.insert(parts.join("/"), if executable { 0o755 } else { 0o644 });
        let mut chunk = [0u8; 64 * 1024];
        loop {
            if start.elapsed() >= limits.timeout {
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
    Ok(modes)
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
pub(crate) fn join_within(base: &[String], rel: &str) -> Option<Vec<String>> {
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
    modes: &BTreeMap<String, u32>,
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
        if dir.is_empty() && name == ".git" {
            continue;
        }
        let mut path = dir.to_vec();
        path.push(name.clone());
        let rel = path.join("/");
        if rel.chars().count() > MAX_PATH_CHARS {
            return Err(fail("input_file_refused", "a path is too long"));
        }
        let meta = fs::symlink_metadata(e.path())
            .map_err(|err| fail("input_file_refused", format!("{}: {err}", shown(&rel))))?;
        if meta.is_dir() {
            if name == ".terraform" {
                return Err(fail(
                    "input_file_refused",
                    format!("{} is refused", shown(&rel)),
                ));
            }
            walk(checkout, &path, modes, files)?;
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
        let Some(&mode) = modes.get(&rel) else {
            return Err(fail(
                "input_file_refused",
                format!("{} has no recorded mode", shown(&rel)),
            ));
        };
        let mut hasher = Sha256::new();
        let mut f = fs::File::open(e.path())
            .map_err(|err| fail("input_file_refused", format!("{}: {err}", shown(&rel))))?;
        io::copy(&mut f, &mut hasher)
            .map_err(|err| fail("input_file_refused", format!("{}: {err}", shown(&rel))))?;
        files.insert(
            rel,
            FileEntry {
                mode,
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
///
/// `modes` is what [`unpack`] returned: the disk holds every file 0600, so
/// the mode in each [`FileEntry`] (and so in the digest) comes from there.
pub fn execution_input(
    checkout: &Path,
    project_path: &str,
    modes: &BTreeMap<String, u32>,
) -> Result<Tree, Failure> {
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
        walk(checkout, &dir, modes, &mut files)?;
    }
    Ok(Tree {
        root: checkout.to_path_buf(),
        files,
    })
}

/// Modes for the operator's own checkout, which is not an unpacked archive:
/// the file's permission bits, normalized the way [`unpack`] does it (0o755
/// when owner-execute is set, else 0o644). `paths` are `/`-separated
/// relative paths; a path that cannot be stat'ed is left out, so
/// [`execution_input`] reports it.
pub fn modes_from_disk(checkout: &Path, paths: &[String]) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for rel in paths {
        let abs = rel
            .split('/')
            .fold(checkout.to_path_buf(), |p, c| p.join(c));
        if let Ok(meta) = fs::symlink_metadata(&abs) {
            let exec = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o100 != 0;
            out.insert(rel.clone(), if exec { 0o755 } else { 0o644 });
        }
    }
    out
}

fn list_files(root: &Path, dir: &[String], out: &mut Vec<String>) {
    let abs = dir.iter().fold(root.to_path_buf(), |p, c| p.join(c));
    let Ok(read) = fs::read_dir(&abs) else {
        return;
    };
    for e in read.filter_map(|e| e.ok()) {
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        if dir.is_empty() && name == ".git" {
            continue;
        }
        let mut path = dir.to_vec();
        path.push(name);
        match e.file_type() {
            Ok(t) if t.is_dir() => list_files(root, &path, out),
            Ok(t) if t.is_file() => out.push(path.join("/")),
            _ => {}
        }
    }
}

/// [`execution_input`] for a checkout on disk whose modes come from its own
/// permission bits (see [`modes_from_disk`]), not from an archive header.
pub fn execution_input_from_disk(checkout: &Path, project_path: &str) -> Result<Tree, Failure> {
    let mut paths = Vec::new();
    list_files(checkout, &[], &mut paths);
    let modes = modes_from_disk(checkout, &paths);
    execution_input(checkout, project_path, &modes)
}

/// Copies exactly the files of `tree` from the checkout at `from` into the
/// fresh, empty directory `into`, at the same relative paths, files 0600 and
/// directories 0700. A run directory built this way holds nothing outside the
/// execution input, so a read outside it finds nothing.
pub fn copy_execution_input(tree: &Tree, from: &Path, into: &Path) -> Result<(), Failure> {
    require_empty(into)?;
    for rel in tree.files.keys() {
        let parts: Vec<String> = rel.split('/').map(str::to_string).collect();
        let shown_path = shown(rel);
        let failed = |e: io::Error| {
            fail(
                "input_copy_failed",
                format!("cannot copy {shown_path}: {e}"),
            )
        };
        let (name, parent) = parts.split_last().expect("a file has a name");
        let src = parts.iter().fold(from.to_path_buf(), |p, c| p.join(c));
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&src)
            .map_err(failed)?;
        let dir = make_dirs(into, parent).map_err(failed)?;
        let mut out = create_private(&dir.join(name)).map_err(failed)?;
        io::copy(&mut input, &mut out).map_err(failed)?;
    }
    Ok(())
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
        let n = name.len().min(100);
        h[..n].copy_from_slice(&name.as_bytes()[..n]);
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

    /// A pax record `"<len> key=value\n"`, where len counts itself.
    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let body = format!(" {key}={value}\n");
        let mut len = body.len();
        loop {
            let total = body.len() + len.to_string().len();
            if total == len {
                break;
            }
            len = total;
        }
        format!("{len}{body}").into_bytes()
    }

    /// A file entry whose real name is carried by a pax `path` record.
    fn pax_path_file(out: &mut Vec<u8>, real: &str, data: &[u8]) {
        raw_entry(out, "pax-header", b'x', 0o644, &pax_record("path", real));
        raw_entry(out, "innocent", b'0', 0o644, data);
    }

    /// A file entry whose real name is carried by a GNU `L` longname entry.
    fn gnu_long_file(out: &mut Vec<u8>, real: &str, data: &[u8]) {
        let mut name = real.as_bytes().to_vec();
        name.push(0);
        raw_entry(out, "././@LongLink", b'L', 0o644, &name);
        raw_entry(out, "innocent", b'0', 0o644, data);
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

    type Fixture = (tempfile::TempDir, BTreeMap<String, u32>);

    fn unpacked(entries: &[(&str, &str)]) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let modes = unpack(&archive(entries), dir.path(), &Limits::default()).unwrap();
        (dir, modes)
    }

    fn input(fx: &Fixture, project: &str) -> Result<Tree, Failure> {
        execution_input(fx.0.path(), project, &fx.1)
    }

    fn refused(tar: Vec<u8>) -> Failure {
        let dir = tempfile::tempdir().unwrap();
        unpack(&gz(tar), dir.path(), &Limits::default()).unwrap_err()
    }

    #[test]
    fn long_paths_are_refused_at_unpack_and_in_the_input() {
        let long = format!("{}/{}", "a".repeat(150), "b".repeat(150));
        let mut t = Vec::new();
        gnu_long_file(&mut t, &long, b"x");
        assert_eq!(refused(t).category, "archive_entry_refused");
        let dir = tempfile::tempdir().unwrap();
        let deep = dir
            .path()
            .join("p")
            .join("a".repeat(150))
            .join("b".repeat(150));
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("main.tf"), "x = 1\n").unwrap();
        let err = execution_input_from_disk(dir.path(), "p").unwrap_err();
        assert_eq!(err.category, "input_file_refused");
    }

    #[test]
    fn git_file_at_the_root_is_skipped_and_archive_git_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".git"), "gitdir: /elsewhere\n").unwrap();
        fs::write(dir.path().join("main.tf"), "x = 1\n").unwrap();
        let t = execution_input_from_disk(dir.path(), ".").unwrap();
        assert_eq!(t.files.keys().collect::<Vec<_>>(), vec!["main.tf"]);
        let into = tempfile::tempdir().unwrap();
        let err = unpack(
            &archive(&[("main.tf", "x"), (".git/HEAD", "ref")]),
            into.path(),
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(err.category, "archive_entry_refused");
    }

    #[test]
    fn git_directory_at_the_root_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git/objects")).unwrap();
        fs::write(dir.path().join(".git/HEAD"), "ref\n").unwrap();
        fs::write(dir.path().join("main.tf"), "x = 1\n").unwrap();
        let t = execution_input_from_disk(dir.path(), ".").unwrap();
        assert_eq!(t.files.keys().collect::<Vec<_>>(), vec!["main.tf"]);
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
    fn hard_link_device_and_fifo_entries_are_refused() {
        for kind in [b'1', b'3', b'4', b'6'] {
            let mut t = Vec::new();
            raw_entry(&mut t, "odd", kind, 0o644, b"");
            assert_eq!(refused(t).category, "archive_entry_refused", "{kind}");
        }
    }

    #[test]
    fn dotdot_entry_is_refused() {
        let mut t = Vec::new();
        raw_entry(&mut t, "a/../../evil", b'0', 0o644, b"x");
        assert_eq!(refused(t).category, "archive_entry_refused");
        let mut t = Vec::new();
        raw_entry(&mut t, "/etc/evil", b'0', 0o644, b"x");
        assert_eq!(refused(t).category, "archive_entry_refused");
    }

    #[test]
    fn traversal_hidden_in_pax_path_and_gnu_longname_is_refused() {
        let mut t = Vec::new();
        pax_path_file(&mut t, "../evil", b"x");
        assert_eq!(refused(t).category, "archive_entry_refused");
        let mut t = Vec::new();
        gnu_long_file(&mut t, "../evil", b"x");
        assert_eq!(refused(t).category, "archive_entry_refused");
        let mut t = Vec::new();
        gnu_long_file(&mut t, "/abs/evil", b"x");
        assert_eq!(refused(t).category, "archive_entry_refused");
    }

    #[test]
    fn pax_global_header_is_skipped_without_affecting_later_entries() {
        let mut t = Vec::new();
        raw_entry(
            &mut t,
            "pax_global_header",
            b'g',
            0o666,
            &pax_record("comment", "abc"),
        );
        raw_entry(&mut t, "p/main.tf", b'0', 0o644, b"# x\n");
        let dir = tempfile::tempdir().unwrap();
        let modes = unpack(&gz(t), dir.path(), &Limits::default()).unwrap();
        assert_eq!(modes.keys().collect::<Vec<_>>(), ["p/main.tf"]);
        assert!(dir.path().join("p/main.tf").is_file());
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
    fn file_and_directory_at_the_same_path_are_refused() {
        let mut t = Vec::new();
        raw_entry(&mut t, "x", b'0', 0o644, b"1");
        raw_entry(&mut t, "x", b'5', 0o755, b"");
        assert_eq!(refused(t).category, "archive_entry_refused");
        let mut t = Vec::new();
        raw_entry(&mut t, "x", b'5', 0o755, b"");
        raw_entry(&mut t, "x", b'0', 0o644, b"1");
        assert_eq!(refused(t).category, "archive_entry_refused");
    }

    #[test]
    fn file_under_a_path_that_was_a_file_is_refused() {
        let mut t = Vec::new();
        raw_entry(&mut t, "x", b'0', 0o644, b"1");
        raw_entry(&mut t, "x/y", b'0', 0o644, b"2");
        assert_eq!(refused(t).category, "archive_entry_refused");
    }

    #[test]
    fn bidi_and_c1_paths_are_refused_and_not_echoed() {
        for name in ["a\u{202e}fdp.tf", "a\u{85}b", "a\u{200b}b", "a\u{feff}b"] {
            let mut t = Vec::new();
            raw_entry(&mut t, name, b'0', 0o644, b"x");
            let err = refused(t);
            assert_eq!(err.category, "archive_entry_refused");
            let detail = err.detail.unwrap();
            assert!(!detail.chars().any(is_hostile_char), "{detail:?}");
        }
    }

    #[test]
    fn very_long_path_is_refused_with_a_bounded_detail() {
        let long = "a".repeat(10_000);
        let mut t = Vec::new();
        gnu_long_file(&mut t, &long, b"x");
        let err = refused(t);
        assert_eq!(err.category, "archive_entry_refused");
        let detail = err.detail.unwrap();
        assert!(detail.chars().count() < 400, "{}", detail.len());
        assert!(detail.contains("longer than 255"), "{detail}");
        let shown_long = shown(&"b".repeat(10_000));
        assert_eq!(shown_long.chars().count(), 257);
    }

    #[test]
    fn malformed_archive_detail_does_not_echo_tar_error_text() {
        let err = refused(vec![0xffu8; 512]);
        assert_eq!(err.category, "archive_malformed");
        assert_eq!(err.detail.as_deref(), Some("the archive could not be read"));
    }

    #[test]
    fn non_empty_target_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("old"), "x").unwrap();
        let err = unpack(&archive(&[("a", "x")]), dir.path(), &Limits::default()).unwrap_err();
        assert_eq!(err.category, "archive_write_failed");
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
        let err = unpack(&archive(&[("a", "x")]), dir.path(), &limits).unwrap_err();
        assert_eq!(err.category, "archive_timeout");
    }

    #[test]
    fn files_are_0600_on_disk_and_the_digest_sees_the_header_mode() {
        let mut t = Vec::new();
        raw_entry(&mut t, "d/run.sh", b'0', 0o755, b"x");
        raw_entry(&mut t, "d/plain", b'0', 0o666, b"x");
        raw_entry(&mut t, "d/main.tf", b'0', 0o600, b"# x\n");
        let dir = tempfile::tempdir().unwrap();
        let modes = unpack(&gz(t), dir.path(), &Limits::default()).unwrap();
        let mode = |p: &str| {
            fs::metadata(dir.path().join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("d"), 0o700);
        assert_eq!(mode("d/run.sh"), 0o600);
        assert_eq!(mode("d/plain"), 0o600);
        let tree = execution_input(dir.path(), "d", &modes).unwrap();
        assert_eq!(tree.files["d/run.sh"].mode, 0o755);
        assert_eq!(tree.files["d/plain"].mode, 0o644);
        assert_eq!(tree.files["d/main.tf"].mode, 0o644);
    }

    const UMASK_CHILD: &str = "SHOEPHONE_TREE_UMASK_CHILD";

    fn digest_of_exec_and_plain(dir: &Path) -> String {
        let mut t = Vec::new();
        raw_entry(&mut t, "d/run.sh", b'0', 0o755, b"x");
        raw_entry(&mut t, "d/main.tf", b'0', 0o644, b"# x\n");
        let modes = unpack(&gz(t), dir, &Limits::default()).unwrap();
        digest(&execution_input(dir, "d", &modes).unwrap())
    }

    #[test]
    fn umask_child() {
        if std::env::var_os(UMASK_CHILD).is_none() {
            return;
        }
        let want = std::env::var(UMASK_CHILD).unwrap();
        // SAFETY: the child process runs only this test.
        let dir = tempfile::tempdir().unwrap();
        unsafe { libc::umask(0o177) };
        assert_eq!(digest_of_exec_and_plain(dir.path()), want);
    }

    #[test]
    fn umask_does_not_change_the_digest() {
        if std::env::var_os(UMASK_CHILD).is_some() {
            return;
        }
        let want = digest_of_exec_and_plain(tempfile::tempdir().unwrap().path());
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runner::tree::tests::umask_child",
                "--test-threads=1",
            ])
            .env(UMASK_CHILD, &want)
            .status()
            .unwrap();
        assert!(status.success());
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
            let fx = unpacked(&[("p/main.tf", &tf)]);
            let err = input(&fx, "p").unwrap_err();
            assert_eq!(err.category, "module_not_local", "{src}");
        }
        let fx = unpacked(&[("p/main.tf", "module \"m\" {\n  source = var.s\n}\n")]);
        let err = input(&fx, "p").unwrap_err();
        assert_eq!(err.category, "module_not_local");
    }

    #[test]
    fn module_leaving_the_checkout_is_refused() {
        for src in ["../../x", "./x/../../../y"] {
            let tf = format!("module \"m\" {{\n  source = \"{src}\"\n}}\n");
            let fx = unpacked(&[("p/main.tf", &tf)]);
            let err = input(&fx, "p").unwrap_err();
            assert_eq!(err.category, "module_outside_checkout", "{src}");
        }
    }

    #[test]
    fn dot_segments_that_stay_inside_resolve_lexically() {
        let tf = "module \"m\" {\n  source = \"./x/../../y\"\n}\n";
        let fx = unpacked(&[("p/main.tf", tf), ("y/main.tf", "# y\n")]);
        let tree = input(&fx, "p").unwrap();
        assert!(tree.files.contains_key("y/main.tf"));
    }

    #[test]
    fn module_cycle_terminates() {
        let a = "module \"b\" {\n  source = \"../b\"\n}\n";
        let b = "module \"a\" {\n  source = \"../a\"\n}\n";
        let fx = unpacked(&[("a/main.tf", a), ("b/main.tf", b)]);
        let tree = input(&fx, "a").unwrap();
        assert_eq!(tree.files.len(), 2);
    }

    #[test]
    fn local_module_outside_project_dir_is_included() {
        let tf = "module \"net\" {\n  source = \"../../modules/net\"\n}\n";
        let fx = unpacked(&[
            ("env/prod/main.tf", tf),
            (
                "modules/net/main.tf",
                LOCAL.replace("./sub", "../leaf").as_str(),
            ),
            ("modules/leaf/main.tf", "# leaf\n"),
            ("modules/unused/main.tf", "# unused\n"),
        ]);
        let tree = input(&fx, "env/prod").unwrap();
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
            let fx = unpacked(&[("p/main.tf", "# x\n"), (&format!("p/{name}"), "{}")]);
            let err = input(&fx, "p").unwrap_err();
            assert_eq!(err.category, "input_file_refused", "{name}");
        }
        let fx = unpacked(&[("p/main.tf", "# x\n"), ("p/.terraform/x", "x")]);
        assert_eq!(input(&fx, "p").unwrap_err().category, "input_file_refused");
        let fx = unpacked(&[("p/main.tf", "# x\n"), ("p/a.tf.json", "{}")]);
        assert_eq!(input(&fx, "p").unwrap_err().category, "tf_json_refused");
    }

    #[test]
    fn digest_changes_with_mode_and_content() {
        let a = unpacked(&[("p/main.tf", "# one\n")]);
        let base = digest(&input(&a, "p").unwrap());
        let b = unpacked(&[("p/main.tf", "# two\n")]);
        assert_ne!(base, digest(&input(&b, "p").unwrap()));
        let mut t = Vec::new();
        raw_entry(&mut t, "p/main.tf", b'0', 0o755, b"# one\n");
        let c = tempfile::tempdir().unwrap();
        let modes = unpack(&gz(t), c.path(), &Limits::default()).unwrap();
        let exec = digest(&execution_input(c.path(), "p", &modes).unwrap());
        assert_ne!(base, exec);
        let again = unpacked(&[("p/main.tf", "# one\n")]);
        assert_eq!(base, digest(&input(&again, "p").unwrap()));
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
            digest(&input(&a, "p").unwrap()),
            digest(&input(&b, "p").unwrap())
        );
    }

    #[test]
    fn copy_holds_only_the_execution_input_and_keeps_the_digest() {
        let tf = "module \"net\" {\n  source = \"../m\"\n}\n";
        let fx = unpacked(&[
            ("p/main.tf", tf),
            ("m/main.tf", "# m\n"),
            ("secret/notes", "outside"),
        ]);
        let tree = input(&fx, "p").unwrap();
        let into = tempfile::tempdir().unwrap();
        copy_execution_input(&tree, fx.0.path(), into.path()).unwrap();
        assert!(!into.path().join("secret").exists());
        let modes: BTreeMap<String, u32> = tree
            .files
            .iter()
            .map(|(k, v)| (k.clone(), v.mode))
            .collect();
        let copied = execution_input(into.path(), "p", &modes).unwrap();
        assert_eq!(digest(&copied), digest(&tree));
        let mode = |p: &str| {
            fs::metadata(into.path().join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("p"), 0o700);
        assert_eq!(mode("p/main.tf"), 0o600);
        let err = copy_execution_input(&tree, fx.0.path(), into.path()).unwrap_err();
        assert_eq!(err.category, "archive_write_failed");
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
