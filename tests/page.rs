// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The approve page's inline script must at least parse.
//!
//! A syntax error in that script is invisible to every Rust test: the page
//! is a string constant that the daemon serves verbatim, and the browser
//! then silently runs none of it, so every button does nothing. That shipped
//! once (a `const` declared twice in one block). This test hands the script
//! to `node --check` when node is on PATH, which covers CI and most
//! development machines, and skips loudly otherwise.

use std::io::Write;
use std::process::{Command, Stdio};

use shoephone::server::PAGE;

fn inline_script(page: &str) -> &str {
    let start = page.find("<script>").expect("page has a <script> tag") + "<script>".len();
    let end = page[start..]
        .find("</script>")
        .expect("page has a </script> tag")
        + start;
    &page[start..end]
}

#[test]
fn approve_page_script_parses() {
    let script = inline_script(PAGE);
    assert!(
        script.contains("navigator.credentials"),
        "extracted the wrong block from the page"
    );
    let mut child = match Command::new("node")
        .arg("--check")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("skipping: node is not runnable ({e}); the page script was not parsed");
            return;
        }
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "the approve page's script does not parse:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
