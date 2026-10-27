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

const NODE_PRELUDE: &str = include_str!("fixtures/node-prelude.js");

/// Runs against every vector in the shared fixture: the page must rebuild the
/// signed bytes, the address text and the counts exactly as the daemon does,
/// and its verification must accept a consistent job and refuse a tampered one.
const NODE_HARNESS: &str = r#"
const assert = require('node:assert/strict');
const sha = async s => {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d), b => b.toString(16).padStart(2, '0')).join('');
};
const refused = async (job, what) => {
  try { await verifyJob(job); } catch (e) {
    assert.equal(e.message, "the daemon's challenge does not match the request on screen", what);
    return;
  }
  assert.fail('accepted: ' + what);
};
const withChallenge = async (job, bytes) => {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bytes));
  job.challenge = b64u.enc(d);
  return job;
};
(async () => {
  let applyIndex = 0;
  for (const v of V.vectors) {
    const bytes = v.kind === 'trust' ? trustBytes(v.scope, v.nonce) : applyBytes(v.scope, v.nonce);
    assert.equal(bytes, v.bytes_to_sign, v.name);
    assert.equal(await sha(bytes), v.challenge_sha256_hex, v.name);
    if (v.kind === 'apply') {
      const text = Object.values(V.address_texts)[applyIndex++];
      assert.equal(addressText(text.split('\n').slice(0, -1)), text, v.name);
      assert.equal(await sha(text), v.scope.addresses, v.name);
      const lines = parseAddressText(text);
      const c = countActions(lines);
      assert.deepEqual(c, v.scope.counts, v.name);
      assert.equal(c.delete + c.replace > 0, v.scope.destructive, v.name);
    }
  }
  assert.equal(parseAddressText('create a\nbogus b\n'), null);
  assert.equal(parseAddressText('create a\nupdate x'), null);
  assert.equal(parseAddressText('create a update x\n'), null);
  assert.equal(parseAddressText('create \n'), null);
  assert.deepEqual(parseAddressText(''), []);

  const base = '{"a":1,"b":"x","c":[1]}';
  const next = '{"b":"y","c":[1],"d":null}';
  const delta = variableDiff(base, next);
  assert.deepEqual(delta.added.map(x => x.key), ['d']);
  assert.deepEqual(delta.removed.map(x => x.key), ['a']);
  assert.deepEqual(delta.changed.map(x => x.key), ['b']);
  assert.equal(delta.changed[0].old, '"x"');
  assert.equal(delta.changed[0].new, '"y"');
  assert.throws(() => variableDiff(null, '[1]'));

  const text = 'delete aws_instance.old\nreplace aws_db.main\ncreate aws_eip.web\n';
  const scope = {
    project: 'p', revision: 'a'.repeat(64), schema: 'b'.repeat(64),
    manifest: await sha(next), baseline_manifest: await sha(base),
    baseline_status: 'uncertain', plan: 'c'.repeat(64), destructive: true,
    counts: {create: 1, update: 0, replace: 1, delete: 1}, addresses: await sha(text),
  };
  const mkApply = async () => {
    const j = {id: 7, kind: 'apply', nonce: 'n1', scope: {kind: 'apply', ...scope},
      display: {manifest: next, baseline_manifest: base, address_text: text}};
    return withChallenge(j, applyBytes(j.scope, j.nonce));
  };
  const ok = await mkApply();
  assert.ok(await verifyJob(ok));
  let j = await mkApply(); j.display.manifest = '{"b":"z"}'; await refused(j, 'manifest');
  j = await mkApply(); j.display.baseline_manifest = '{}'; await refused(j, 'baseline');
  j = await mkApply(); j.display.baseline_manifest = null; await refused(j, 'baseline dropped');
  j = await mkApply(); j.display.address_text = 'create x\n'; await refused(j, 'addresses');
  j = await mkApply(); delete j.display.address_text; await refused(j, 'no address text');
  j = await mkApply(); delete j.display.manifest; await refused(j, 'no manifest');
  j = await mkApply(); j.scope.counts = {...j.scope.counts, delete: 0, update: 1};
  j = await withChallenge(j, applyBytes(j.scope, j.nonce)); await refused(j, 'counts');
  j = await mkApply(); j.scope.destructive = false;
  j = await withChallenge(j, applyBytes(j.scope, j.nonce)); await refused(j, 'destructive');
  j = await mkApply(); j.nonce = 'n2'; await refused(j, 'nonce');
  j = await mkApply(); j.challenge = 'AAAA'; await refused(j, 'challenge');

  const diff = '+++ b/main.tf\n+resource "x" "y" {}\n';
  const tscope = {
    project: 'p', baseline: null, candidate: 'a'.repeat(64), diff: await sha(diff),
    schema: 'b'.repeat(64), policy_version: 1, files_changed: 1, lines_added: 1,
    lines_removed: 0, schema_changed: false,
  };
  const mkTrust = async display => {
    const j = {id: 8, kind: 'trust', nonce: 'n3', scope: {kind: 'trust', ...tscope}, display};
    return withChallenge(j, trustBytes(j.scope, j.nonce));
  };
  assert.ok(await verifyJob(await mkTrust({diff})));
  await refused(await mkTrust({diff: diff + 'x'}), 'trust diff');
  await refused(await mkTrust({}), 'trust with no diff');
  await refused(await mkTrust({external: false}), 'trust with no diff, not external');
  await refused(await mkTrust({external: true}), 'external without a command');
  assert.ok(await verifyJob(await mkTrust({external: true, verify_command: 'shoephone diff-digest p'})));
  console.log('harness ok');
})().catch(e => { console.error(e); process.exit(1); });
"#;

#[test]
fn page_rebuilds_trust_and_apply_bytes() {
    let script = inline_script(PAGE);
    let vectors = include_str!("fixtures/job-scope-vectors.json");
    let program = format!("{NODE_PRELUDE}\n{script}\nconst V = {vectors};\n{NODE_HARNESS}\n");
    let mut child = match Command::new("node")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!(
                "skipping: node is not runnable ({e}); the page's byte formats were not checked"
            );
            return;
        }
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "the page's job verification failed under node:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
