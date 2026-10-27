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
  assert.equal(parseAddressText('create a\u2028update x\n'), null);
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
    const j = {id: 7, kind: 'apply', project: 'p', nonce: 'n1', reason: 'r', match_code: 'M', expires: 0, scope: {kind: 'apply', ...scope},
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

  const bidi = String.fromCharCode(0x202e), c1 = String.fromCharCode(0x85);
  assert.equal(parseAddressText('create a' + bidi + 'b\n'), null);
  assert.equal(parseAddressText('create a' + c1 + 'b\n'), null);
  assert.equal(visible('a' + bidi + 'b' + c1 + String.fromCharCode(0x2028)), 'a\\u202eb\\u0085\\u2028');
  assert.equal(visible('x\ny', true), 'x\ny');
  assert.equal(visible('x\ny'), 'x\\u000ay');

  const big = variableDiff('{"a":9007199254740992}', '{"a":9007199254740993}');
  assert.deepEqual(big.changed, [{key: 'a', old: '9007199254740992', new: '9007199254740993'}], 'integers a double cannot tell apart');
  assert.equal(variableDiff(null, '{"a":[1.2345678901234567890]}').added[0].new, '[1.2345678901234567890]');
  const tenth = variableDiff(null, '{"a":0.30000000000000004}');
  assert.equal(tenth.added[0].new, '0.30000000000000004');
  assert.equal(variableRows(tenth)[0], '+ a = 0.30000000000000004');
  assert.equal(variableDiff('{"a":1.5,"s":"9007199254740993"}', '{"a":2.5,"s":"9007199254740993"}').changed.length, 1);

  j = await mkApply(); j.kind = 'trust'; await refused(j, 'kind differs from scope');
  j = await mkApply(); j.project = 'other'; await refused(j, 'project differs from scope');
  j = await mkApply(); j.scope.project = 'bad project'; j = await withChallenge(j, applyBytes(j.scope, j.nonce)); j.project = 'bad project'; await refused(j, 'project not a slug');
  j = await mkApply(); j.scope.plan = 'A'.repeat(64); j = await withChallenge(j, applyBytes(j.scope, j.nonce)); await refused(j, 'digest not lowercase hex');
  j = await mkApply(); j.scope.baseline_status = 'bogus'; j = await withChallenge(j, applyBytes(j.scope, j.nonce)); await refused(j, 'baseline status');

  const emptyScope = {...scope, destructive: false, counts: {create: 0, update: 0, replace: 0, delete: 0}, addresses: await sha('')};
  j = {id: 9, kind: 'apply', project: 'p', nonce: 'n4', scope: {kind: 'apply', ...emptyScope}, display: {manifest: next, baseline_manifest: base, address_text: ''}};
  assert.ok(await verifyJob(await withChallenge(j, applyBytes(j.scope, j.nonce))), 'empty change list is consistent');

  assert.deepEqual(variableDiff('{"a":0}', '{"a":1e-400}').changed, [{key: 'a', old: '0', new: '1e-400'}], 'underflow is still a change');
  assert.throws(() => variableDiff(null, '{"a":1e400}'));
  assert.throws(() => variableDiff(null, '{"a":[-1e400]}'));
  assert.throws(() => variableDiff('{"a":{"b":1e999}}', '{"a":1}'));
  assert.equal(variableDiff(null, '{"a":1e-310}').added.length, 1);
  assert.equal(variableDiff('{"a":0}', '{"a":-1e-400}').changed.length, 1);
  assert.equal(variableDiff('{"a":0.0}', '{"a":1.5e3}').changed.length, 1);
  assert.equal(variableDiff('{"a":0}', '{"a":0.0e5}').changed.length, 1, 'compared as written');
  assert.equal(variableDiff('{"a":{"x":[1,true]},"b":null}', '{"a":{"x":[1,true]},"b":null}').changed.length, 0);
  assert.deepEqual(variableDiff(null, '{"__proto__":1,"constructor":2}').added.map(x => x.key), ['__proto__', 'constructor']);
  j = await mkApply(); j.display.manifest = '{"b":1e400}'; j.scope.manifest = await sha(j.display.manifest);
  await refused(await withChallenge(j, applyBytes(j.scope, j.nonce)), 'infinite number in manifest');

  const bs = String.fromCharCode(92);
  assert.equal(visible(bs + 'u202e'), bs + bs + 'u202e', 'a literal backslash is escaped');
  assert.equal(visible(bs + 'u202e', false, true), bs + 'u202e');
  const hidden = [0x61c, 0x200b, 0x2060, 0xfeff, 0xad].map(c => String.fromCharCode(c)).join('') + String.fromCodePoint(0xe0001, 0xe007f);
  assert.equal(visible(hidden), bs + 'u061c' + bs + 'u200b' + bs + 'u2060' + bs + 'ufeff' + bs + 'u00ad' + bs + 'u{e0001}' + bs + 'u{e007f}');
  const rows = variableRows(variableDiff('{"k":"a' + bs + bs + 'b"}', '{"k' + bs + 'u202e":"v' + bs + '"q"}'.replace(bs + '"', bs + '"')));
  assert.deepEqual(rows[0], '+ k' + bs + 'u202e = "v' + bs + '"q"', 'a real U+202E key shows as one escape');
  const lit = variableRows(variableDiff(null, '{"k' + bs + bs + 'u202e":1}'));
  assert.equal(lit[0], '+ k' + bs + bs + 'u202e = 1', 'typed backslash-u text is told apart from the real character');
  const one = variableRows(variableDiff('{"k":"x"}', '{"k":"a' + bs + bs + 'b"}'));
  assert.equal(one[0], '~ k: "x" -> "a' + bs + bs + 'b"', 'JSON values are not escaped twice');

  assert.throws(() => variableDiff(null, '{"a":1,"a":2}'));
  assert.throws(() => variableDiff(null, '{"a":{"b":1,"c":[{"d":1,"d":2}]}}'));
  assert.throws(() => variableDiff('{"a":1,"a":1}', '{"a":1}'));
  assert.equal(variableDiff(null, '{"a":{"b":1},"c":{"b":2},"s":"{\\"x\\":1,\\"x\\":2}"}').added.length, 3);
  j = {id: 10, kind: 'apply', project: 'p', nonce: 'n5', scope: {kind: 'apply', ...scope}, display: {manifest: '{"b":1,"b":1}', baseline_manifest: base, address_text: text}};
  j.scope.manifest = await sha('{"b":1,"b":1}');
  await refused(await withChallenge(j, applyBytes(j.scope, j.nonce)), 'duplicate key in manifest');

  const timers = [];
  globalThis.setTimeout = fn => { timers.push(fn); return 0; };
  showJob(null);
  const first = await mkApply();
  showJob(first);
  assert.equal(els.jobapprove.disabled, true, 'buttons are held right after a render');
  assert.equal(els.jobdecline.disabled, true);
  timers.shift()();
  assert.equal(els.jobapprove.disabled, false, 'and released after the hold');
  const changed = await mkApply();
  changed.display.address_text = 'create z\n';
  showJob(changed);
  assert.equal(els.jobapprove.disabled, true, 'a content change holds them again');
  timers.shift()();
  assert.equal(els.jobapprove.disabled, false);
  timers.length = 0;
  showJob(first);
  showJob(changed);
  showJob(first);
  assert.equal(timers.length, 3);
  timers.shift()();
  assert.equal(els.jobapprove.disabled, true, 'an older render does not release the hold, even for the same content');
  timers.shift()();
  assert.equal(els.jobapprove.disabled, true);
  timers.shift()();
  assert.equal(els.jobapprove.disabled, false, 'the current render releases it');
  showJob(changed);
  busy = true;
  timers.shift()();
  assert.equal(els.jobapprove.disabled, true, 'not released while an approval is in progress');
  busy = false;
  timers.length = 0;

  const realFetch = globalThis.fetch;
  let fail;
  globalThis.fetch = () => new Promise((_, rej) => { fail = () => rej(new Error('offline')); });
  const settle = async p => { await new Promise(r => setImmediate(r)); fail(); await p; };
  showJob(first);
  timers.shift()();
  assert.equal(els.jobapprove.disabled, false);
  let flight = els.jobdecline.onclick();
  assert.equal(els.jobapprove.disabled, true, 'decline holds both buttons while its request is in flight');
  assert.equal(els.jobdecline.disabled, true);
  await settle(flight);
  assert.equal(els.jobapprove.disabled, false, 'and releases them after, when the hold has run out');
  timers.length = 0;
  flight = els.jobapprove.onclick();
  assert.equal(els.jobapprove.disabled, true);
  showJob(changed);
  await settle(flight);
  assert.equal(els.jobapprove.disabled, true, 'approve does not release a new render still on hold');
  assert.equal(els.jobdecline.disabled, true);
  timers.shift()();
  assert.equal(els.jobapprove.disabled, false, 'the new render releases them after its hold');
  showJob(first);
  timers.length = 0;
  flight = els.jobdecline.onclick();
  await settle(flight);
  assert.equal(els.jobdecline.disabled, true, 'decline does not release a render still on hold');
  timers.length = 0;
  globalThis.fetch = realFetch;
  showJob(null);

  const line = 'x = "a' + bs + 'nb" y = ' + bs + '"q' + bs + '" ' + bs + 'u202e ' + bs + 'U{1} p' + bs + bs + 'u';
  assert.equal(visibleDiff(line), 'x = "a' + bs + 'nb" y = ' + bs + '"q' + bs + '" ' + bs + bs + 'u202e ' + bs + bs + 'U{1} p' + bs + bs + bs + bs + 'u');
  assert.equal(visibleDiff('a' + bs + 'nb' + bidi), 'a' + bs + 'nb' + bs + 'u202e');
  assert.equal(visibleDiff('c:' + bs + 'temp' + bs + 'new'), 'c:' + bs + 'temp' + bs + 'new');
  const typedBidi = bs + 'u202e', typedTag = bs + 'u{e0001}', tag = String.fromCodePoint(0xe0001);
  assert.notEqual(visibleDiff(bs + bidi), visibleDiff(typedBidi), 'backslash before a real U+202E differs from typed text');
  assert.notEqual(visibleDiff(bs + tag), visibleDiff(typedTag), 'backslash before a real tag differs from typed text');
  assert.notEqual(visibleDiff(bs + bidi), visibleDiff(bs + typedBidi), 'and from a typed backslash before typed text');
  assert.notEqual(visibleDiff(bs + tag), visibleDiff(bs + typedTag));
  assert.equal(visibleDiff(bs + bidi), bs + bs + bs + 'u202e');
  assert.equal(visibleDiff(bs + bs + bidi), bs.repeat(5) + 'u202e');
  assert.equal(visibleDiff(bs + bs + 'u202e'), bs.repeat(4) + 'u202e');
  assert.equal(visibleDiff(bs + tag), bs + bs + bs + 'u{e0001}');
  assert.equal(visibleDiff(bs + String.fromCharCode(1)), bs + bs + bs + 'u0001');
  assert.equal(visibleDiff(bs + '\n' + bs + '\t'), bs + '\n' + bs + '\t', 'newline and tab are not escaped, so their backslash stays');

  const shown = await mkApply();
  const later = await mkApply();
  later.display.manifest = '{"b":"z"}';
  showJob(shown);
  assert.equal(jobToSign(), shown);
  showJob(later);
  assert.equal(jobToSign(), later, 'a changed display re-renders and is what gets verified');
  showJob(null);
  assert.equal(jobToSign(), null);
  const hostile = await mkApply();
  hostile.reason = 'a' + bidi + 'b';
  hostile.scope.project = 'real';
  showJob(hostile);
  assert.equal(els.jobreason.textContent, 'a\\u202eb');
  assert.equal(els.jobheading.textContent, 'Apply to real');
  assert.equal(els.jobapprove.textContent, 'Apply');

  const diff = '+++ b/main.tf\n+resource "x" "y" {}\n';
  const tscope = {
    project: 'p', baseline: null, candidate: 'a'.repeat(64), diff: await sha(diff),
    schema: 'b'.repeat(64), policy_version: 1, files_changed: 1, lines_added: 1,
    lines_removed: 0, schema_changed: false,
  };
  const mkTrust = async display => {
    const j = {id: 8, kind: 'trust', project: 'p', nonce: 'n3', reason: 'r', match_code: 'M', expires: 0, scope: {kind: 'trust', ...tscope}, display};
    return withChallenge(j, trustBytes(j.scope, j.nonce));
  };
  assert.ok(await verifyJob(await mkTrust({diff})));
  await refused(await mkTrust({diff: diff + 'x'}), 'trust diff');
  await refused(await mkTrust({}), 'trust with no diff');
  await refused(await mkTrust({external: false}), 'trust with no diff, not external');
  assert.ok(await verifyJob(await mkTrust({external: true})));
  assert.equal(verifyCommand({baseline: null}), 'shoephone-runner diff-digest none - <candidate-checkout> <project-path>');
  assert.equal(verifyCommand({baseline: 'a'.repeat(64)}), 'shoephone-runner diff-digest ' + 'a'.repeat(64) + ' <baseline-checkout> <candidate-checkout> <project-path>');
  // Runner warnings: shown through textContent and visible(), never signed.
  const realCreate = document.createElement;
  const rec = () => ({className: '', textContent: '', children: [], append(...c) { this.children.push(...c); }});
  const texts = n => [n.textContent, ...n.children.map(texts)].filter(t => t !== '').join('|');
  const rendered = async display => {
    document.createElement = rec;
    try { return renderTrust(await mkTrust(display)).map(texts); } finally { document.createElement = realCreate; }
  };
  const w = (kind, extra) => ({kind, file: 'infra/main.tf', line: 7, ...extra});
  const expectLines = [
    [w('provisioner'), 'provisioner block infra/main.tf:7'],
    [w('external_data'), 'external data source infra/main.tf:7'],
    [w('http_data'), 'HTTP data source infra/main.tf:7'],
    [w('import'), 'import block infra/main.tf:7'],
    [w('nonsensitive'), 'nonsensitive() call infra/main.tf:7'],
    [w('provider_function'), 'provider-defined function infra/main.tf:7'],
    [w('local_file_read'), 'local file read infra/main.tf:7'],
    [w('schema_variable_steers', {variable: 'region', into: 'count'}), 'agent-settable variable region reaches count infra/main.tf:7'],
  ];
  for (const [warning, line] of expectLines) assert.equal(warningLine(warning), line);
  const header = 'Runner warnings (not covered by your signature)';
  const withDiff = await rendered({diff, warnings: expectLines.map(x => x[0])});
  const wi = withDiff.findIndex(t => t.startsWith(header));
  assert.ok(wi > 0 && withDiff[0].length > 0, 'warnings follow the obligation statement');
  assert.ok(withDiff[wi].includes('provisioner block infra/main.tf:7'));
  assert.ok(withDiff[wi].includes('agent-settable variable region reaches count infra/main.tf:7'));
  assert.ok(!withDiff[wi].includes('No warnings'));
  assert.ok(withDiff.findIndex(t => t.startsWith('diff')) > wi, 'warnings come before the diff');
  for (const display of [{diff}, {diff, warnings: []}, {external: true}]) {
    const out = await rendered(display);
    const i = out.findIndex(t => t.startsWith(header));
    assert.ok(i > 0 && out[i].endsWith('No warnings'), JSON.stringify(display));
  }
  const more = await rendered({diff, warnings: [w('import')], warnings_omitted: 50});
  assert.ok(more.find(t => t.startsWith(header)).endsWith('50 more warnings not shown'));
  assert.ok(!withDiff[wi].includes('more warnings'));
  const hostileOut = await rendered({diff, warnings: [w('provisioner', {file: 'a' + bidi + 'b.tf'}), w('bogus<b>')]});
  const hi = hostileOut.find(t => t.startsWith(header));
  assert.ok(hi.includes('a\\u202eb.tf') && !hi.includes(bidi), 'hidden characters are escaped');
  assert.ok(hi.includes('unknown warning bogus<b>'), 'an unknown kind is shown, not dropped');
  // Warnings change nothing about verification.
  assert.ok(await verifyJob(await mkTrust({diff, warnings: [w('provisioner')]})));
  assert.ok(await verifyJob(await mkTrust({external: true, warnings: [w('import')]})));
  await refused(await mkTrust({diff: diff + 'x', warnings: [w('provisioner')]}), 'warnings do not rescue a bad diff');
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

#[test]
fn page_marks_file_boundaries_and_asks_for_both_digests() {
    let html = include_str!("../assets/approve.html");
    assert!(html.contains("startsWith('diff --git ')"));
    assert!(html.contains(".dfile"));
    assert!(html.contains("clean exports"));
    assert!(html.contains("candidate digest and the diff digest"));
}
