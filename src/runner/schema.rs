// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The variable schema and the strict reader for the agent's manifest.
//!
//! The schema (`shoephone-schema.toml`) lives in the operator-trusted tree.
//! The manifest is hostile JSON from an agent. [`validate`] refuses anything
//! the schema does not describe and returns the [`Canonical`] text: the exact
//! bytes the approver's page and the daemon compare, key by key.
//!
//! Refusals name variables, never values. A `detail` is shown to the agent
//! unauthenticated, so none of these failures carries one that could echo
//! input.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::job::Failure;

/// Largest manifest accepted, checked before parsing.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Largest integer magnitude that survives a round trip through a JSON
/// double: 2^53 - 1.
const MAX_SAFE: i64 = 9_007_199_254_740_991;
const REGEX_LIMIT: usize = 1 << 20;
const DEFAULT_MAX_LEN: usize = 256;
const DEFAULT_MAX_ITEMS: usize = 64;

fn fail(category: &str, name: &str) -> Failure {
    Failure {
        category: category.to_string(),
        addresses: if name.is_empty() {
            Vec::new()
        } else {
            vec![name.to_string()]
        },
        detail: None,
    }
}

fn detailed(category: &str, name: &str, detail: &str) -> Failure {
    Failure {
        detail: Some(detail.to_string()),
        ..fail(category, name)
    }
}

/// A variable name is Terraform-safe and needs no escaping.
fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some('a'..='z' | '_'))
        && name.len() <= 64
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

/// An address for a name the agent chose: only one that is well-formed, so
/// hostile text never reaches the agent-visible failure.
fn agent_name(name: &str) -> &str {
    if is_valid_name(name) { name } else { "" }
}

// ---------------------------------------------------------------------
// Schema

/// A string constraint: exactly one of an anchored pattern or a choice list.
#[derive(Debug, Clone)]
enum Allowed {
    Pattern(Regex),
    Choices(Vec<String>),
}

impl Allowed {
    fn admits(&self, s: &str) -> bool {
        match self {
            Allowed::Pattern(re) => re.is_match(s),
            Allowed::Choices(c) => c.iter().any(|x| x == s),
        }
    }
}

#[derive(Debug, Clone)]
enum Kind {
    Str {
        allowed: Allowed,
        max_len: usize,
    },
    Number {
        min: Option<f64>,
        max: Option<f64>,
        integer: bool,
    },
    Bool,
    List {
        item: Allowed,
        max_len: usize,
        max_items: usize,
    },
}

#[derive(Debug, Clone)]
struct Variable {
    kind: Kind,
    default: Option<Val>,
}

/// A parsed `shoephone-schema.toml`.
#[derive(Debug, Clone)]
pub struct Schema {
    variables: BTreeMap<String, Variable>,
}

impl Schema {
    /// The variable names the schema declares.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.variables.keys().map(String::as_str)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSchema {
    #[serde(default)]
    variables: BTreeMap<String, RawVariable>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVariable {
    #[serde(rename = "type")]
    ty: String,
    pattern: Option<String>,
    choices: Option<Vec<String>>,
    item_pattern: Option<String>,
    item_choices: Option<Vec<String>>,
    max_len: Option<usize>,
    max_items: Option<usize>,
    min: Option<toml::Value>,
    max: Option<toml::Value>,
    integer: Option<bool>,
    default: Option<toml::Value>,
}

fn invalid(name: &str, why: &str) -> Failure {
    detailed("schema_invalid", name, why)
}

fn compile(name: &str, pattern: &str) -> Result<Allowed, Failure> {
    let build = |src: &str| {
        RegexBuilder::new(src)
            .size_limit(REGEX_LIMIT)
            .dfa_size_limit(REGEX_LIMIT)
            .build()
    };
    let bad = || invalid(name, "pattern does not compile");
    // The bare pattern must compile on its own, so an unbalanced `)` cannot
    // close the anchor group and let an alternation escape it.
    build(pattern).map_err(|_| bad())?;
    // Anchored so a pattern always judges the whole value. The pattern text
    // and the compiler's message are not repeated: the failure is shown to
    // the agent.
    build(&format!(r"\A(?:{pattern})\z"))
        .map(Allowed::Pattern)
        .map_err(|_| bad())
}

fn allowed(
    name: &str,
    pattern: Option<&String>,
    choices: Option<&Vec<String>>,
) -> Result<Allowed, Failure> {
    match (pattern, choices) {
        (Some(p), None) => compile(name, p),
        (None, Some(c)) if !c.is_empty() && !c.iter().any(|s| s.chars().any(is_forbidden)) => {
            Ok(Allowed::Choices(c.clone()))
        }
        _ => Err(invalid(name, "needs exactly one non-empty constraint")),
    }
}

fn toml_number(name: &str, v: Option<&toml::Value>) -> Result<Option<f64>, Failure> {
    match v {
        None => Ok(None),
        Some(toml::Value::Integer(i)) if i.unsigned_abs() <= MAX_SAFE as u64 => Ok(Some(*i as f64)),
        Some(toml::Value::Float(f)) if f.is_finite() && f.abs() <= MAX_SAFE as f64 => Ok(Some(*f)),
        _ => Err(invalid(name, "min and max must be safe numbers")),
    }
}

fn toml_default(name: &str, v: &toml::Value) -> Result<Val, Failure> {
    Ok(normalize(match v {
        toml::Value::String(s) => Val::Str(s.clone()),
        toml::Value::Boolean(b) => Val::Bool(*b),
        toml::Value::Integer(i) => Val::Int(*i),
        toml::Value::Float(f) => Val::Float(*f),
        toml::Value::Array(a) => Val::Arr(
            a.iter()
                .map(|x| toml_default(name, x))
                .collect::<Result<_, _>>()?,
        ),
        _ => return Err(invalid(name, "default has an unsupported type")),
    }))
}

/// Equal numbers must render as equal bytes: an integral value within the
/// safe range becomes an integer (`1.0`, `1e0` and `-0.0` all become an
/// integer), and everything else is left as it is.
fn normalize(v: Val) -> Val {
    match v {
        Val::UInt(u) if u <= MAX_SAFE as u64 => Val::Int(u as i64),
        Val::Float(f) if f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE as f64 => {
            Val::Int(f as i64)
        }
        other => other,
    }
}

fn build_variable(name: &str, raw: &RawVariable) -> Result<Variable, Failure> {
    let stray_string = raw.pattern.is_some() || raw.choices.is_some();
    let stray_list = raw.item_pattern.is_some() || raw.item_choices.is_some();
    let stray_number = raw.min.is_some() || raw.max.is_some() || raw.integer.is_some();
    let kind = match raw.ty.as_str() {
        "string" => {
            if stray_list || stray_number || raw.max_items.is_some() {
                return Err(invalid(name, "key does not apply to a string"));
            }
            Kind::Str {
                allowed: allowed(name, raw.pattern.as_ref(), raw.choices.as_ref())?,
                max_len: raw.max_len.unwrap_or(DEFAULT_MAX_LEN),
            }
        }
        "number" => {
            if stray_string || stray_list || raw.max_len.is_some() || raw.max_items.is_some() {
                return Err(invalid(name, "key does not apply to a number"));
            }
            let (min, max) = (
                toml_number(name, raw.min.as_ref())?,
                toml_number(name, raw.max.as_ref())?,
            );
            if min.zip(max).is_some_and(|(lo, hi)| lo > hi) {
                return Err(invalid(name, "min is greater than max"));
            }
            Kind::Number {
                min,
                max,
                integer: raw.integer.unwrap_or(false),
            }
        }
        "bool" => {
            if stray_string
                || stray_list
                || stray_number
                || raw.max_len.is_some()
                || raw.max_items.is_some()
            {
                return Err(invalid(name, "key does not apply to a bool"));
            }
            Kind::Bool
        }
        "list_of_strings" => {
            if stray_string || stray_number {
                return Err(invalid(name, "key does not apply to a list"));
            }
            if raw.max_items == Some(0) {
                return Err(invalid(name, "max_items must be at least 1"));
            }
            Kind::List {
                item: allowed(name, raw.item_pattern.as_ref(), raw.item_choices.as_ref())?,
                max_len: raw.max_len.unwrap_or(DEFAULT_MAX_LEN),
                max_items: raw.max_items.unwrap_or(DEFAULT_MAX_ITEMS),
            }
        }
        _ => return Err(invalid(name, "unknown type")),
    };
    let mut var = Variable {
        kind,
        default: None,
    };
    if let Some(d) = &raw.default {
        let d = toml_default(name, d)?;
        // A default must satisfy its own variable, or a manifest that omits
        // it would pass through a value the schema forbids.
        check(name, &var.kind, &d).map_err(|_| invalid(name, "default violates the variable"))?;
        var.default = Some(d);
    }
    Ok(var)
}

/// Parse and validate a schema. Any problem is `schema_invalid`, naming the
/// variable when there is one.
pub fn parse_schema(text: &str) -> Result<Schema, Failure> {
    let raw: RawSchema =
        toml::from_str(text).map_err(|_| invalid("", "schema is not valid for this version"))?;
    let mut variables = BTreeMap::new();
    for (name, rv) in &raw.variables {
        if !is_valid_name(name) {
            return Err(invalid("", "a variable name is not allowed"));
        }
        variables.insert(name.clone(), build_variable(name, rv)?);
    }
    Ok(Schema { variables })
}

/// The schema's variable names must not appear in the runner's own
/// `variables` for the project.
pub fn disjoint(schema: &Schema, runner_vars: &BTreeSet<String>) -> Result<(), Failure> {
    let overlap: Vec<String> = schema
        .variables
        .keys()
        .filter(|k| runner_vars.contains(*k))
        .cloned()
        .collect();
    if overlap.is_empty() {
        Ok(())
    } else {
        Err(Failure {
            category: "schema_overlaps_runner_variables".to_string(),
            addresses: overlap,
            detail: None,
        })
    }
}

// ---------------------------------------------------------------------
// Manifest values

/// A JSON value as the strict reader sees it. Integers stay integers.
#[derive(Debug, Clone, PartialEq)]
enum Val {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
    Arr(Vec<Val>),
    Obj(Vec<(String, Val)>),
}

thread_local! {
    /// The key a duplicate-key refusal was raised for, set by the visitor.
    static DUPLICATE: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

struct ValVisitor;

impl<'de> Visitor<'de> for ValVisitor {
    type Value = Val;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Val, E> {
        Ok(Val::Null)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Val, E> {
        Ok(Val::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Val, E> {
        Ok(Val::Int(v))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Val, E> {
        Ok(Val::UInt(v))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Val, E> {
        Ok(Val::Float(v))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Val, E> {
        Ok(Val::Str(v.to_string()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Val, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element::<Val>()? {
            out.push(v);
        }
        Ok(Val::Arr(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Val, A::Error> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                DUPLICATE.with(|d| *d.borrow_mut() = Some(key));
                return Err(de::Error::custom("duplicate key"));
            }
            out.push((key, map.next_value::<Val>()?));
        }
        Ok(Val::Obj(out))
    }
}

impl<'de> Deserialize<'de> for Val {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Val, D::Error> {
        d.deserialize_any(ValVisitor)
    }
}

// ---------------------------------------------------------------------
// Checking a value against a variable

/// Control characters and the bidi or invisible set. Any of these can make
/// the approver's page show something other than what Terraform receives.
fn is_forbidden(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001F}'
        | '\u{007F}'..='\u{009F}'
        | '\u{061C}'
        | '\u{00AD}'
        | '\u{200B}'..='\u{200F}'
        | '\u{2028}'..='\u{202E}'
        | '\u{2060}'
        | '\u{2066}'..='\u{2069}'
        | '\u{FEFF}'
        | '\u{034F}'
        | '\u{115F}'
        | '\u{180E}'
        | '\u{3164}'
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0000}'..='\u{E007F}')
}

fn check_string(name: &str, a: &Allowed, max_len: usize, s: &str) -> Result<(), Failure> {
    if s.chars().any(is_forbidden) || s.chars().count() > max_len || !a.admits(s) {
        return Err(fail("manifest_constraint", name));
    }
    Ok(())
}

fn check(name: &str, kind: &Kind, v: &Val) -> Result<(), Failure> {
    let type_err = || fail("manifest_type", name);
    match (kind, v) {
        (Kind::Str { allowed, max_len }, Val::Str(s)) => check_string(name, allowed, *max_len, s),
        (Kind::Bool, Val::Bool(_)) => Ok(()),
        (Kind::Number { min, max, integer }, Val::Int(_) | Val::UInt(_) | Val::Float(_)) => {
            let n = match v {
                Val::Int(i) if i.unsigned_abs() <= MAX_SAFE as u64 => *i as f64,
                Val::UInt(u) if *u <= MAX_SAFE as u64 => *u as f64,
                Val::Float(f) if f.is_finite() && f.abs() <= MAX_SAFE as f64 => *f,
                _ => return Err(type_err()),
            };
            if *integer && matches!(v, Val::Float(_)) {
                return Err(fail("manifest_constraint", name));
            }
            if min.is_some_and(|m| n < m) || max.is_some_and(|m| n > m) {
                return Err(fail("manifest_constraint", name));
            }
            Ok(())
        }
        (
            Kind::List {
                item,
                max_len,
                max_items,
            },
            Val::Arr(items),
        ) => {
            if items.len() > *max_items {
                return Err(fail("manifest_constraint", name));
            }
            for it in items {
                match it {
                    Val::Str(s) => check_string(name, item, *max_len, s)?,
                    _ => return Err(type_err()),
                }
            }
            Ok(())
        }
        _ => Err(type_err()),
    }
}

// ---------------------------------------------------------------------
// Canonical form

/// The canonical manifest text: a JSON object with keys sorted by code
/// point, no whitespace, and every schema variable present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical(pub String);

fn render(v: &Val, out: &mut String) {
    match v {
        Val::Null => out.push_str("null"),
        Val::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Val::Int(i) => out.push_str(&i.to_string()),
        Val::UInt(u) => out.push_str(&u.to_string()),
        Val::Float(f) => {
            out.push_str(&serde_json::to_string(f).expect("a checked float is finite"))
        }
        Val::Str(s) => out.push_str(&serde_json::to_string(s).expect("a string serializes")),
        Val::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                render(x, out);
            }
            out.push(']');
        }
        Val::Obj(_) => unreachable!("objects never pass a type check"),
    }
}

/// Validate the agent's manifest against the schema and return its
/// canonical form.
pub fn validate(schema: &Schema, manifest: &str) -> Result<Canonical, Failure> {
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(fail("manifest_too_large", ""));
    }
    DUPLICATE.with(|d| *d.borrow_mut() = None);
    let top = match serde_json::from_str::<Val>(manifest) {
        Ok(Val::Obj(entries)) => entries,
        Ok(_) => return Err(detailed("manifest_type", "", "manifest is not an object")),
        Err(_) => {
            if let Some(key) = DUPLICATE.with(|d| d.borrow_mut().take()) {
                return Err(fail("manifest_duplicate_key", agent_name(&key)));
            }
            return Err(detailed("manifest_type", "", "manifest is not valid JSON"));
        }
    };
    let mut given: BTreeMap<&str, &Val> = BTreeMap::new();
    for (k, v) in &top {
        if !schema.variables.contains_key(k) {
            return Err(fail("manifest_unknown_variable", agent_name(k)));
        }
        given.insert(k, v);
    }
    let mut out = String::from("{");
    for (i, (name, var)) in schema.variables.iter().enumerate() {
        let v = match (given.get(name.as_str()), &var.default) {
            (Some(v), _) => normalize((*v).clone()),
            (None, Some(d)) => d.clone(),
            (None, None) => return Err(fail("manifest_missing", name)),
        };
        check(name, &var.kind, &v)?;
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(name);
        out.push_str("\":");
        render(&v, &mut out);
    }
    out.push('}');
    Ok(Canonical(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = r#"
[variables.region]
type = "string"
pattern = "[a-z]{2}-[a-z]+-[0-9]"

[variables.size]
type = "string"
choices = ["small", "large"]
default = "small"

[variables.count]
type = "number"
min = 1
max = 10
integer = true

[variables.debug]
type = "bool"
default = false

[variables.zones]
type = "list_of_strings"
item_pattern = "[a-z]"
max_items = 3
default = []
"#;

    fn schema() -> Schema {
        parse_schema(SCHEMA).unwrap()
    }

    fn refusal(manifest: &str) -> Failure {
        validate(&schema(), manifest).unwrap_err()
    }

    const OK: &str = r#"{"region":"us-east-1","count":3}"#;

    #[test]
    fn unknown_key_is_refused() {
        let f = refusal(r#"{"region":"us-east-1","count":3,"evil":1}"#);
        assert_eq!(f.category, "manifest_unknown_variable");
        assert_eq!(f.addresses, vec!["evil".to_string()]);
    }

    #[test]
    fn duplicate_key_is_refused() {
        let f = refusal(r#"{"region":"us-east-1","count":3,"count":4}"#);
        assert_eq!(f.category, "manifest_duplicate_key");
        assert_eq!(f.addresses, vec!["count".to_string()]);
    }

    #[test]
    fn string_number_is_not_coerced() {
        let f = refusal(r#"{"region":"us-east-1","count":"3"}"#);
        assert_eq!(f.category, "manifest_type");
        assert_eq!(f.addresses, vec!["count".to_string()]);
    }

    #[test]
    fn pattern_mismatch_names_variable_not_value() {
        let f = refusal(r#"{"region":"SECRET-VALUE","count":3}"#);
        assert_eq!(f.category, "manifest_constraint");
        assert_eq!(f.addresses, vec!["region".to_string()]);
        assert!(!format!("{f:?}").contains("SECRET"));
    }

    #[test]
    fn pattern_is_anchored() {
        let f = refusal(r#"{"region":"xx us-east-1 xx","count":3}"#);
        assert_eq!(f.category, "manifest_constraint");
    }

    #[test]
    fn choices_enforced() {
        let f = refusal(r#"{"region":"us-east-1","count":3,"size":"huge"}"#);
        assert_eq!(f.category, "manifest_constraint");
        assert_eq!(f.addresses, vec!["size".to_string()]);
        assert!(
            validate(
                &schema(),
                r#"{"region":"us-east-1","count":3,"size":"large"}"#
            )
            .is_ok()
        );
    }

    #[test]
    fn list_item_pattern_enforced() {
        let f = refusal(r#"{"region":"us-east-1","count":3,"zones":["a","B"]}"#);
        assert_eq!(f.category, "manifest_constraint");
        assert_eq!(f.addresses, vec!["zones".to_string()]);
        let f = refusal(r#"{"region":"us-east-1","count":3,"zones":["a","b","c","d"]}"#);
        assert_eq!(f.category, "manifest_constraint");
    }

    #[test]
    fn missing_without_default_is_refused() {
        let f = refusal(r#"{"region":"us-east-1"}"#);
        assert_eq!(f.category, "manifest_missing");
        assert_eq!(f.addresses, vec!["count".to_string()]);
    }

    #[test]
    fn canonical_is_sorted_and_compact() {
        let c = validate(
            &schema(),
            r#" { "count" : 3 , "region" : "us-east-1", "zones": ["b","a"] } "#,
        )
        .unwrap();
        assert_eq!(
            c.0,
            r#"{"count":3,"debug":false,"region":"us-east-1","size":"small","zones":["b","a"]}"#
        );
    }

    #[test]
    fn overlap_with_runner_variables_is_refused() {
        let mut runner = BTreeSet::new();
        runner.insert("api_key".to_string());
        assert!(disjoint(&schema(), &runner).is_ok());
        runner.insert("count".to_string());
        let f = disjoint(&schema(), &runner).unwrap_err();
        assert_eq!(f.category, "schema_overlaps_runner_variables");
        assert_eq!(f.addresses, vec!["count".to_string()]);
    }

    #[test]
    fn numbers_keep_integers_and_refuse_unsafe_values() {
        let s = parse_schema("[variables.n]\ntype = \"number\"\n").unwrap();
        assert_eq!(
            validate(&s, r#"{"n":9007199254740991}"#).unwrap().0,
            r#"{"n":9007199254740991}"#
        );
        assert_eq!(validate(&s, r#"{"n":-3}"#).unwrap().0, r#"{"n":-3}"#);
        assert_eq!(validate(&s, r#"{"n":1.5}"#).unwrap().0, r#"{"n":1.5}"#);
        for bad in [
            r#"{"n":9007199254740992}"#,
            r#"{"n":1e999}"#,
            r#"{"n":1e300}"#,
        ] {
            assert_eq!(
                validate(&s, bad).unwrap_err().category,
                "manifest_type",
                "{bad}"
            );
        }
        let si = parse_schema("[variables.n]\ntype = \"number\"\ninteger = true\n").unwrap();
        assert!(validate(&si, r#"{"n":1.5}"#).is_err());
    }

    #[test]
    fn hostile_strings_are_refused() {
        let s = parse_schema("[variables.s]\ntype = \"string\"\npattern = \".*\"\n").unwrap();
        for esc in [
            "\\u0000",
            "\\n",
            "\\u007f",
            "\\u0085",
            "\\u00ad",
            "\\u061c",
            "\\u200b",
            "\\u200f",
            "\\u2028",
            "\\u202e",
            "\\u2060",
            "\\u2066",
            "\\u2069",
            "\\ufeff",
            "\\udb40\\udc01",
        ] {
            let bad = format!("{{\"s\":\"a{esc}b\"}}");
            assert_eq!(
                validate(&s, &bad).unwrap_err().category,
                "manifest_constraint",
                "{bad}"
            );
        }
        assert!(validate(&s, "{\"s\":\"caf\\u00e9 \\\"q\\\"\"}").is_ok());
    }

    #[test]
    fn size_depth_and_shape() {
        let big = format!(r#"{{"region":"{}"}}"#, "a".repeat(70_000));
        assert_eq!(refusal(&big).category, "manifest_too_large");
        assert_eq!(refusal("[1]").category, "manifest_type");
        assert_eq!(refusal("not json").category, "manifest_type");
        assert_eq!(
            refusal(r#"{"region":{"a":1},"count":3}"#).category,
            "manifest_type"
        );
        let deep = format!("{}1{}", "[".repeat(500), "]".repeat(500));
        assert_eq!(
            refusal(&format!(r#"{{"region":{deep},"count":3}}"#)).category,
            "manifest_type"
        );
        assert_eq!(
            refusal(r#"{"region":"us-east-1","count":3,"debug":"no"}"#).category,
            "manifest_type"
        );
        let long = format!(
            r#"{{"region":"us-east-1","count":3,"size":"{}"}}"#,
            "a".repeat(300)
        );
        assert_eq!(refusal(&long).category, "manifest_constraint");
        assert!(validate(&schema(), OK).is_ok());
    }

    #[test]
    fn bad_schemas_are_refused() {
        for bad in [
            "[variables.Bad]\ntype = \"bool\"\n",
            "[variables.a-b]\ntype = \"bool\"\n",
            "[variables.s]\ntype = \"string\"\n",
            "[variables.s]\ntype = \"string\"\npattern = \"a\"\nchoices = [\"a\"]\n",
            "[variables.s]\ntype = \"string\"\npattern = \"(\"\n",
            "[variables.s]\ntype = \"string\"\npattern = \"a\"\ndefault = \"b\"\n",
            "[variables.b]\ntype = \"bool\"\nmin = 1\n",
            "[variables.b]\ntype = \"bool\"\ndefault = 1\n",
            "[variables.b]\ntype = \"nope\"\n",
            "extra = 1\n",
            "this is not toml",
        ] {
            let f = parse_schema(bad).unwrap_err();
            assert_eq!(f.category, "schema_invalid", "{bad}");
        }
    }

    #[test]
    fn equal_numbers_render_identically() {
        let s = parse_schema("[variables.n]\ntype = \"number\"\n").unwrap();
        for m in ["1", "1.0", "1e0", "10e-1"] {
            let c = validate(&s, &format!("{{\"n\":{m}}}")).unwrap();
            assert_eq!(c.0, "{\"n\":1}", "{m}");
        }
        for m in ["-0", "-0.0", "0"] {
            let c = validate(&s, &format!("{{\"n\":{m}}}")).unwrap();
            assert_eq!(c.0, "{\"n\":0}", "{m}");
        }
        assert_eq!(validate(&s, "{\"n\":1.5}").unwrap().0, "{\"n\":1.5}");
        let si = parse_schema("[variables.n]\ntype = \"number\"\ninteger = true\n").unwrap();
        assert_eq!(validate(&si, "{\"n\":2.0}").unwrap().0, "{\"n\":2}");
        assert!(validate(&si, "{\"n\":2.5}").is_err());
        let d = parse_schema("[variables.n]\ntype = \"number\"\ndefault = 3.0\n").unwrap();
        assert_eq!(validate(&d, "{}").unwrap().0, "{\"n\":3}");
    }

    #[test]
    fn i64_min_and_escaping_patterns_are_refused() {
        let s = parse_schema("[variables.n]\ntype = \"number\"\n").unwrap();
        let f = validate(&s, "{\"n\":-9223372036854775808}").unwrap_err();
        assert_eq!(f.category, "manifest_type");
        for bad in [
            "[variables.n]\ntype = \"number\"\ndefault = -9223372036854775808\n",
            "[variables.n]\ntype = \"number\"\nmin = -9223372036854775808\n",
            "[variables.s]\ntype = \"string\"\npattern = \"a)|(.*\"\n",
            "[variables.n]\ntype = \"number\"\nmin = 5\nmax = 1\n",
            "[variables.l]\ntype = \"list_of_strings\"\nitem_pattern = \"a\"\nmax_items = 0\n",
            "[variables.s]\ntype = \"string\"\nchoices = [\"a\\u200bb\"]\n",
            "[variables.l]\ntype = \"list_of_strings\"\nitem_choices = [\"a\\ufe0f\"]\n",
        ] {
            assert_eq!(
                parse_schema(bad).unwrap_err().category,
                "schema_invalid",
                "{bad}"
            );
        }
    }

    #[test]
    fn more_invisible_characters_are_refused() {
        let s = parse_schema("[variables.s]\ntype = \"string\"\npattern = \".*\"\n").unwrap();
        for esc in [
            "\\u034f", "\\u115f", "\\u180e", "\\u3164", "\\ufe0f", "\\ufff9", "\\ufffb",
        ] {
            let bad = format!("{{\"s\":\"a{esc}b\"}}");
            assert_eq!(
                validate(&s, &bad).unwrap_err().category,
                "manifest_constraint",
                "{bad}"
            );
        }
    }
}
