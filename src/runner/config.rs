// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
//! The runner's config file.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

fn default_log_days() -> u32 {
    30
}

fn default_schema_file() -> String {
    "shoephone-schema.toml".to_string()
}

/// Where a value comes from: written in the config, or resolved at run time
/// by `secret_command`. This holds config values and secret *references*,
/// never a resolved secret; resolved values live elsewhere (Task 15).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Value(String),
    Secret(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    /// Path of the Terraform root module inside the project's tree.
    pub path: String,
    pub terraform_version: String,
    #[serde(default)]
    pub backend_config: BTreeMap<String, Source>,
    #[serde(default)]
    pub env: BTreeMap<String, Source>,
    /// Runner-supplied variables. These must not overlap the project's
    /// schema; that is checked at trust time, once a schema exists.
    #[serde(default)]
    pub variables: BTreeMap<String, Source>,
    #[serde(default = "default_schema_file")]
    pub schema_file: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    pub name: String,
    pub daemon: String,
    pub key: PathBuf,
    pub state_dir: PathBuf,
    pub log_dir: PathBuf,
    #[serde(default = "default_log_days")]
    pub log_days: u32,
    pub terraform: PathBuf,
    pub plugin_dir: PathBuf,
    pub bwrap: PathBuf,
    pub review_user: String,
    pub terraform_user: String,
    /// Run with each reference appended as its last argument; the resolved
    /// value is its stdout, trimmed.
    pub secret_command: Vec<String>,
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectConfig>,
}

/// True for `^[A-Za-z0-9._-]{1,64}$`.
fn valid_project_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A relative path with no `..` and no root or prefix.
fn relative_and_contained(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
}

/// Like `relative_and_contained`, and the last component names a file or
/// directory, so `.` and `./` are refused.
fn names_a_child(path: &str) -> bool {
    relative_and_contained(path)
        && matches!(
            Path::new(path).components().next_back(),
            Some(Component::Normal(_))
        )
}

impl RunnerConfig {
    /// Read and validate the config. This checks only what the file itself
    /// contains. The overlap between a project's `variables` and its schema
    /// is checked at trust time, because no schema exists until then.
    pub fn from_file(path: &Path) -> Result<RunnerConfig, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let cfg: RunnerConfig =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        if self.secret_command.is_empty() || self.secret_command[0].is_empty() {
            return Err("secret_command must not be empty".to_string());
        }
        for (name, p) in &self.projects {
            if !valid_project_name(name) {
                return Err(format!(
                    "project name {name:?} must match ^[A-Za-z0-9._-]{{1,64}}$"
                ));
            }
            if !relative_and_contained(&p.path) {
                return Err(format!(
                    "project {name}: path {:?} must be relative with no '..'",
                    p.path
                ));
            }
            if !names_a_child(&p.schema_file) {
                return Err(format!(
                    "project {name}: schema_file {:?} must be relative with no '..'",
                    p.schema_file
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../contrib/runner/shoephone-runner.toml.example");

    fn parse(text: &str) -> Result<RunnerConfig, String> {
        let cfg: RunnerConfig = toml::from_str(text).map_err(|e| e.to_string())?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn config_parses_example() {
        let dir = std::env::temp_dir().join(format!("sp-runner-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("r.toml");
        std::fs::write(&file, EXAMPLE).unwrap();
        let cfg = RunnerConfig::from_file(&file).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(cfg.name, "runner-1");
        assert_eq!(cfg.log_days, 30);
        assert_eq!(cfg.secret_command.len(), 2);
        let p = &cfg.projects["example"];
        assert_eq!(p.schema_file, "shoephone-schema.toml");
        assert_eq!(
            p.variables["api_key"],
            Source::Secret("vault/item/api-key".to_string())
        );
        assert_eq!(
            p.variables["region"],
            Source::Value("example-region-1".to_string())
        );
    }

    #[test]
    fn config_refuses_unknown_field() {
        let bad = EXAMPLE.replace("log_days = 30", "log_days = 30\nsurprise = 1");
        assert!(parse(&bad).unwrap_err().contains("surprise"));
        let bad = EXAMPLE.replace("terraform_version", "terraform_versio");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn config_refuses_dot_project_names_and_dot_schema_file() {
        for name in [".", ".."] {
            let bad = EXAMPLE.replace("[projects.example]", &format!("[projects.\"{name}\"]"));
            assert!(parse(&bad).is_err(), "{name}");
        }
        let bad = EXAMPLE.replace("shoephone-schema.toml", ".");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn config_refuses_bad_names_paths_and_empty_secret_command() {
        let bad = EXAMPLE.replace("[projects.example]", "[projects.\"a/b\"]");
        assert!(parse(&bad).is_err());
        let bad = EXAMPLE.replace("infra/example", "../escape");
        assert!(parse(&bad).is_err());
        let bad = EXAMPLE.replace("infra/example", "/abs");
        assert!(parse(&bad).is_err());
        let bad = EXAMPLE.replace(
            "secret_command = [\"/usr/local/bin/secret-tool\", \"read\"]",
            "secret_command = []",
        );
        assert!(parse(&bad).unwrap_err().contains("secret_command"));
    }
}
