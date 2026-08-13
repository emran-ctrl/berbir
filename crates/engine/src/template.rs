//! Vulnerability template schema, deserialized from YAML.

use serde::{Deserialize, Serialize};

use crate::error::{EngineError, Result};

/// A full vulnerability signature (Nuclei-inspired, minimal subset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub info: Info,
    #[serde(default)]
    pub http: Vec<HttpStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub name: String,
    #[serde(default = "default_severity")]
    pub severity: String,
}

fn default_severity() -> String {
    "info".to_string()
}

/// One HTTP request sequence within a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpStep {
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
}

fn default_method() -> String {
    "GET".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// A single match rule against a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(rename = "type")]
    pub mtype: MatcherType,
    #[serde(default)]
    pub part: Part,
    #[serde(default)]
    pub words: Vec<String>,
    #[serde(default)]
    pub regex: Vec<String>,
    #[serde(default)]
    pub status: Vec<u16>,
    /// `or` (any) or `and` (all) across `words`. Defaults to `or`.
    #[serde(default)]
    pub condition: Condition,
    /// Invert the result (matches when the condition does NOT hold).
    #[serde(default)]
    pub negative: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatcherType {
    #[default]
    Word,
    Regex,
    Status,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    #[default]
    Body,
    Header,
    #[serde(rename = "status_code")]
    Status,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    #[default]
    Or,
    And,
}

impl Template {
    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        let t: Template = serde_yaml::from_str(yaml).map_err(EngineError::Template)?;
        if t.id.is_empty() {
            return Err(EngineError::InvalidTemplate(
                "template id must not be empty".into(),
            ));
        }
        Ok(t)
    }
}
