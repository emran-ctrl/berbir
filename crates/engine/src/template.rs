//! Vulnerability template schema, deserialized from YAML.
//!
//! The schema intentionally mirrors the Nuclei HTTP template format
//! (https://github.com/projectdiscovery/nuclei-templates) for the supported
//! subset. Unknown `type:`/`part:` matcher values are tolerated and the
//! affected matcher is dropped, so a single exotic matcher never rejects a
//! whole template file.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{EngineError, Result};

/// A full vulnerability signature (Nuclei-compatible HTTP subset).
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

/// One HTTP request within a template. Extra Nuclei keys (`raw`,
/// `redirects`, `max-size`, `payloads`, `extractors`, …) are ignored, which
/// keeps templates loadable even when only part of the feature set is run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpStep {
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub path: Vec<String>,
    /// Header map (`Key: Value`) as written in real templates.
    #[serde(default, deserialize_with = "deserialize_headers")]
    pub headers: Vec<Header>,
    /// Request body for POST/PUT requests.
    #[serde(default)]
    pub body: Option<String>,
    /// Raw `Cookie:` header value.
    #[serde(default)]
    pub cookie: Option<String>,
    /// How the step's matchers combine. Nuclei defaults to `or`.
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Condition,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Accept both Nuclei's header map (`Key: Value`), a list of `Key: Value`
/// strings, and a list of `{name, value}` pairs. Map values may be any YAML
/// scalar (numbers, booleans), not just strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum HeadersInput {
    Map(HashMap<String, serde_yaml::Value>),
    List(Vec<Header>),
    Strings(Vec<String>),
}

fn deserialize_headers<'de, D>(deserializer: D) -> std::result::Result<Vec<Header>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let input = HeadersInput::deserialize(deserializer)?;
    Ok(match input {
        HeadersInput::Map(map) => map
            .into_iter()
            .map(|(name, value)| Header {
                name,
                value: scalar_to_string(value),
            })
            .collect(),
        HeadersInput::List(list) => list,
        HeadersInput::Strings(list) => list
            .into_iter()
            .map(|s| {
                let (name, value) = s.split_once(':').unwrap_or((s.as_str(), ""));
                Header {
                    name: name.trim().to_string(),
                    value: value.trim().to_string(),
                }
            })
            .collect(),
    })
}

fn scalar_to_string(v: serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s,
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Null => String::new(),
        other => format!("{other:?}"),
    }
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
    /// DSL expressions for `type: dsl` matchers.
    #[serde(default)]
    pub dsl: Vec<String>,
    /// `or` (any) or `and` (all) across `words`/`regex`/`dsl`. Defaults to `or`.
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
    Dsl,
    /// Any other Nuclei matcher type (`binary`, `xpath`, `quality`, `size`, …)
    /// we don't implement. Matchers of this kind are dropped at load time.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    #[default]
    Body,
    Header,
    #[serde(rename = "status_code")]
    Status,
    All,
    /// Unsupported part values (`request`, `response`, `binary`, …). The
    /// matcher is dropped at load time.
    #[serde(other)]
    Unknown,
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
        let mut t: Template = serde_yaml::from_str(yaml).map_err(EngineError::Template)?;
        if t.id.is_empty() {
            return Err(EngineError::InvalidTemplate(
                "template id must not be empty".into(),
            ));
        }
        for step in &mut t.http {
            let before = step.matchers.len();
            step.matchers.retain(|m| {
                matches!(
                    m.mtype,
                    MatcherType::Word | MatcherType::Regex | MatcherType::Status | MatcherType::Dsl
                ) && !matches!(m.part, Part::Unknown)
            });
            if step.matchers.len() != before {
                tracing::warn!(
                    "template {} dropped {} unsupported matcher(s)",
                    t.id,
                    before - step.matchers.len()
                );
            }
        }
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_accept_list_of_strings() {
        let t = Template::from_yaml_str(
            r#"
id: headers-string-list
info:
  name: Headers as list of strings
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    headers:
      - "X-Custom: hello"
      - "X-Empty:"
    matchers:
      - type: status
        status: [200]
"#,
        )
        .expect("should parse");
        let headers = &t.http[0].headers;
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].name, "X-Custom");
        assert_eq!(headers[0].value, "hello");
        assert_eq!(headers[1].name, "X-Empty");
        assert_eq!(headers[1].value, "");
    }

    #[test]
    fn headers_accept_map_and_pairs() {
        let t = Template::from_yaml_str(
            r#"
id: headers-map
info:
  name: Headers as map
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    headers:
      X-Custom: hello
    matchers:
      - type: word
        words: ["ok"]
"#,
        )
        .expect("should parse");
        assert_eq!(t.http[0].headers[0].name, "X-Custom");
    }

    #[test]
    fn headers_accept_numeric_map_values() {
        let t = Template::from_yaml_str(
            r#"
id: headers-numeric
info:
  name: Headers with numeric values
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    headers:
      X-Version: 3
      X-Enabled: true
    matchers:
      - type: word
        words: ["ok"]
"#,
        )
        .expect("should parse");
        let headers = &t.http[0].headers;
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].name, "X-Version");
        assert_eq!(headers[0].value, "3");
        assert_eq!(headers[1].name, "X-Enabled");
        assert_eq!(headers[1].value, "true");
    }
}
