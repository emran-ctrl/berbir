//! The native scan engine: YAML signature templates, response matchers, an
//! async executor, passive subdomain discovery, and an optional RustScan port
//! scanner.

pub mod discovery;
pub mod dsl;
pub mod error;
pub mod matcher;
pub mod port_scanner;
pub mod scanner;
pub mod template;

pub use error::{EngineError, Result};
pub use matcher::Response;
pub use scanner::Scanner;
pub use template::Template;

const BUILTIN_TEMPLATES: &[&str] = &[
    include_str!("../templates/env-exposure.yaml"),
    include_str!("../templates/git-exposure.yaml"),
    include_str!("../templates/backup-files.yaml"),
    include_str!("../templates/debug-endpoint.yaml"),
    include_str!("../templates/security-headers.yaml"),
    include_str!("../templates/admin-paths.yaml"),
];

/// Templates compiled into the binary.
pub fn builtin_templates() -> Result<Vec<Template>> {
    BUILTIN_TEMPLATES
        .iter()
        .map(|yaml| Template::from_yaml_str(yaml))
        .collect()
}

/// Load every `*.yaml` template under a directory, recursing into subfolders.
pub fn load_templates_from_dir(dir: impl AsRef<std::path::Path>) -> Result<Vec<Template>> {
    let dir = dir.as_ref();
    let mut templates = Vec::new();
    if !dir.is_dir() {
        return Err(EngineError::Other(format!(
            "not a directory: {}",
            dir.display()
        )));
    }
    let mut entries = std::fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            templates.extend(load_templates_from_dir(&path)?);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let contents = std::fs::read_to_string(&path)?;
        match Template::from_yaml_str(&contents) {
            Ok(t) => templates.push(t),
            Err(e) => tracing::warn!("skipping {}: {e}", path.display()),
        }
    }
    Ok(templates)
}

/// Build the full template registry: built-ins first, then templates from an
/// optional directory. Duplicate `id`s are replaced by the later entry (so a
/// user-provided template can supersede a bundled one) with a warning.
pub fn load_template_registry(extra_dir: Option<&std::path::Path>) -> Result<Vec<Template>> {
    let mut registry = builtin_templates()?;
    if let Some(dir) = extra_dir {
        for t in load_templates_from_dir(dir)? {
            if let Some(existing) = registry.iter().position(|r| r.id == t.id) {
                tracing::warn!(
                    "template id '{}' already registered; replacing previous entry",
                    t.id
                );
                registry[existing] = t;
            } else {
                registry.push(t);
            }
        }
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_templates_parse() {
        let templates = builtin_templates().expect("builtins should parse");
        assert!(templates.len() >= 6);
        for t in &templates {
            assert!(!t.id.is_empty());
            assert!(!t.info.name.is_empty());
            assert!(!t.http.is_empty());
            for step in &t.http {
                assert!(!step.path.is_empty());
            }
        }
    }

    #[test]
    fn registry_replaces_duplicate_ids() {
        let dir = std::env::temp_dir().join(format!("berbir-registry-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(dir.join("nested")).unwrap();

        std::fs::write(
            dir.join("a.yaml"),
            "id: git-directory-exposure\ninfo:\n  name: Replacement\n  severity: low\nhttp:\n  - path: ['{{BaseURL}}/x']\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("nested/b.yaml"),
            "id: nested-extra\ninfo:\n  name: Nested\n  severity: info\nhttp:\n  - path: ['{{BaseURL}}/y']\n",
        )
        .unwrap();

        let registry = load_template_registry(Some(&dir)).unwrap();
        let git = registry
            .iter()
            .find(|t| t.id == "git-directory-exposure")
            .unwrap();
        assert_eq!(git.info.name, "Replacement");
        assert!(registry.iter().any(|t| t.id == "nested-extra"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn real_git_config_template_parses() {
        // A genuine Nuclei template exercising dsl matchers, matchers-condition,
        // extractors and a header-less request. Must load despite unsupported
        // pieces (extractors are ignored, dsl is supported).
        let yaml = r#"
id: git-config

info:
  name: Git Configuration - Detect
  author: pdteam,pikpikcu,Mah3Sec_,m4lwhere
  severity: medium
  description: Git configuration was detected via the pattern /.git/config and log file on passed URLs.
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
    cvss-score: 5.3
    cwe-id: CWE-200
  metadata:
    max-request: 1
  tags: config,git,exposure,vuln

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "[credentials]"
          - "[core]"
        condition: or

      - type: dsl
        dsl:
          - "!contains(tolower(body), '<html')"
          - "!contains(tolower(body), '<body')"
        condition: and

      - type: status
        status:
          - 200

    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "url ?= ?https?://(.*:.*)@"
"#;
        let t = Template::from_yaml_str(yaml).expect("real template should load");
        assert_eq!(t.id, "git-config");
        assert_eq!(t.info.severity, "medium");
        let step = &t.http[0];
        assert_eq!(step.matchers.len(), 3);
        assert_eq!(step.matchers_condition, template::Condition::And);
        assert_eq!(step.matchers[1].mtype, template::MatcherType::Dsl);
        assert_eq!(step.matchers[1].dsl.len(), 2);
    }
}
