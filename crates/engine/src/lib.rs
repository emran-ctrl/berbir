//! The native scan engine: YAML signature templates, response matchers, an
//! async executor, passive subdomain discovery, and an optional RustScan port
//! scanner.

pub mod discovery;
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

/// Load every `*.yaml` template from a directory.
pub fn load_templates_from_dir(dir: impl AsRef<std::path::Path>) -> Result<Vec<Template>> {
    let mut templates = Vec::new();
    let mut entries = std::fs::read_dir(dir)?.collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
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
}
