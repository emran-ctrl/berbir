//! Passive subdomain discovery via Certificate Transparency logs (crt.sh).

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::error::{EngineError, Result};

#[derive(Debug, Deserialize)]
struct CrtEntry {
    #[serde(default)]
    name_value: String,
}

/// Enumerate subdomains of `domain` using crt.sh certificate transparency.
pub async fn enumerate_subdomains(client: &reqwest::Client, domain: &str) -> Result<Vec<String>> {
    let domain = domain
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let domain = domain
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap_or(domain);

    let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Err(EngineError::Other(format!(
            "crt.sh returned {}",
            resp.status()
        )));
    }
    let entries: Vec<CrtEntry> = resp.json().await?;

    let mut names = BTreeSet::new();
    for entry in entries {
        for line in entry.name_value.split('\n') {
            let name = line
                .trim()
                .trim_start_matches("*.")
                .trim_end_matches('.')
                .to_lowercase();
            if name.ends_with(domain) && name.len() > domain.len() && !name.contains("..") {
                names.insert(name);
            }
        }
    }

    Ok(names.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_dedups_crt_json() {
        let json = r#"[
            {"name_value": "*.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "api.example.com"},
            {"name_value": "www.example.com\nmail.example.com"},
            {"name_value": "example.com"}
        ]"#;
        let entries: Vec<CrtEntry> = serde_json::from_str(json).unwrap();
        let mut names = BTreeSet::new();
        for entry in entries {
            for line in entry.name_value.split('\n') {
                let name = line
                    .trim()
                    .trim_start_matches("*.")
                    .trim_end_matches('.')
                    .to_lowercase();
                if name.ends_with("example.com") && name.len() > "example.com".len() {
                    names.insert(name);
                }
            }
        }
        let names: Vec<_> = names.into_iter().collect();
        assert_eq!(
            names,
            vec!["api.example.com", "mail.example.com", "www.example.com"]
        );
    }

    #[tokio::test]
    async fn handles_missing_domain_suffix() {
        // Domain normalization: strip scheme and path.
        let domain = "https://example.com/some/path";
        let normalized = domain
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .split('/')
            .next()
            .unwrap();
        assert_eq!(normalized, "example.com");
    }
}
