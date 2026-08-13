//! Passive subdomain discovery via Certificate Transparency logs (crt.sh).

use std::collections::BTreeSet;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{EngineError, Result};

const MAX_ATTEMPTS: usize = 3;
const BACKOFF: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(2)];

#[derive(Debug, Deserialize)]
struct CrtEntry {
    #[serde(default)]
    name_value: String,
}

/// Enumerate subdomains of `domain` using crt.sh certificate transparency.
///
/// Retries transient failures (5xx, 429, network errors) with short backoff,
/// since crt.sh is frequently overloaded. Returns an error only after all
/// attempts are exhausted.
pub async fn enumerate_subdomains(client: &reqwest::Client, domain: &str) -> Result<Vec<String>> {
    let domain = normalize_domain(domain);
    let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
    fetch_subdomains(client, &url, domain).await
}

/// Retry-aware fetch of a CT JSON endpoint. Shared by the crt.sh entry point
/// and the local-server retry test.
async fn fetch_subdomains(
    client: &reqwest::Client,
    url: &str,
    domain: &str,
) -> Result<Vec<String>> {
    let mut last_status = None;
    for attempt in 0..MAX_ATTEMPTS {
        let resp = match client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) if e.is_timeout() || e.is_connect() || e.is_request() => {
                // Transient transport error; retry unless it's our last shot.
                if attempt + 1 == MAX_ATTEMPTS {
                    return Err(EngineError::Http(e));
                }
                sleep_backoff(attempt).await;
                continue;
            }
            Err(e) => return Err(EngineError::Http(e)),
        };

        let status = resp.status();
        if status.is_success() {
            let entries: Vec<CrtEntry> = resp.json().await?;
            return Ok(extract_names(entries, domain));
        }
        if !is_retryable(status) || attempt + 1 == MAX_ATTEMPTS {
            return Err(EngineError::Other(format!(
                "crt.sh returned {status} after {MAX_ATTEMPTS} attempts"
            )));
        }

        last_status = Some(status);
        sleep_backoff(attempt).await;
    }

    Err(EngineError::Other(format!(
        "crt.sh returned {} after {MAX_ATTEMPTS} attempts",
        last_status.unwrap_or_default()
    )))
}

fn is_retryable(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

async fn sleep_backoff(attempt: usize) {
    let delay = BACKOFF
        .get(attempt)
        .copied()
        .unwrap_or(Duration::from_secs(4));
    tokio::time::sleep(delay).await;
}

/// Strip scheme/path from a user-supplied domain string.
fn normalize_domain(domain: &str) -> &str {
    let domain = domain
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    domain
        .trim_end_matches('/')
        .split('/')
        .next()
        .unwrap_or(domain)
}

/// Filter and dedupe raw crt.sh `name_value` entries into plausible subdomains.
fn extract_names(entries: Vec<CrtEntry>, domain: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    for entry in entries {
        for line in entry.name_value.split('\n') {
            let name = line
                .trim()
                .trim_start_matches("*.")
                .trim_end_matches('.')
                .to_lowercase();
            if name.ends_with(domain)
                && name.len() > domain.len()
                && !name.contains("..")
                && is_plausible_name(&name)
            {
                names.insert(name);
            }
        }
    }
    names.into_iter().collect()
}

/// crt.sh sometimes leaks issuer metadata into `name_value` (e.g.
/// "AS207960 test intermediate - example.com"). Keep only names that look
/// like real hostnames: lowercase letters, digits, dots and hyphens only.
fn is_plausible_name(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Vec<String> {
        let entries: Vec<CrtEntry> = serde_json::from_str(json).unwrap();
        extract_names(entries, "example.com")
    }

    #[test]
    fn parses_and_dedups_crt_json() {
        let names = parse(
            r#"[
                {"name_value": "*.example.com"},
                {"name_value": "api.example.com"},
                {"name_value": "api.example.com"},
                {"name_value": "www.example.com\nmail.example.com"},
                {"name_value": "example.com"}
            ]"#,
        );
        assert_eq!(
            names,
            vec!["api.example.com", "mail.example.com", "www.example.com"]
        );
    }

    #[test]
    fn filters_issuer_metadata_junk() {
        // crt.sh commonly mixes issuer lines into name_value; they must be dropped.
        let names = parse(
            r#"[
                {"name_value": "AS207960 test intermediate - example.com"},
                {"name_value": "C=US, O=Example, CN=example.com"},
                {"name_value": "real-api.example.com"},
                {"name_value": "dev.Example.COM"}
            ]"#,
        );
        assert_eq!(names, vec!["dev.example.com", "real-api.example.com"]);
    }

    #[test]
    fn handles_missing_domain_suffix() {
        assert_eq!(
            normalize_domain("https://example.com/some/path"),
            "example.com"
        );
        assert_eq!(normalize_domain("example.com"), "example.com");
    }

    #[tokio::test]
    async fn retries_transient_503_then_succeeds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/?q=%25.example.com&output=json");

        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut first, &mut buf).await;
            tokio::io::AsyncWriteExt::write_all(
                &mut first,
                b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n",
            )
            .await
            .unwrap();
            drop(first);

            let (mut second, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut second, &mut buf).await;
            let body = r#"[{"name_value": "api.example.com"}]"#;
            tokio::io::AsyncWriteExt::write_all(
                &mut second,
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let names = fetch_subdomains(&client, &url, "example.com")
            .await
            .unwrap();
        assert_eq!(names, vec!["api.example.com"]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn gives_up_after_exhausted_retries() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/?q=%25.example.com&output=json");

        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                tokio::io::AsyncWriteExt::write_all(
                    &mut stream,
                    b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n",
                )
                .await
                .unwrap();
            }
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let err = fetch_subdomains(&client, &url, "example.com")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("502"), "got: {err}");
        server.await.unwrap();
    }
}
