//! Async execution of templates against a base URL.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::error::Result;
use crate::matcher::{self, Response};
use crate::template::{Condition, HttpStep, Template};

const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Concurrent template executor over a single base URL.
#[derive(Clone)]
pub struct Scanner {
    client: reqwest::Client,
    templates: Vec<Template>,
    concurrency: usize,
}

impl Scanner {
    pub fn new(templates: Vec<Template>, concurrency: usize) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("berbir/0.1.0")
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;
        Ok(Self {
            client,
            templates,
            concurrency: concurrency.max(1),
        })
    }

    pub fn templates(&self) -> &[Template] {
        &self.templates
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Run templates against `base_url`. When `template_ids` is non-empty only
    /// those templates run; empty means every registered template. Each
    /// template is executed concurrently (bounded by `concurrency`).
    pub async fn run(
        &self,
        scan_id: Uuid,
        base_url: &str,
        template_ids: &[String],
    ) -> Vec<berbir_shared::Finding> {
        let base = base_url.trim_end_matches('/').to_string();
        let selected: Vec<&Template> = if template_ids.is_empty() {
            self.templates.iter().collect()
        } else {
            template_ids
                .iter()
                .filter_map(|id| self.templates.iter().find(|t| &t.id == id))
                .collect()
        };
        if selected.is_empty() {
            return Vec::new();
        }

        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = Vec::new();

        for template in selected {
            let client = self.client.clone();
            let semaphore = semaphore.clone();
            let template = template.clone();
            let base = base.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = match semaphore.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return None,
                };
                run_template(&client, scan_id, template, &base).await
            }));
        }

        let mut findings = Vec::new();
        for task in tasks {
            match task.await {
                Ok(Some(finding)) => findings.push(finding),
                Ok(None) => {}
                Err(e) => tracing::warn!("template task panicked: {e}"),
            }
        }
        findings
    }
}

/// Execute every HTTP step of a template sequentially. A finding is produced
/// only when *all* steps match (Nuclei semantics); the first matching `path`
/// of each step is used.
async fn run_template(
    client: &reqwest::Client,
    scan_id: Uuid,
    template: Template,
    base: &str,
) -> Option<berbir_shared::Finding> {
    let mut evidence = Vec::new();
    let mut matched_url: Option<String> = None;

    for step in &template.http {
        let mut step_ok = false;
        for path in &step.path {
            let url = interpolate(path, base);
            if let Some((evs, url)) = execute_step(client, step, &url).await {
                evidence.extend(evs);
                matched_url = Some(url);
                step_ok = true;
                break;
            }
        }
        if !step_ok {
            return None;
        }
    }

    if evidence.is_empty() {
        return None;
    }

    tracing::info!(
        "matched template {} on {} (severity={})",
        template.id,
        matched_url.as_deref().unwrap_or(base),
        template.info.severity
    );

    Some(berbir_shared::Finding {
        id: Uuid::new_v4(),
        scan_id,
        template_id: template.id.clone(),
        name: template.info.name.clone(),
        severity: parse_severity(&template.info.severity).unwrap_or(berbir_shared::Severity::Info),
        url: matched_url.unwrap_or_else(|| base.to_string()),
        evidence: evidence.join(" | "),
        detected_at: chrono::Utc::now(),
    })
}

/// Execute a single step's request. Returns the per-matcher evidence and the
/// final URL when the step's matchers (combined per `matchers-condition`)
/// succeed.
async fn execute_step(
    client: &reqwest::Client,
    step: &HttpStep,
    url: &str,
) -> Option<(Vec<String>, String)> {
    let mut request = client.request(step.method.parse().unwrap_or(reqwest::Method::GET), url);
    for header in &step.headers {
        request = request.header(&header.name, &header.value);
    }
    if let Some(cookie) = &step.cookie {
        request = request.header(reqwest::header::COOKIE, cookie);
    }
    if let Some(body) = &step.body {
        request = request.body(body.clone());
    }

    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("request failed for {url}: {e}");
            return None;
        }
    };

    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect::<Vec<_>>();

    let body = match response.text().await {
        Ok(b) if b.len() <= MAX_BODY_BYTES => b,
        _ => return None,
    };

    let resp = Response {
        status,
        headers,
        body,
    };

    let matched: Vec<String> = step
        .matchers
        .iter()
        .filter_map(|m| matcher::evaluate(m, &resp))
        .collect();

    let ok = match step.matchers_condition {
        Condition::Or => !matched.is_empty(),
        Condition::And => matched.len() == step.matchers.len(),
    };
    if !ok {
        return None;
    }
    Some((matched, url.to_string()))
}

/// Substitute Nuclei URL variables (`{{BaseURL}}`, `{{RootURL}}`,
/// `{{Hostname}}`, `{{Path}}`) into a request path.
fn interpolate(path: &str, base: &str) -> String {
    let parsed = url::Url::parse(base).ok();
    let root_url = parsed
        .as_ref()
        .map(|u| {
            let host = u.host_str().unwrap_or_default();
            let mut root = format!("{}://{}", u.scheme(), host);
            if let Some(port) = u.port() {
                root.push_str(&format!(":{port}"));
            }
            root
        })
        .unwrap_or_else(|| base.to_string());
    let hostname = parsed
        .as_ref()
        .map(|u| {
            let host = u.host_str().unwrap_or_default().to_string();
            match u.port() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            }
        })
        .unwrap_or_default();
    let path_part = parsed
        .as_ref()
        .map(|u| u.path().to_string())
        .unwrap_or_default();

    path.replace("{{BaseURL}}", base)
        .replace("{{RootURL}}", &root_url)
        .replace("{{Hostname}}", &hostname)
        .replace("{{Path}}", &path_part)
}

/// Parse a severity string (None on unknown values).
pub fn parse_severity(s: &str) -> Option<berbir_shared::Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" | "unknown" => Some(berbir_shared::Severity::Info),
        "low" => Some(berbir_shared::Severity::Low),
        "medium" => Some(berbir_shared::Severity::Medium),
        "high" => Some(berbir_shared::Severity::High),
        "critical" => Some(berbir_shared::Severity::Critical),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_parsing() {
        assert_eq!(
            parse_severity("critical"),
            Some(berbir_shared::Severity::Critical)
        );
        assert_eq!(parse_severity("HIGH"), Some(berbir_shared::Severity::High));
        assert_eq!(
            parse_severity("unknown"),
            Some(berbir_shared::Severity::Info)
        );
        assert_eq!(parse_severity("bogus"), None);
    }

    #[test]
    fn interpolation_variables() {
        assert_eq!(
            interpolate("{{RootURL}}/api", "https://example.com:8443/app"),
            "https://example.com:8443/api"
        );
        assert_eq!(
            interpolate(
                "GET /x HTTP/1.1\r\nHost: {{Hostname}}",
                "https://example.com/app"
            ),
            "GET /x HTTP/1.1\r\nHost: example.com"
        );
        assert_eq!(interpolate("{{Path}}", "https://example.com/app"), "/app");
        assert_eq!(
            interpolate("{{BaseURL}}/.git/config", "https://example.com"),
            "https://example.com/.git/config"
        );
    }

    /// Spawn a throwaway HTTP server that answers every request with `body`
    /// and `status`. Returns the base URL.
    async fn mock_server(body: &'static str, status: u16) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, resp.as_bytes()).await;
                });
            }
        });
        base
    }

    #[tokio::test]
    async fn single_step_template_reports_finding() {
        let base = mock_server("ref: refs/heads/main", 200).await;
        let template = Template::from_yaml_str(
            "id: git-test\ninfo:\n  name: Git\n  severity: high\nhttp:\n  - path: ['{{BaseURL}}/.git/HEAD']\n    matchers:\n      - type: word\n        part: body\n        words: ['ref: refs/heads/']\n",
        )
        .unwrap();
        let scanner = Scanner::new(vec![template], 4).unwrap();
        let findings = scanner.run(Uuid::new_v4(), &base, &[]).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].template_id, "git-test");
        assert_eq!(findings[0].url, format!("{base}/.git/HEAD"));
    }

    #[tokio::test]
    async fn all_steps_must_match() {
        let base = mock_server("page one marker", 200).await;
        let match_template = Template::from_yaml_str(
            "id: two-step-match\ninfo:\n  name: Two\n  severity: low\nhttp:\n  - path: ['{{BaseURL}}/1']\n    matchers:\n      - type: word\n        words: ['page']\n  - path: ['{{BaseURL}}/2']\n    matchers:\n      - type: word\n        words: ['marker']\n",
        )
        .unwrap();
        let miss_template = Template::from_yaml_str(
            "id: two-step-miss\ninfo:\n  name: Miss\n  severity: low\nhttp:\n  - path: ['{{BaseURL}}/1']\n    matchers:\n      - type: word\n        words: ['page']\n  - path: ['{{BaseURL}}/2']\n    matchers:\n      - type: word\n        words: ['absent-word']\n",
        )
        .unwrap();
        let scanner = Scanner::new(vec![match_template, miss_template], 4).unwrap();
        let findings = scanner.run(Uuid::new_v4(), &base, &[]).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].template_id, "two-step-match");
    }

    #[tokio::test]
    async fn template_ids_filter_selection() {
        let base = mock_server("vulnerable marker", 200).await;
        let a = Template::from_yaml_str(
            "id: sel-a\ninfo:\n  name: A\n  severity: info\nhttp:\n  - path: ['{{BaseURL}}/a']\n    matchers:\n      - type: word\n        words: ['vulnerable']\n",
        )
        .unwrap();
        let b = Template::from_yaml_str(
            "id: sel-b\ninfo:\n  name: B\n  severity: info\nhttp:\n  - path: ['{{BaseURL}}/b']\n    matchers:\n      - type: word\n        words: ['vulnerable']\n",
        )
        .unwrap();
        let scanner = Scanner::new(vec![a, b], 4).unwrap();
        let findings = scanner
            .run(Uuid::new_v4(), &base, &["sel-a".to_string()])
            .await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].template_id, "sel-a");

        let findings = scanner
            .run(Uuid::new_v4(), &base, &["nope".to_string()])
            .await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn dsl_matcher_in_real_template_run() {
        let base = mock_server("[core]\n\tbare = false", 200).await;
        let template = Template::from_yaml_str(
            "id: git-config\ninfo:\n  name: Git Config\n  severity: medium\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/.git/config'\n    matchers-condition: and\n    matchers:\n      - type: word\n        part: body\n        words: ['[credentials]', '[core]']\n        condition: or\n      - type: dsl\n        dsl:\n          - \"!contains(tolower(body), '<html')\"\n          - \"!contains(tolower(body), '<body')\"\n        condition: and\n      - type: status\n        status: [200]\n",
        )
        .unwrap();
        let scanner = Scanner::new(vec![template], 4).unwrap();
        let findings = scanner.run(Uuid::new_v4(), &base, &[]).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].template_id, "git-config");
        assert_eq!(findings[0].severity, berbir_shared::Severity::Medium);
    }
}
