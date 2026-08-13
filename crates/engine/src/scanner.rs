//! Async execution of templates against a base URL.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::error::Result;
use crate::matcher::{self, Response};
use crate::template::{HttpStep, Template};

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

    /// Run every template against `base_url`, returning all matched findings.
    pub async fn run(&self, scan_id: Uuid, base_url: &str) -> Vec<berbir_shared::Finding> {
        let base = base_url.trim_end_matches('/').to_string();
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut tasks = Vec::new();

        for template in &self.templates {
            for step in &template.http {
                for path in &step.path {
                    let url = path.replace("{{BaseURL}}", &base);
                    let client = self.client.clone();
                    let semaphore = semaphore.clone();
                    let template = template.clone();
                    let step = step.clone();

                    tasks.push(tokio::spawn(async move {
                        let _permit = match semaphore.acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => return Vec::new(),
                        };
                        let _ = _permit;
                        execute_step(client, scan_id, template, step, &url).await
                    }));
                }
            }
        }

        let mut findings = Vec::new();
        for task in tasks {
            match task.await {
                Ok(found) => findings.extend(found),
                Err(e) => tracing::warn!("template task panicked: {e}"),
            }
        }
        findings
    }
}

async fn execute_step(
    client: reqwest::Client,
    scan_id: Uuid,
    template: Template,
    step: HttpStep,
    url: &str,
) -> Vec<berbir_shared::Finding> {
    let mut request = client.request(step.method.parse().unwrap_or(reqwest::Method::GET), url);
    for header in &step.headers {
        request = request.header(&header.name, &header.value);
    }

    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("request failed for {url}: {e}");
            return Vec::new();
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
        Ok(_) => return Vec::new(),
        Err(e) => {
            tracing::debug!("failed to read body for {url}: {e}");
            return Vec::new();
        }
    };

    let resp = Response {
        status,
        headers,
        body,
    };

    // All matchers within a step must match (AND).
    let mut evidence = Vec::new();
    for matcher in &step.matchers {
        match matcher::evaluate(matcher, &resp) {
            Some(ev) => evidence.push(ev),
            None => return Vec::new(),
        }
    }
    if evidence.is_empty() {
        return Vec::new();
    }

    tracing::info!(
        "matched template {} on {} (severity={})",
        template.id,
        url,
        template.info.severity
    );

    vec![berbir_shared::Finding {
        id: Uuid::new_v4(),
        scan_id,
        template_id: template.id.clone(),
        name: template.info.name.clone(),
        severity: crate::scanner::parse_severity(&template.info.severity)
            .unwrap_or(berbir_shared::Severity::Info),
        url: url.to_string(),
        evidence: evidence.join(" | "),
        detected_at: chrono::Utc::now(),
    }]
}

/// Parse a severity string (None on unknown values).
pub fn parse_severity(s: &str) -> Option<berbir_shared::Severity> {
    match s.to_ascii_lowercase().as_str() {
        "info" => Some(berbir_shared::Severity::Info),
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
        assert_eq!(parse_severity("bogus"), None);
    }
}
