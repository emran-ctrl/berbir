//! Dev tool: analyze how many templates in a directory (e.g. a Nuclei
//! templates checkout) are actually loadable and runnable by `berbir-engine`.
//!
//! Usage: `cargo run -p berbir-engine --example analyze_templates -- <dir>`

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use berbir_engine::Template;
use berbir_engine::template::MatcherType;

const PROTOCOLS: &[&str] = &[
    "http",
    "dns",
    "ssl",
    "tcp",
    "network",
    "file",
    "headless",
    "code",
    "javascript",
    "dast",
    "websocket",
    "workflows",
    "email",
];

const SUPPORTED_URL_VARS: &[&str] = &["BaseURL", "RootURL", "Hostname", "Path"];

fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: analyze_templates <dir>");

    let start = std::time::Instant::now();
    let mut files = Vec::new();
    walk(Path::new(&dir), &mut files);

    let mut protocol_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut parse_failures: Vec<String> = Vec::new();
    let mut http_total = 0usize;
    let mut http_with_matchers = 0usize;
    let mut runnable = 0usize;
    let mut runnable_with_unsupported_vars = 0usize;
    let mut runnable_with_extractors = 0usize;
    let mut matcher_type_counts: BTreeMap<&str, usize> = BTreeMap::new();

    for path in &files {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };

        let top_keys = serde_yaml::from_str::<serde_yaml::Value>(&contents)
            .ok()
            .and_then(|v| v.as_mapping().cloned())
            .map(|m| {
                m.keys()
                    .filter_map(|k| k.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            });
        let primary = top_keys
            .as_deref()
            .and_then(|keys| PROTOCOLS.iter().find(|p| keys.contains(&p.to_string())))
            .copied()
            .map(str::to_string)
            .unwrap_or_else(|| "other".into());
        *protocol_counts.entry(primary).or_insert(0) += 1;

        let has_extractors = contents.contains("extractors:");

        match Template::from_yaml_str(&contents) {
            Err(e) => {
                if parse_failures.len() < 20 {
                    parse_failures.push(format!("{}: {e}", path.display()));
                }
            }
            Ok(t) => {
                if t.http.is_empty() {
                    continue;
                }
                http_total += 1;
                if !t.http.iter().any(|s| !s.matchers.is_empty()) {
                    continue;
                }
                http_with_matchers += 1;
                runnable += 1;
                if has_extractors {
                    runnable_with_extractors += 1;
                }
                for step in &t.http {
                    for m in &step.matchers {
                        *matcher_type_counts.entry(mtype_name(m.mtype)).or_insert(0) += 1;
                    }
                }
                let uses_unsupported = t.http.iter().any(|step| {
                    step.path.iter().any(|p| has_unsupported_var(p))
                        || step.matchers.iter().any(|m| {
                            m.words.iter().any(|w| has_unsupported_var(w))
                                || m.regex.iter().any(|r| has_unsupported_var(r))
                                || m.dsl.iter().any(|d| has_unsupported_var(d))
                        })
                });
                if uses_unsupported {
                    runnable_with_unsupported_vars += 1;
                }
            }
        }
    }

    let elapsed = start.elapsed();

    println!("=== template analysis: {dir} ===");
    println!("yaml files found:        {}", files.len());
    println!("registry load time:      {elapsed:?}");
    println!();
    println!("--- by top-level protocol ---");
    let mut by_protocol: Vec<_> = protocol_counts.iter().collect();
    by_protocol.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in by_protocol {
        println!("  {proto:<12} {count:>6}");
    }
    println!();
    println!("--- engine compatibility (http only) ---");
    println!("  http templates parsed:        {http_total}");
    println!("  with >=1 surviving matcher:   {http_with_matchers}");
    println!("  -> runnable:                  {runnable}");
    println!(
        "     of which reference unsupported {{{{...}}}} vars: {runnable_with_unsupported_vars}"
    );
    println!("     of which use extractors:   {runnable_with_extractors}");
    println!();
    println!("  matcher type counts (runnable templates):");
    for (name, count) in &matcher_type_counts {
        println!("    {name:<8} {count:>6}");
    }
    println!();
    println!("parse failures (first {}):", parse_failures.len());
    for f in &parse_failures {
        println!("  {f}");
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p
            .extension()
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
}

/// True when `s` contains a `{{...}}` variable outside the supported set
/// (BaseURL/RootURL/Hostname/Path), which the engine leaves as a literal.
fn has_unsupported_var(s: &str) -> bool {
    if !s.contains("{{") {
        return false;
    }
    let mut rest = s;
    while let Some(start) = rest.find("{{") {
        let Some(rel_end) = rest[start + 2..].find("}}") else {
            break;
        };
        let inner = &rest[start + 2..start + 2 + rel_end];
        if !SUPPORTED_URL_VARS.contains(&inner) {
            return true;
        }
        rest = &rest[start + 2 + rel_end + 2..];
    }
    false
}

fn mtype_name(t: MatcherType) -> &'static str {
    match t {
        MatcherType::Word => "word",
        MatcherType::Regex => "regex",
        MatcherType::Status => "status",
        MatcherType::Dsl => "dsl",
        MatcherType::Unknown => "unknown",
    }
}
