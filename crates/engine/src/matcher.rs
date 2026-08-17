//! Pure response-matching logic. No I/O, unit-testable in isolation.

use regex::Regex;

use crate::dsl;
use crate::template::{Condition, Matcher, MatcherType, Part};

/// A minimal, normalized HTTP response.
#[derive(Debug, Clone, Default)]
pub struct Response {
    pub status: u16,
    /// Header name/value pairs, lowercased names.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Evaluate a matcher against a response.
/// Returns `Some(evidence)` when the matcher (honoring `negative`) succeeds.
/// Unsupported matcher kinds never match.
pub fn evaluate(matcher: &Matcher, resp: &Response) -> Option<String> {
    let matched = match matcher.mtype {
        // `type` wins over `part`: status/dsl matchers ignore the part field.
        MatcherType::Status => match_status(matcher, resp),
        MatcherType::Dsl => match_dsl(matcher, resp),
        MatcherType::Word | MatcherType::Regex => match matcher.part {
            Part::Status => match_status(matcher, resp),
            Part::Body => match_text(matcher, &resp.body),
            Part::Header => match_headers(matcher, &resp.headers),
            Part::All => match_text(matcher, &all_text(resp)),
            Part::Unknown => None,
        },
        MatcherType::Unknown => None,
    };

    match (matched, matcher.negative) {
        (Some(ev), false) => Some(ev),
        (None, true) => Some("no match (negative)".into()),
        _ => None,
    }
}

fn all_text(resp: &Response) -> String {
    let headers = resp
        .headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{headers}\n{}", resp.body)
}

fn match_status(matcher: &Matcher, resp: &Response) -> Option<String> {
    matcher
        .status
        .contains(&resp.status)
        .then(|| format!("status {}", resp.status))
}

fn match_headers(matcher: &Matcher, headers: &[(String, String)]) -> Option<String> {
    let joined = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    match_text(matcher, &joined)
}

/// Word / regex matching over a single text blob.
fn match_text(matcher: &Matcher, text: &str) -> Option<String> {
    match matcher.mtype {
        MatcherType::Word => match_word(matcher, text),
        MatcherType::Regex => match_regex(matcher, text),
        MatcherType::Status | MatcherType::Dsl | MatcherType::Unknown => None,
    }
}

fn match_word(matcher: &Matcher, text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let present = |w: &str| lower.contains(&w.to_ascii_lowercase());
    match matcher.condition {
        Condition::Or => matcher.words.iter().find(|w| present(w)).cloned(),
        Condition::And => {
            if matcher.words.is_empty() || matcher.words.iter().all(|w| present(w)) {
                matcher.words.first().cloned()
            } else {
                None
            }
        }
    }
}

fn match_regex(matcher: &Matcher, text: &str) -> Option<String> {
    if matcher.regex.is_empty() {
        return None;
    }
    for pattern in &matcher.regex {
        let re = match Regex::new(pattern) {
            Ok(re) => re,
            Err(_) => continue,
        };
        if let Some(captures) = re.captures(text) {
            let ev = captures
                .get(1)
                .or_else(|| captures.get(0))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| pattern.clone());
            if matcher.condition == Condition::And {
                if matcher
                    .regex
                    .iter()
                    .all(|p| Regex::new(p).is_ok_and(|r| r.is_match(text)))
                {
                    return Some(ev);
                }
                continue;
            }
            return Some(ev);
        }
    }
    None
}

/// DSL matchers evaluate against the full response context; unsupported or
/// unparsable expressions fail closed (no match).
fn match_dsl(matcher: &Matcher, resp: &Response) -> Option<String> {
    if matcher.dsl.is_empty() {
        return None;
    }
    let ctx = dsl::Context {
        body: resp.body.clone(),
        header: resp
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n"),
        status_code: resp.status,
    };
    match matcher.condition {
        Condition::Or => matcher
            .dsl
            .iter()
            .find(|expr| dsl::evaluate(expr, &ctx) == Some(true))
            .cloned(),
        Condition::And => {
            if matcher
                .dsl
                .iter()
                .all(|expr| dsl::evaluate(expr, &ctx) == Some(true))
            {
                matcher.dsl.first().cloned()
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> Response {
        Response {
            status,
            body: body.into(),
            headers: vec![("server".into(), "nginx".into())],
        }
    }

    fn word_matcher(words: &[&str]) -> Matcher {
        Matcher {
            mtype: MatcherType::Word,
            part: Part::Body,
            words: words.iter().map(|s| s.to_string()).collect(),
            regex: vec![],
            status: vec![],
            dsl: vec![],
            condition: Condition::Or,
            negative: false,
        }
    }

    #[test]
    fn word_or_matches_any() {
        let m = word_matcher(&["root:x:0:0:", "no_such_thing"]);
        assert_eq!(
            evaluate(&m, &resp(200, "uid=0(root) root:x:0:0: /root")).unwrap(),
            "root:x:0:0:"
        );
    }

    #[test]
    fn word_or_no_match() {
        let m = word_matcher(&["marker-does-not-exist"]);
        assert!(evaluate(&m, &resp(200, "harmless body")).is_none());
    }

    #[test]
    fn word_and_requires_all() {
        let mut m = word_matcher(&["root:x:0:0:", "db_password"]);
        m.condition = Condition::And;
        assert!(evaluate(&m, &resp(200, "root:x:0:0: only")).is_none());
        assert!(evaluate(&m, &resp(200, "root:x:0:0: db_password=secret")).is_some());
    }

    #[test]
    fn case_insensitive() {
        let m = word_matcher(&["Db_PassWord"]);
        assert!(evaluate(&m, &resp(200, "DB_PASSWORD=1")).is_some());
    }

    #[test]
    fn regex_match_and_evidence() {
        let m = Matcher {
            mtype: MatcherType::Regex,
            part: Part::Body,
            words: vec![],
            regex: vec!["aws_access_key_id=[A-Z0-9]{20}".into()],
            status: vec![],
            dsl: vec![],
            condition: Condition::Or,
            negative: false,
        };
        let ev = evaluate(&m, &resp(200, "aws_access_key_id=AKIAIOSFODNN7EXAMPLE")).unwrap();
        assert!(ev.contains("AKIAIOSFODNN7"));
    }

    #[test]
    fn status_matcher() {
        let m = Matcher {
            mtype: MatcherType::Status,
            part: Part::Status,
            words: vec![],
            regex: vec![],
            status: vec![301, 302, 200],
            condition: Condition::Or,
            negative: false,
            dsl: vec![],
        };
        assert!(evaluate(&m, &resp(302, "")).is_some());
        assert!(evaluate(&m, &resp(404, "")).is_none());
    }

    #[test]
    fn header_matcher() {
        let m = Matcher {
            mtype: MatcherType::Word,
            part: Part::Header,
            words: vec!["server: nginx".into()],
            regex: vec![],
            status: vec![],
            dsl: vec![],
            condition: Condition::Or,
            negative: false,
        };
        assert!(evaluate(&m, &resp(200, "")).is_some());
    }

    #[test]
    fn all_part_matches_headers_or_body() {
        let m = Matcher {
            mtype: MatcherType::Word,
            part: Part::All,
            words: vec!["nginx".into()],
            regex: vec![],
            status: vec![],
            dsl: vec![],
            condition: Condition::Or,
            negative: false,
        };
        assert!(evaluate(&m, &resp(200, "body without marker")).is_some());
    }

    #[test]
    fn negative_matcher() {
        let m = Matcher {
            mtype: MatcherType::Word,
            part: Part::Header,
            words: vec!["x-content-type-options: nosniff".into()],
            regex: vec![],
            status: vec![],
            dsl: vec![],
            condition: Condition::Or,
            negative: true,
        };
        assert!(evaluate(&m, &resp(200, "")).is_some());
        assert!(
            evaluate(
                &m,
                &Response {
                    status: 200,
                    body: "".into(),
                    headers: vec![("x-content-type-options".into(), "nosniff".into())],
                }
            )
            .is_none()
        );
    }

    #[test]
    fn dsl_matcher() {
        let m = Matcher {
            mtype: MatcherType::Dsl,
            part: Part::Body,
            words: vec![],
            regex: vec![],
            status: vec![],
            dsl: vec!["contains(body, 'admin')".into()],
            condition: Condition::Or,
            negative: false,
        };
        assert!(evaluate(&m, &resp(200, "admin")).is_some());
        assert!(evaluate(&m, &resp(200, "nothing here")).is_none());
    }

    #[test]
    fn unknown_matcher_kind_never_matches() {
        let m = Matcher {
            mtype: MatcherType::Unknown,
            part: Part::Body,
            words: vec!["anything".into()],
            regex: vec![],
            status: vec![],
            dsl: vec![],
            condition: Condition::Or,
            negative: false,
        };
        assert!(evaluate(&m, &resp(200, "anything")).is_none());
    }
}
