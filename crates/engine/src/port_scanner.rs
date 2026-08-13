//! Optional port scanning via the RustScan binary (GPL-3.0, called as a subprocess).

use std::time::Duration;

use crate::error::{EngineError, Result};

/// Run `rustscan -a <host> --range <ports> -g` and return the open ports.
///
/// RustScan is invoked as a subprocess, so its GPL license does not affect
/// this project. If the binary is not installed, `EngineError::RustScanMissing`
/// is returned and callers should skip port scanning gracefully.
#[cfg(feature = "rustscan")]
pub async fn scan_ports(host: &str, range: &str) -> Result<Vec<u16>> {
    use tokio::io::AsyncBufReadExt;
    use tokio::process::Command;
    use tokio::time::timeout;

    let mut cmd = Command::new("rustscan");
    cmd.arg("-a").arg(host).arg("--range").arg(range).arg("-g");
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            EngineError::RustScanMissing
        } else {
            EngineError::Io(e)
        }
    })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| EngineError::RustScan("failed to open rustscan stdout".into()))?;

    let reader = tokio::io::BufReader::new(stdout);
    let mut lines = reader.lines();
    let mut buffer = String::new();

    loop {
        match timeout(Duration::from_secs(120), lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                buffer.push_str(&line);
                buffer.push('\n');
            }
            Ok(Ok(None)) => break,
            Ok(Err(e)) => {
                let _ = child.kill().await;
                return Err(EngineError::Io(e));
            }
            Err(_) => break,
        }
    }

    let _ = child.kill().await;
    let _ = child.wait().await;
    Ok(parse_grepable_output(&buffer))
}

/// Parse open ports out of rustscan `-g` (grepable) output. Pure, testable.
pub fn parse_grepable_output(output: &str) -> Vec<u16> {
    let re = regex::Regex::new(r"(?i)open\s+(\d+)").expect("static regex");
    let mut ports: Vec<u16> = re
        .captures_iter(output)
        .filter_map(|cap| cap[1].parse::<u16>().ok())
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_grepable_output() {
        let sample = r#"
[Host] open 80 -> 127.0.0.1
[Host] open 443 -> 127.0.0.1
scan complete in 0.2s
"#;
        assert_eq!(parse_grepable_output(sample), vec![80, 443]);
    }

    #[test]
    fn parses_mixed_ips_and_dedups() {
        let sample = "open 22 -> 10.0.0.1\nopen 22 -> 10.0.0.2\nopen 8080 -> 10.0.0.1\n";
        assert_eq!(parse_grepable_output(sample), vec![22, 8080]);
    }

    #[test]
    fn no_ports() {
        assert!(parse_grepable_output("nothing here").is_empty());
    }
}
