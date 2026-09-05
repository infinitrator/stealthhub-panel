//! Bounded subprocess boundary. Commands are constructed by typed operations,
//! never parsed as shell programs. Secret input travels only through stdin.

use anyhow::{bail, Context, Result};
use nix::{
    sys::signal::{killpg, Signal},
    unistd::Pid,
};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
};

const OUTPUT_LIMIT: usize = 64 * 1024;

/// Owns the isolated process group so timeout, cancellation and disconnect
/// terminate descendants as well as the immediate helper.
struct ProcessGroup {
    pid: u32,
    armed: bool,
}
impl ProcessGroup {
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(pid) = i32::try_from(self.pid) {
                let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
            }
        }
    }
}

async fn drain(mut stream: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let keep = count.min(OUTPUT_LIMIT.saturating_sub(result.len()));
        result.extend_from_slice(&buffer[..keep]);
    }
    Ok(result)
}

/// Removes control sequences and potentially credential-bearing lines before
/// output reaches a terminal, JSON response or render snapshot.
pub fn safe_output(raw: &str) -> String {
    let mut pem = false;
    raw.lines()
        .take(600)
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            let pem_line = lower.contains("-----begin ") || lower.contains("-----end ");
            let redact_pem = pem || pem_line;
            if lower.contains("-----begin ") {
                pem = true;
            }
            if lower.contains("-----end ") {
                pem = false;
            }
            if redact_pem
                || [
                    "password",
                    "token",
                    "authorization:",
                    "/sub/",
                    "private_key",
                    "private-key",
                    "private key",
                    "cookie",
                    "secret value",
                    "uuid",
                ]
                .iter()
                .any(|key| lower.contains(key))
                || line.split_whitespace().any(looks_like_uuid)
            {
                "[credential-bearing line redacted]".to_string()
            } else {
                line.chars()
                    .filter(|c| !c.is_control())
                    .take(1000)
                    .collect()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn looks_like_uuid(value: &str) -> bool {
    let value = value.trim_matches(|c: char| !c.is_ascii_hexdigit() && c != '-');
    value.len() == 36
        && [8, 13, 18, 23]
            .iter()
            .all(|&index| value.as_bytes()[index] == b'-')
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
}

pub async fn run(
    program: &str,
    args: &[String],
    input: Option<String>,
    timeout: Duration,
    sensitive: bool,
) -> Result<String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "")
        .env("NO_COLOR", "1")
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .kill_on_drop(true)
        .process_group(0);
    // Never inherit Bash startup hooks into a privileged script.
    command
        .env_remove("BASH_ENV")
        .env_remove("ENV")
        .env_remove("SHELLOPTS")
        .env_remove("BASHOPTS");
    let mut child = command
        .spawn()
        .context("operation executable unavailable")?;
    let mut group = ProcessGroup {
        pid: child.id().context("operation process unavailable")?,
        armed: true,
    };
    let mut stdin = child.stdin.take().context("operation stdin unavailable")?;
    let stdout = child
        .stdout
        .take()
        .context("operation stdout unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("operation stderr unavailable")?;
    let work = async {
        let writer = async {
            if let Some(value) = input {
                stdin.write_all(value.as_bytes()).await?;
            }
            drop(stdin);
            Ok::<_, anyhow::Error>(())
        };
        let (_, out, err, status) =
            tokio::try_join!(writer, drain(stdout), drain(stderr), async {
                Ok::<_, anyhow::Error>(child.wait().await?)
            })?;
        group.disarm();
        if sensitive {
            if !status.success() {
                bail!("Operation failed; sensitive output was withheld. Verify service state before retrying.");
            }
            return Ok(
                "Operation completed. Sensitive output withheld; refresh status to verify."
                    .to_string(),
            );
        }
        let output = safe_output(&format!(
            "{}\n{}",
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&err)
        ));
        if !status.success() {
            bail!(
                "Operation failed ({}).\n{}",
                status.code().unwrap_or(-1),
                output
            );
        }
        Ok(output)
    };
    tokio::time::timeout(timeout, work)
        .await
        .context("Operation timed out; inspect state before retrying")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sanitizes_terminal_controls_and_credentials() {
        let text = safe_output("fine\npassword=CANARY\n/sub/CANARY\n\u{1b}[2Jbad\nUUID CANARY\n550e8400-e29b-41d4-a716-446655440000\n-----BEGIN PRIVATE KEY-----\nCANARY\n-----END PRIVATE KEY-----");
        assert!(!text.contains("CANARY"));
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("fine"));
    }
    #[tokio::test]
    async fn command_failure_and_timeout_are_explicit() {
        assert!(
            run("/usr/bin/false", &[], None, Duration::from_secs(1), false)
                .await
                .is_err()
        );
        let err = run(
            "/bin/sleep",
            &["2".into()],
            None,
            Duration::from_millis(20),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }
    #[tokio::test]
    async fn sensitive_stdin_never_appears_in_output() {
        let out = run(
            "/bin/cat",
            &[],
            Some("CANARY".into()),
            Duration::from_secs(1),
            true,
        )
        .await
        .unwrap();
        assert!(!out.contains("CANARY"));
    }
}
