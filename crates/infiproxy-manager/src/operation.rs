//! Finite operation catalog shared by forms and automation validation.

use crate::{command, data::Snapshot};
use anyhow::{ensure, Result};
use std::time::Duration;

pub const HELPER: &str = "/usr/local/sbin/infiproxy-manager";

#[derive(Clone)]
pub struct Field {
    pub label: &'static str,
    pub secret: bool,
    pub choices: Vec<String>,
}

#[derive(Clone)]
pub struct Action {
    pub label: &'static str,
    pub verb: &'static str,
    pub fields: Vec<Field>,
    pub confirmation: Option<&'static str>,
    pub sensitive: bool,
}

fn field(label: &'static str) -> Field {
    Field {
        label,
        secret: false,
        choices: Vec::new(),
    }
}
fn choice(label: &'static str, values: &[String]) -> Field {
    Field {
        label,
        secret: false,
        choices: values.to_vec(),
    }
}
fn action(
    label: &'static str,
    verb: &'static str,
    fields: Vec<Field>,
    confirmation: Option<&'static str>,
    sensitive: bool,
) -> Action {
    Action {
        label,
        verb,
        fields,
        confirmation,
        sensitive,
    }
}

pub fn actions(screen: &str, snapshot: &Snapshot) -> Vec<Action> {
    let module = || choice("Registered module", &snapshot.modules);
    match screen {
        "Dashboard" => vec![action(
            "Run reconciliation",
            "reconcile",
            vec![],
            Some("APPLY"),
            false,
        )],
        "System" => vec![
            action(
                "Restart panel",
                "panel-restart",
                vec![],
                Some("APPLY"),
                false,
            ),
            action(
                "Validate / reload nginx",
                "nginx-reload",
                vec![],
                Some("APPLY"),
                false,
            ),
            action(
                "Validate / reload SSH",
                "ssh-reload",
                vec![],
                Some("APPLY"),
                false,
            ),
            action(
                "Restart enabled runtimes",
                "modules-restart",
                vec![],
                Some("APPLY"),
                false,
            ),
        ],
        "Runtimes" => vec![
            action(
                "Check module release",
                "module-check",
                vec![module()],
                None,
                false,
            ),
            action(
                "Install / update verified module",
                "module-update",
                vec![module()],
                Some("APPLY"),
                false,
            ),
            action(
                "Start runtime",
                "module-start",
                vec![module()],
                Some("APPLY"),
                false,
            ),
            action(
                "Stop runtime",
                "module-stop",
                vec![module()],
                Some("STOP"),
                false,
            ),
            action(
                "Restart runtime",
                "module-restart",
                vec![module()],
                Some("APPLY"),
                false,
            ),
            action(
                "Remove runtime registration",
                "module-remove",
                vec![module()],
                Some("REMOVE"),
                false,
            ),
        ],
        "Updates" => vec![
            action(
                "Check pinned GitHub source",
                "update-check",
                vec![],
                None,
                false,
            ),
            action(
                "Request update now",
                "update-apply",
                vec![],
                Some("APPLY"),
                false,
            ),
            action(
                "Enable timer and path watcher",
                "update-timer",
                vec![],
                Some("APPLY"),
                false,
            ),
        ],
        "Logs" => vec![action(
            "Read service journal (120 lines)",
            "logs",
            vec![choice("Service", &snapshot.services)],
            None,
            false,
        )],
        "Diagnostics" => vec![
            action("Failed systemd units", "failed-units", vec![], None, false),
            action("Disk capacity", "disk", vec![], None, false),
            action("Listener inventory", "listeners", vec![], None, false),
            action(
                "Database / reconciliation checks",
                "diagnostics",
                vec![],
                None,
                false,
            ),
        ],
        "Secrets" => vec![
            action(
                "Store / rotate root-only reference",
                "secret-store",
                vec![
                    field("Reference name"),
                    Field {
                        label: "Secret value",
                        secret: true,
                        choices: vec![],
                    },
                ],
                Some("STORE"),
                true,
            ),
            action(
                "Delete root-only reference",
                "secret-delete",
                vec![field("Reference name")],
                Some("DELETE"),
                true,
            ),
            action(
                "Adopt legacy server reference",
                "secret-adopt",
                vec![field("Reference name")],
                Some("ADOPT"),
                true,
            ),
        ],
        "HTTPS" => vec![
            action(
                "Install HTTPS dependencies",
                "https-deps",
                vec![],
                Some("INSTALL"),
                false,
            ),
            action(
                "Configure DNS + certificate + HTTPS",
                "https-setup",
                vec![
                    field("Cloudflare zone"),
                    field("Panel hostname"),
                    field("ACME email"),
                    field("Public IPv4"),
                    Field {
                        label: "Cloudflare API credential",
                        secret: true,
                        choices: vec![],
                    },
                ],
                Some("HTTPS"),
                true,
            ),
            action(
                "Renew existing certificates",
                "https-renew",
                vec![],
                Some("RENEW"),
                true,
            ),
        ],
        "Deployment" => vec![
            action(
                "1. Inspect deployment readiness",
                "diagnostics",
                vec![],
                None,
                false,
            ),
            action(
                "2. Install / repair panel (preserve env)",
                "repair",
                vec![],
                Some("INSTALL"),
                true,
            ),
            action(
                "3. Configure DNS + HTTPS",
                "https-setup",
                vec![
                    field("Cloudflare zone"),
                    field("Panel hostname"),
                    field("ACME email"),
                    field("Public IPv4"),
                    Field {
                        label: "Cloudflare API credential",
                        secret: true,
                        choices: vec![],
                    },
                ],
                Some("HTTPS"),
                true,
            ),
            action(
                "4. Install a verified runtime",
                "module-update",
                vec![module()],
                Some("INSTALL"),
                false,
            ),
            action(
                "5. Verify services and panel",
                "diagnostics",
                vec![],
                None,
                false,
            ),
        ],
        "Danger" => vec![
            action(
                "Preview panel-only removal",
                "uninstall-preview",
                vec![choice(
                    "Mode",
                    &["panel".into(), "full".into(), "factory".into()],
                )],
                None,
                false,
            ),
            action(
                "Remove Infiproxy footprint",
                "uninstall",
                vec![choice(
                    "Mode",
                    &["panel".into(), "full".into(), "factory".into()],
                )],
                Some("DELETE INFIPROXY"),
                false,
            ),
            action("Reboot server", "reboot", vec![], Some("REBOOT"), false),
        ],
        _ => vec![],
    }
}

pub fn validate(action: &Action, values: &[String]) -> Result<()> {
    ensure!(
        values.len() == action.fields.len(),
        "Missing operation fields"
    );
    for (value, field) in values.iter().zip(&action.fields) {
        ensure!(
            !value.is_empty() && value.len() <= if field.secret { 8192 } else { 256 },
            "{} is required and must be bounded",
            field.label
        );
        ensure!(
            value.chars().all(|c| !c.is_control()),
            "Control characters are forbidden"
        );
        if !field.choices.is_empty() {
            ensure!(
                field.choices.contains(value),
                "Select a registered value for {}",
                field.label
            );
        }
    }
    if action.verb.starts_with("module-") {
        ensure!(
            values.first().is_some_and(|s| !s.is_empty()
                && s.len() <= 32
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')),
            "Invalid module ID"
        );
    }
    if action.verb.starts_with("secret-") {
        let value = &values[0];
        ensure!(
            value.len() <= 128
                && !matches!(value.as_str(), "." | "..")
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
            "Invalid secret reference"
        );
    }
    Ok(())
}

pub async fn execute(action: Action, values: Vec<String>) -> Result<String> {
    validate(&action, &values)?;
    let panel_url = if action.verb == "https-setup" {
        Some(format!("https://{}/admin/setup", values[1]))
    } else {
        None
    };
    let mut args = vec!["--operation".to_string(), action.verb.to_string()];
    let mut stdin = None;
    for (value, field) in values.into_iter().zip(&action.fields) {
        if field.secret {
            stdin = Some(format!("{value}\n"));
        } else {
            args.push(value);
        }
    }
    if let Some(confirmation) = action.confirmation {
        args.push(confirmation.into());
    }
    let timeout = if matches!(
        action.verb,
        "repair" | "module-update" | "https-setup" | "https-deps" | "https-renew"
    ) {
        Duration::from_secs(3600)
    } else {
        Duration::from_secs(60)
    };
    let mut result = command::run(HELPER, &args, stdin, timeout, action.sensitive).await?;
    if let Some(url) = panel_url {
        result.push_str(&format!("\nPanel HTTPS configured: {url}"));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn references_and_registered_targets_fail_closed() {
        let s = Snapshot {
            modules: vec!["mihomo".into()],
            ..Snapshot::default()
        };
        let a = actions("Runtimes", &s).remove(0);
        assert!(validate(&a, &["sshd;reboot".into()]).is_err());
        assert!(validate(&a, &["mihomo".into()]).is_ok());
        let a = actions("Secrets", &s).remove(1);
        for reference in ["../key", "..", "bad\nname"] {
            assert!(validate(&a, &[reference.into()]).is_err());
        }
    }
}
