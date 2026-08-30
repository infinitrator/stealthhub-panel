//! Privileged built-in runtime adapters.
//!
//! Every command and path is fixed by this root-owned package. Desired JSON can
//! select capabilities and values, but can never select an executable or shell
//! command.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::adapter::{
    CoreAdapter, CoreAdapterManifest, CorePlan, CoreRegistry, CoreSnapshot, UserSyncObservation,
    ADAPTER_API_VERSION,
};
use crate::module_manifest::normalized_release_version;

use super::tls::{
    capabilities_require_tls, tls_material_readiness, CERTIFICATE_PATH, PRIVATE_KEY_PATH,
};
const RUNTIME_GROUP: &str = "infiproxy-runtime";
const XRAY_CAPABILITIES: &[&str] = &["vless-reality-tcp", "vless-reality-xhttp"];
const SING_BOX_CAPABILITIES: &[&str] = &[
    "vless-reality-tcp",
    "shadowsocks2022-shadow-tls",
    "hysteria2",
    "any-tls",
    "tuic",
];
const HYSTERIA_CAPABILITIES: &[&str] = &["hysteria2"];
const TUIC_CAPABILITIES: &[&str] = &["tuic"];
const MIHOMO_CAPABILITIES: &[&str] = &[
    "vless-reality-tcp",
    "vless-reality-xhttp",
    "vless-shadowtls-v3",
    "vless-restls",
    "vless-jls",
    "anytls-tls",
    "anytls-shadowtls-v3",
    "anytls-restls",
    "anytls-jls",
    "trojan-tls",
    "trojan-shadowtls-v3",
    "trojan-restls",
    "trojan-jls",
    "trojan-reality",
    "snell-v5",
    "snell-v5-shadowtls-v3",
    "snell-v5-restls",
    "snell-v5-jls",
    "mieru",
    "trusttunnel-h2",
    "shadowquic",
    "sudoku-httpmask",
];
#[cfg(test)]
const MIHOMO_EXCLUSIVE_CAPABILITIES: &[&str] = &[
    "vless-reality-xhttp",
    "vless-shadowtls-v3",
    "vless-restls",
    "vless-jls",
    "anytls-tls",
    "anytls-shadowtls-v3",
    "anytls-restls",
    "anytls-jls",
    "trojan-tls",
    "trojan-shadowtls-v3",
    "trojan-restls",
    "trojan-jls",
    "trojan-reality",
    "snell-v5",
    "snell-v5-shadowtls-v3",
    "snell-v5-restls",
    "snell-v5-jls",
    "mieru",
    "trusttunnel-h2",
    "shadowquic",
    "sudoku-httpmask",
];

#[derive(Clone, Copy)]
enum Flavor {
    Xray,
    SingBox,
    Hysteria,
    Tuic,
    Mihomo,
}

#[derive(Default)]
struct ListenerState {
    previous: Vec<(u16, bool)>,
    desired: Vec<(u16, bool)>,
}

struct ManagedCoreAdapter {
    manifest: CoreAdapterManifest,
    flavor: Flavor,
    binary: PathBuf,
    config: PathBuf,
    validated_version: &'static str,
    version_file: PathBuf,
    listeners: Mutex<ListenerState>,
}

struct ManagedCoreSpec<'a> {
    id: &'a str,
    display_name: &'a str,
    service: &'a str,
    flavor: Flavor,
    binary: &'a str,
    config: &'a str,
    capabilities: &'a [&'a str],
    selection_priority: i32,
    validated_version: &'static str,
    version_file: Option<&'a str>,
}

impl ManagedCoreAdapter {
    fn new(spec: ManagedCoreSpec<'_>) -> Self {
        Self {
            manifest: CoreAdapterManifest {
                api_version: ADAPTER_API_VERSION,
                id: spec.id.to_string(),
                display_name: spec.display_name.to_string(),
                capabilities: spec
                    .capabilities
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                service: spec.service.to_string(),
                selection_priority: spec.selection_priority,
            },
            flavor: spec.flavor,
            binary: PathBuf::from(spec.binary),
            config: PathBuf::from(spec.config),
            validated_version: spec.validated_version,
            version_file: spec.version_file.map_or_else(
                || {
                    PathBuf::from(format!(
                        "/var/lib/infiproxy-maintenance/module-versions/{}.version",
                        spec.id
                    ))
                },
                PathBuf::from,
            ),
            listeners: Mutex::new(ListenerState::default()),
        }
    }

    fn compose(&self, plan: &CorePlan) -> Result<Vec<u8>> {
        match self.flavor {
            Flavor::Xray => Ok(serde_json::to_vec_pretty(&compose_xray(plan)?)?),
            Flavor::SingBox => Ok(serde_json::to_vec_pretty(&compose_sing_box(plan)?)?),
            Flavor::Hysteria => Ok(serde_norway::to_string(&compose_hysteria(plan)?)?.into_bytes()),
            Flavor::Tuic => Ok(serde_json::to_vec_pretty(&compose_tuic(plan)?)?),
            Flavor::Mihomo => Ok(serde_norway::to_string(&compose_mihomo(plan)?)?.into_bytes()),
        }
    }

    fn validate_structure(&self, candidate: &Path) -> Result<()> {
        match self.flavor {
            Flavor::Xray | Flavor::SingBox | Flavor::Tuic => {
                let value: Value = serde_json::from_slice(&fs::read(candidate)?)?;
                if !value.is_object() {
                    bail!("candidate root must be an object");
                }
            }
            Flavor::Hysteria | Flavor::Mihomo => {
                let value: serde_norway::Value = serde_norway::from_slice(&fs::read(candidate)?)?;
                if !value.is_mapping() {
                    bail!("candidate root must be a mapping");
                }
            }
        }
        Ok(())
    }

    fn validation_command(&self, candidate: &Path) -> Result<()> {
        let status = match self.flavor {
            Flavor::Xray => Some(
                Command::new(&self.binary)
                    .args(["run", "-test", "-config"])
                    .arg(candidate)
                    .status()?,
            ),
            Flavor::SingBox => Some(
                Command::new(&self.binary)
                    .args(["check", "-c"])
                    .arg(candidate)
                    .status()?,
            ),
            Flavor::Mihomo => Some(
                Command::new(&self.binary)
                    .args(["-t", "-f"])
                    .arg(candidate)
                    .status()?,
            ),
            Flavor::Hysteria | Flavor::Tuic => None,
        };
        if status.is_some_and(|status| !status.success()) {
            bail!("runtime rejected candidate configuration");
        }
        Ok(())
    }

    fn systemctl(&self, arguments: &[&str]) -> Result<()> {
        let status = Command::new("/usr/bin/systemctl")
            .args(arguments)
            .arg(&self.manifest.service)
            .status()?;
        if !status.success() {
            bail!("runtime service operation failed");
        }
        Ok(())
    }

    fn systemctl_is(&self, property: &str) -> bool {
        Command::new("/usr/bin/systemctl")
            .args([property, "--quiet", &self.manifest.service])
            .status()
            .is_ok_and(|status| status.success())
    }

    fn atomic_install(&self, source: &Path) -> Result<()> {
        let parent = self
            .config
            .parent()
            .context("runtime config has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".candidate-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o640)
                .open(&temporary)?;
            file.write_all(&fs::read(source)?)?;
            file.sync_all()?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640))?;
            let status = Command::new("/usr/bin/chown")
                .arg(format!("root:{RUNTIME_GROUP}"))
                .arg(&temporary)
                .status()?;
            if !status.success() {
                bail!("could not set runtime config ownership");
            }
            fs::rename(&temporary, &self.config)?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn read_current_config(&self) -> Result<Option<Vec<u8>>> {
        let metadata = match fs::symlink_metadata(&self.config) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() {
            bail!("runtime config must be a regular file");
        }
        Ok(Some(fs::read(&self.config)?))
    }

    fn probed_version(&self) -> Option<[u64; 3]> {
        let arguments: &[&str] = match self.flavor {
            Flavor::Xray => &["version"],
            Flavor::Mihomo => &["-v"],
            Flavor::SingBox | Flavor::Hysteria => &["version"],
            Flavor::Tuic => &["--version"],
        };
        let output = Command::new(&self.binary).args(arguments).output().ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .chain(String::from_utf8_lossy(&output.stderr).split_whitespace())
            .find_map(normalized_release_version)
    }

    fn main_pid(&self) -> Result<u32> {
        let output = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "--property=MainPID",
                "--value",
                &self.manifest.service,
            ])
            .output()?;
        if !output.status.success() {
            bail!("could not inspect runtime PID");
        }
        let pid = String::from_utf8(output.stdout)?.trim().parse::<u32>()?;
        if pid == 0 {
            bail!("runtime has no active PID");
        }
        Ok(pid)
    }

    fn verify_port_set(&self, required: &[(u16, bool)], forbidden: &[(u16, bool)]) -> Result<()> {
        let output = Command::new("/usr/bin/ss")
            .args(["-H", "-ltnup"])
            .output()
            .context("inspect runtime listeners")?;
        if !output.status.success() {
            bail!("listener discovery failed");
        }
        let listeners = String::from_utf8(output.stdout)?;
        let pid = if required.is_empty() {
            None
        } else {
            Some(self.main_pid()?)
        };
        for (port, udp) in required {
            let protocol = if *udp { "udp" } else { "tcp" };
            let pid_marker = format!("pid={}", pid.context("missing runtime PID")?);
            if !listeners.lines().any(|line| {
                line.starts_with(protocol)
                    && listener_line_has_port(line, *port)
                    && line.contains(&pid_marker)
            }) {
                bail!("required listener is absent or owned by another process");
            }
        }
        for (port, udp) in forbidden {
            let protocol = if *udp { "udp" } else { "tcp" };
            if listeners
                .lines()
                .any(|line| line.starts_with(protocol) && listener_line_has_port(line, *port))
            {
                bail!("stale listener remains active");
            }
        }
        Ok(())
    }
}

impl CoreAdapter for ManagedCoreAdapter {
    fn manifest(&self) -> &CoreAdapterManifest {
        &self.manifest
    }

    fn installed(&self) -> Result<bool> {
        Ok(self.binary.is_file())
    }

    fn compatible(&self, required: &std::collections::BTreeSet<String>) -> Result<bool> {
        if !self.binary.is_file() {
            return Ok(false);
        }
        if capabilities_require_tls(required.iter()) && !tls_material_readiness(None).ready {
            return Ok(false);
        }
        let expected = normalized_release_version(self.validated_version)
            .context("validated runtime version is invalid")?;
        let installed = match fs::read_to_string(&self.version_file) {
            Ok(value) => normalized_release_version(value.trim()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.probed_version(),
            Err(error) => return Err(error.into()),
        };
        Ok(installed == Some(expected))
    }

    fn stage_config(&self, plan: &CorePlan, transaction_dir: &Path) -> Result<PathBuf> {
        let candidate = transaction_dir.join(match self.flavor {
            Flavor::Hysteria | Flavor::Mihomo => "candidate.yaml",
            _ => "candidate.json",
        });
        fs::write(&candidate, self.compose(plan)?)?;
        let previous = self
            .read_current_config()?
            .map(|bytes| discover_config_ports(self.flavor, &bytes))
            .transpose()?
            .unwrap_or_default();
        let desired = plan
            .fragments
            .iter()
            .flat_map(|fragment| &fragment.listeners)
            .map(|listener| {
                (
                    listener.port,
                    listener.network == crate::adapter::ListenerNetwork::Udp,
                )
            })
            .collect::<Vec<_>>();
        *self
            .listeners
            .lock()
            .map_err(|_| anyhow::anyhow!("listener lock poisoned"))? =
            ListenerState { previous, desired };
        Ok(candidate)
    }

    fn validate_config(&self, candidate: &Path) -> Result<()> {
        self.validate_structure(candidate)?;
        self.validation_command(candidate)
    }

    fn snapshot_config(&self, transaction_dir: &Path) -> Result<CoreSnapshot> {
        let snapshot_dir = transaction_dir.join("snapshot");
        fs::create_dir_all(&snapshot_dir)?;
        if let Some(config) = self.read_current_config()? {
            fs::write(snapshot_dir.join("config"), config)?;
        } else {
            fs::write(snapshot_dir.join("config.absent"), [])?;
        }
        Ok(CoreSnapshot {
            path: snapshot_dir,
            service_was_enabled: self.systemctl_is("is-enabled"),
            service_was_active: self.systemctl_is("is-active"),
        })
    }

    fn install_config(&self, candidate: &Path) -> Result<()> {
        self.atomic_install(candidate)
    }

    fn activate_config(&self, plan: &CorePlan) -> Result<()> {
        if plan.fragments.is_empty() {
            self.systemctl(&["disable", "--now"])
        } else {
            self.systemctl(&["enable"])?;
            self.systemctl(&["restart"])
        }
    }

    fn healthcheck(&self, _plan: &CorePlan) -> Result<()> {
        if !self.systemctl_is("is-active") {
            bail!("runtime service is not active");
        }
        Ok(())
    }

    fn verify_listeners(&self, plan: &CorePlan) -> Result<()> {
        let listeners = self
            .listeners
            .lock()
            .map_err(|_| anyhow::anyhow!("listener lock poisoned"))?;
        let forbidden = listeners
            .previous
            .iter()
            .filter(|listener| !listeners.desired.contains(listener))
            .copied()
            .collect::<Vec<_>>();
        if plan.fragments.is_empty() {
            self.verify_port_set(&[], &listeners.previous)
        } else {
            self.verify_port_set(&listeners.desired, &forbidden)
        }
    }

    fn observe_users(&self, plan: &CorePlan) -> Result<UserSyncObservation> {
        let expected = plan
            .fragments
            .iter()
            .filter_map(|fragment| fragment.expected_user_ids.as_ref())
            .flatten()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        if !plan
            .fragments
            .iter()
            .any(|fragment| fragment.expected_user_ids.is_some())
        {
            return Ok(UserSyncObservation::InSync { user_count: 0 });
        }
        let config = self
            .read_current_config()?
            .context("runtime user observation requires a live config")?;
        let observed = discover_config_users(self.flavor, &config)?;
        Ok(UserSyncObservation::compare(&expected, &observed))
    }

    fn rollback_config(&self, snapshot: &CoreSnapshot) -> Result<()> {
        let config = snapshot.path.join("config");
        if config.is_file() {
            self.atomic_install(&config)?;
        } else if snapshot.path.join("config.absent").is_file() {
            match fs::remove_file(&self.config) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        } else {
            bail!("snapshot configuration is incomplete");
        }
        if snapshot.service_was_enabled {
            self.systemctl(&["enable"])?;
        } else {
            self.systemctl(&["disable"])?;
        }
        if snapshot.service_was_active {
            self.systemctl(&["restart"])?;
            if !self.systemctl_is("is-active") {
                bail!("restored runtime is not healthy");
            }
            let restored = self
                .read_current_config()?
                .context("active runtime snapshot has no restored config")?;
            let required = discover_config_ports(self.flavor, &restored)?;
            self.verify_port_set(&required, &[])?;
        } else {
            self.systemctl(&["stop"])?;
        }
        Ok(())
    }
}

fn payload_object(fragment: &crate::adapter::ServerFragment) -> Result<&Map<String, Value>> {
    fragment
        .payload
        .as_object()
        .context("server fragment must be an object")
}

fn payload_config(payload: &Map<String, Value>) -> Result<&Map<String, Value>> {
    payload
        .get("config")
        .and_then(Value::as_object)
        .context("server fragment config is invalid")
}

fn payload_secrets(payload: &Map<String, Value>) -> Result<&Map<String, Value>> {
    payload
        .get("resolved_secrets")
        .and_then(Value::as_object)
        .context("server fragment secrets are unresolved")
}

fn config_text<'a>(config: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    config
        .get(name)
        .and_then(Value::as_str)
        .context("required adapter field is absent")
}

fn resolved_secret<'a>(payload: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    let config = payload_config(payload)?;
    let reference = config_text(config, field)?;
    payload_secrets(payload)?
        .get(reference)
        .and_then(Value::as_str)
        .context("privileged secret reference is unresolved")
}

fn users(payload: &Map<String, Value>) -> Result<&Vec<Value>> {
    payload
        .get("users")
        .and_then(Value::as_array)
        .context("server fragment users are invalid")
}

fn port(payload: &Map<String, Value>) -> Result<u16> {
    payload
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .context("server fragment port is invalid")
}

fn compose_xray(plan: &CorePlan) -> Result<Value> {
    let mut inbounds = Vec::new();
    for fragment in &plan.fragments {
        let payload = payload_object(fragment)?;
        let config = payload_config(payload)?;
        let user_entries = users(payload)?
            .iter()
            .map(|user| {
                let mut entry = json!({"id": user["uuid"], "email": user["username"]});
                if fragment.capability == "vless-reality-tcp" {
                    entry["flow"] = json!("xtls-rprx-vision");
                }
                entry
            })
            .collect::<Vec<_>>();
        let mut stream = json!({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": format!("{}:443", config_text(config, "server_name")?),
                "xver": 0,
                "serverNames": [config_text(config, "server_name")?],
                "privateKey": resolved_secret(payload, "private_key_secret")?,
                "shortIds": [resolved_secret(payload, "short_id_secret")?]
            }
        });
        if fragment.capability == "vless-reality-xhttp" {
            stream["network"] = json!("xhttp");
            stream["xhttpSettings"] = json!({"path": config_text(config, "path")?});
        }
        inbounds.push(json!({
            "tag": fragment.profile_id,
            "listen": "::",
            "port": port(payload)?,
            "protocol": "vless",
            "settings": {"clients": user_entries, "decryption": "none"},
            "streamSettings": stream
        }));
    }
    Ok(json!({
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [{"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"blocked"}]
    }))
}

fn compose_sing_box(plan: &CorePlan) -> Result<Value> {
    let mut inbounds = Vec::new();
    for fragment in &plan.fragments {
        let payload = payload_object(fragment)?;
        let config = payload_config(payload)?;
        let listen_port = port(payload)?;
        let tag = &fragment.profile_id;
        let inbound = match fragment.capability.as_str() {
            "vless-reality-tcp" => {
                let user_entries = users(payload)?
                    .iter()
                    .map(|user| json!({"name":user["username"],"uuid":user["uuid"]}))
                    .collect::<Vec<_>>();
                json!({
                    "type":"vless","tag":tag,"listen":"::","listen_port":listen_port,
                    "users":user_entries,
                    "tls":{"enabled":true,"server_name":config_text(config,"server_name")?,"reality":{"enabled":true,"handshake":{"server":config_text(config,"server_name")?,"server_port":443},"private_key":resolved_secret(payload,"private_key_secret")?,"short_id":[resolved_secret(payload,"short_id_secret")?]}}
                })
            }
            "shadowsocks2022-shadow-tls" => {
                let inner_tag = format!("{tag}-inner");
                inbounds.push(json!({"type":"shadowsocks","tag":inner_tag,"method":"2022-blake3-aes-256-gcm","password":resolved_secret(payload,"password_secret")?}));
                json!({
                    "type":"shadowtls","tag":tag,"listen":"::","listen_port":listen_port,
                    "version":3,"users":[{"name":"shared","password":resolved_secret(payload,"shadow_tls_password_secret")?}],
                    "handshake":{"server":config_text(config,"server_name")?,"server_port":443},"detour":inner_tag
                })
            }
            "hysteria2" => {
                let mut inbound = json!({
                    "type":"hysteria2","tag":tag,"listen":"::","listen_port":listen_port,
                    "users":[{"name":"shared","password":resolved_secret(payload,"password_secret")?}],
                    "tls":tls_files()
                });
                if config
                    .get("obfs_password_secret")
                    .and_then(Value::as_str)
                    .is_some_and(|reference| !reference.trim().is_empty())
                {
                    inbound["obfs"] = json!({
                        "type":"salamander",
                        "password":resolved_secret(payload,"obfs_password_secret")?
                    });
                }
                inbound
            }
            "any-tls" => json!({
                "type":"anytls","tag":tag,"listen":"::","listen_port":listen_port,
                "users":[{"name":"shared","password":resolved_secret(payload,"password_secret")?}],"tls":tls_files()
            }),
            "tuic" => {
                let password = resolved_secret(payload, "password_secret")?;
                let user_entries = users(payload)?.iter().map(|user| json!({"name":user["username"],"uuid":user["uuid"],"password":password})).collect::<Vec<_>>();
                json!({"type":"tuic","tag":tag,"listen":"::","listen_port":listen_port,"users":user_entries,"congestion_control":"bbr","zero_rtt_handshake":false,"tls":tls_files()})
            }
            _ => bail!("sing-box adapter received an unsupported capability"),
        };
        inbounds.push(inbound);
    }
    Ok(
        json!({"log":{"level":"warn"},"inbounds":inbounds,"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}]}),
    )
}

fn tls_files() -> Value {
    json!({"enabled":true,"certificate_path":CERTIFICATE_PATH,"key_path":PRIVATE_KEY_PATH})
}

fn compose_hysteria(plan: &CorePlan) -> Result<Value> {
    if plan.fragments.len() > 1 {
        bail!("native runtime supports one managed server profile");
    }
    let Some(fragment) = plan.fragments.first() else {
        return Ok(json!({}));
    };
    let payload = payload_object(fragment)?;
    let mut value = json!({
        "listen":format!(":{}",port(payload)?),
        "tls":{"cert":CERTIFICATE_PATH,"key":PRIVATE_KEY_PATH},
        "auth":{"type":"password","password":resolved_secret(payload,"password_secret")?}
    });
    if payload_config(payload)?
        .get("obfs_password_secret")
        .is_some()
    {
        value["obfs"] = json!({"type":"salamander","salamander":{"password":resolved_secret(payload,"obfs_password_secret")?}});
    }
    Ok(value)
}

fn compose_tuic(plan: &CorePlan) -> Result<Value> {
    if plan.fragments.len() > 1 {
        bail!("native runtime supports one managed server profile");
    }
    let Some(fragment) = plan.fragments.first() else {
        return Ok(
            json!({"server":"[::]:0","users":{},"certificate":CERTIFICATE_PATH,"private_key":PRIVATE_KEY_PATH}),
        );
    };
    let payload = payload_object(fragment)?;
    let password = resolved_secret(payload, "password_secret")?;
    let user_map = users(payload)?
        .iter()
        .filter_map(|user| user.get("uuid").and_then(Value::as_str))
        .map(|uuid| (uuid.to_string(), json!(password)))
        .collect::<Map<_, _>>();
    Ok(
        json!({"server":format!("[::]:{}",port(payload)?),"users":user_map,"certificate":CERTIFICATE_PATH,"private_key":PRIVATE_KEY_PATH,"congestion_control":"bbr","alpn":["h3"],"zero_rtt_handshake":false}),
    )
}

fn compose_mihomo(plan: &CorePlan) -> Result<Value> {
    let mut listeners = Vec::new();
    for fragment in &plan.fragments {
        let payload = payload_object(fragment)?;
        let config = payload_config(payload)?;
        let listen_port = port(payload)?;
        let name = &fragment.profile_id;
        let listener = match fragment.capability.as_str() {
            capability
                if matches!(
                    capability,
                    "vless-reality-tcp"
                        | "vless-reality-xhttp"
                        | "vless-shadowtls-v3"
                        | "vless-restls"
                        | "vless-jls"
                ) =>
            {
                let vision = fragment.capability == "vless-reality-tcp";
                let user_entries = users(payload)?
                    .iter()
                    .map(|user| {
                        let mut entry = json!({
                            "username": user["username"],
                            "uuid": user["uuid"]
                        });
                        if vision {
                            entry["flow"] = json!("xtls-rprx-vision");
                        }
                        entry
                    })
                    .collect::<Vec<_>>();
                let mut listener = json!({
                    "name":name,"type":"vless","listen":"::","port":listen_port,
                    "users":user_entries
                });
                if capability == "vless-reality-tcp" {
                    listener["reality-config"] = reality_server_options(payload, config)?;
                } else if capability == "vless-reality-xhttp" {
                    listener["reality-config"] = reality_server_options(payload, config)?;
                    listener["xhttp-config"] = json!({
                        "path": config_text(config, "path")?,
                        "host": config_text(config, "server_name")?,
                        "mode": "auto"
                    });
                } else {
                    apply_mihomo_server_wrapper(
                        &mut listener,
                        payload,
                        config,
                        wrapper_for_capability(capability)?,
                    )?;
                }
                listener
            }
            capability if capability.starts_with("anytls-") => {
                let password = resolved_secret(payload, "password_secret")?;
                let mut listener = json!({
                    "name":name,"type":"anytls","listen":"::","port":listen_port,
                    "users":{"shared":password}
                });
                apply_mihomo_server_wrapper(
                    &mut listener,
                    payload,
                    config,
                    wrapper_for_capability(capability)?,
                )?;
                listener
            }
            capability if capability.starts_with("trojan-") => {
                let user_entries = users(payload)?
                    .iter()
                    .map(|user| json!({"username":user["uuid"],"password":user["uuid"]}))
                    .collect::<Vec<_>>();
                let mut listener = json!({
                    "name":name,"type":"trojan","listen":"::","port":listen_port,
                    "users":user_entries
                });
                apply_mihomo_server_wrapper(
                    &mut listener,
                    payload,
                    config,
                    wrapper_for_capability(capability)?,
                )?;
                listener
            }
            capability if capability == "snell-v5" || capability.starts_with("snell-v5-") => {
                let mut listener = json!({
                    "name":name,"type":"snell","listen":"::","port":listen_port,
                    "psk":resolved_secret(payload,"psk_secret")?,"version":5,"udp":true
                });
                if capability != "snell-v5" {
                    apply_mihomo_server_wrapper(
                        &mut listener,
                        payload,
                        config,
                        wrapper_for_capability(capability)?,
                    )?;
                }
                listener
            }
            "mieru" => {
                let password = resolved_secret(payload, "password_secret")?;
                let user_entries = users(payload)?
                    .iter()
                    .filter_map(|user| user.get("uuid").and_then(Value::as_str))
                    .map(|uuid| (uuid.to_string(), json!(password)))
                    .collect::<Map<_, _>>();
                json!({
                    "name":name,"type":"mieru","listen":"::","port":listen_port,
                    "transport":"TCP","users":user_entries,"user-hint-is-mandatory":true
                })
            }
            "trusttunnel-h2" => {
                let user_entries = users(payload)?
                    .iter()
                    .map(|user| json!({"username":user["uuid"],"password":user["uuid"]}))
                    .collect::<Vec<_>>();
                json!({
                    "name":name,"type":"trusttunnel","listen":"::","port":listen_port,
                    "users":user_entries,"certificate":CERTIFICATE_PATH,
                    "private-key":PRIVATE_KEY_PATH,"network":["tcp"]
                })
            }
            "shadowquic" => {
                let user_entries = users(payload)?
                    .iter()
                    .map(|user| json!({"username":user["uuid"],"password":user["uuid"]}))
                    .collect::<Vec<_>>();
                let sni = config_text(config, "sni")?;
                json!({
                    "name":name,"type":"shadowquic","listen":"::","port":listen_port,
                    "users":user_entries,
                    "jls-upstream":{"addr":format!("{sni}:443"),"sni":sni},
                    "alpn":["h3"],"quic-versions":["v1"],"zero-rtt":false,
                    "congestion-controller":"cubic"
                })
            }
            "sudoku-httpmask" => json!({
                "name":name,"type":"sudoku","listen":"::","port":listen_port,
                "key":resolved_secret(payload,"key_secret")?,
                "aead-method":"chacha20-poly1305","padding-min":2,"padding-max":7,
                "table-type":"prefer_ascii","handshake-timeout":5,
                "enable-pure-downlink":false,
                "httpmask":{"disable":false,"mode":"legacy","path-root":config_text(config,"path_root")?}
            }),
            _ => bail!("mihomo adapter received an unsupported capability"),
        };
        listeners.push(listener);
    }
    Ok(json!({
        "log-level":"warning",
        "mode":"rule",
        "listeners":listeners,
        "rules":["MATCH,DIRECT"]
    }))
}

#[derive(Clone, Copy)]
enum MihomoSecurityWrapper {
    StandardTls,
    Reality,
    ShadowTlsV3,
    ResTls,
    Jls,
}

fn wrapper_for_capability(capability: &str) -> Result<MihomoSecurityWrapper> {
    if capability.ends_with("-tls") || capability == "anytls-tls" {
        Ok(MihomoSecurityWrapper::StandardTls)
    } else if capability.ends_with("-reality") {
        Ok(MihomoSecurityWrapper::Reality)
    } else if capability.ends_with("-shadowtls-v3") {
        Ok(MihomoSecurityWrapper::ShadowTlsV3)
    } else if capability.ends_with("-restls") {
        Ok(MihomoSecurityWrapper::ResTls)
    } else if capability.ends_with("-jls") {
        Ok(MihomoSecurityWrapper::Jls)
    } else {
        bail!("unsupported Mihomo security wrapper")
    }
}

fn reality_server_options(
    payload: &Map<String, Value>,
    config: &Map<String, Value>,
) -> Result<Value> {
    Ok(json!({
        "dest": format!("{}:443", config_text(config, "sni").or_else(|_| config_text(config, "server_name"))?),
        "private-key": resolved_secret(payload, "private_key_secret")?,
        "short-id": [resolved_secret(payload, "short_id_secret")?],
        "server-names": [config_text(config, "sni").or_else(|_| config_text(config, "server_name"))?]
    }))
}

fn apply_mihomo_server_wrapper(
    listener: &mut Value,
    payload: &Map<String, Value>,
    config: &Map<String, Value>,
    wrapper: MihomoSecurityWrapper,
) -> Result<()> {
    let destination = || -> Result<String> { Ok(format!("{}:443", config_text(config, "sni")?)) };
    match wrapper {
        MihomoSecurityWrapper::StandardTls => {
            listener["certificate"] = json!(CERTIFICATE_PATH);
            listener["private-key"] = json!(PRIVATE_KEY_PATH);
        }
        MihomoSecurityWrapper::Reality => {
            listener["reality-config"] = reality_server_options(payload, config)?;
        }
        MihomoSecurityWrapper::ShadowTlsV3 => {
            listener["shadow-tls"] = json!({
                "enable": true,
                "version": 3,
                "users": [{"name":"shared","password":resolved_secret(payload,"shadow_tls_password_secret")?}],
                "handshake": {"dest":destination()?}
            });
        }
        MihomoSecurityWrapper::ResTls => {
            listener["res-tls"] = json!({
                "enable": true,
                "dest": destination()?,
                "password": resolved_secret(payload,"restls_password_secret")?
            });
        }
        MihomoSecurityWrapper::Jls => {
            listener["jls-config"] = json!({
                "enable": true,
                "users": [{
                    "username":resolved_secret(payload,"jls_username_secret")?,
                    "password":resolved_secret(payload,"jls_password_secret")?
                }],
                "dest": destination()?
            });
        }
    }
    Ok(())
}

fn listener_line_has_port(line: &str, port: u16) -> bool {
    let marker = format!(":{port}");
    line.split_whitespace()
        .any(|field| field.ends_with(&marker))
}

fn discover_config_ports(flavor: Flavor, bytes: &[u8]) -> Result<Vec<(u16, bool)>> {
    let mut ports = Vec::new();
    match flavor {
        Flavor::Xray => {
            let value: Value = serde_json::from_slice(bytes)?;
            for inbound in value
                .get("inbounds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(port) = inbound
                    .get("port")
                    .and_then(Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                {
                    ports.push((port, false));
                }
            }
        }
        Flavor::SingBox => {
            let value: Value = serde_json::from_slice(bytes)?;
            for inbound in value
                .get("inbounds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(port) = inbound
                    .get("listen_port")
                    .and_then(Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                {
                    let udp = inbound
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| matches!(kind, "hysteria2" | "tuic"));
                    ports.push((port, udp));
                }
            }
        }
        Flavor::Hysteria => {
            let value: serde_norway::Value = serde_norway::from_slice(bytes)?;
            if let Some(listen) = value.get("listen").and_then(serde_norway::Value::as_str) {
                if let Some(port) = listen
                    .rsplit(':')
                    .next()
                    .and_then(|value| value.parse().ok())
                {
                    ports.push((port, true));
                }
            }
        }
        Flavor::Tuic => {
            let value: Value = serde_json::from_slice(bytes)?;
            if let Some(server) = value.get("server").and_then(Value::as_str) {
                if let Some(port) = server
                    .rsplit(':')
                    .next()
                    .and_then(|value| value.parse().ok())
                {
                    if port != 0 {
                        ports.push((port, true));
                    }
                }
            }
        }
        Flavor::Mihomo => {
            let value: Value = serde_norway::from_slice(bytes)?;
            for listener in value
                .get("listeners")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(port) = listener
                    .get("port")
                    .and_then(Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                {
                    let udp = listener
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind == "shadowquic");
                    ports.push((port, udp));
                }
            }
        }
    }
    Ok(ports)
}

fn discover_config_users(
    flavor: Flavor,
    bytes: &[u8],
) -> Result<std::collections::BTreeSet<String>> {
    let mut users = std::collections::BTreeSet::new();
    match flavor {
        Flavor::Xray => {
            let value: Value = serde_json::from_slice(bytes)?;
            for inbound in value
                .get("inbounds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                for user in inbound
                    .pointer("/settings/clients")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(id) = user.get("id").and_then(Value::as_str) {
                        users.insert(id.to_string());
                    }
                }
            }
        }
        Flavor::SingBox => {
            let value: Value = serde_json::from_slice(bytes)?;
            for inbound in value
                .get("inbounds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                for user in inbound
                    .get("users")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(id) = user.get("uuid").and_then(Value::as_str) {
                        users.insert(id.to_string());
                    }
                }
            }
        }
        Flavor::Tuic => {
            let value: Value = serde_json::from_slice(bytes)?;
            users.extend(
                value
                    .get("users")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|entries| entries.keys().cloned()),
            );
        }
        Flavor::Hysteria => {}
        Flavor::Mihomo => {
            let value: Value = serde_norway::from_slice(bytes)?;
            for listener in value
                .get("listeners")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                match listener.get("users") {
                    Some(Value::Array(entries)) => {
                        users.extend(entries.iter().filter_map(mihomo_array_user_identity));
                    }
                    Some(Value::Object(entries)) => users.extend(entries.keys().cloned()),
                    _ => {}
                }
            }
        }
    }
    Ok(users)
}

fn mihomo_array_user_identity(entry: &Value) -> Option<String> {
    entry
        .get("uuid")
        .and_then(Value::as_str)
        .or_else(|| entry.get("username").and_then(Value::as_str))
        .map(str::to_string)
}

fn built_in_adapters() -> [ManagedCoreAdapter; 5] {
    [
        ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "xray",
            display_name: "Xray",
            service: "infiproxy-xray.service",
            flavor: Flavor::Xray,
            binary: "/opt/infiproxy/cores/xray/current/xray",
            config: "/etc/infiproxy-cores/xray/config.json",
            capabilities: XRAY_CAPABILITIES,
            selection_priority: 100,
            validated_version: "v26.3.27",
            version_file: None,
        }),
        ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "mihomo",
            display_name: "Mihomo",
            service: "infiproxy-mihomo.service",
            flavor: Flavor::Mihomo,
            binary: "/opt/infiproxy/cores/mihomo/current/mihomo",
            config: "/etc/infiproxy-cores/mihomo/config.yaml",
            capabilities: MIHOMO_CAPABILITIES,
            selection_priority: 200,
            validated_version: "v1.19.30",
            version_file: None,
        }),
        ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "sing-box",
            display_name: "sing-box",
            service: "infiproxy-sing-box.service",
            flavor: Flavor::SingBox,
            binary: "/opt/infiproxy/cores/sing-box/current/sing-box",
            config: "/etc/infiproxy-cores/sing-box/config.json",
            capabilities: SING_BOX_CAPABILITIES,
            selection_priority: 50,
            validated_version: "v1.13.20",
            version_file: None,
        }),
        ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "hysteria",
            display_name: "Hysteria",
            service: "infiproxy-hysteria.service",
            flavor: Flavor::Hysteria,
            binary: "/opt/infiproxy/cores/hysteria/current/hysteria",
            config: "/etc/infiproxy-cores/hysteria/config.yaml",
            capabilities: HYSTERIA_CAPABILITIES,
            selection_priority: 200,
            validated_version: "app/v2.12.2",
            version_file: None,
        }),
        ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "tuic",
            display_name: "TUIC",
            service: "infiproxy-tuic.service",
            flavor: Flavor::Tuic,
            binary: "/opt/infiproxy/cores/tuic/current/tuic-server",
            config: "/etc/infiproxy-cores/tuic/config.json",
            capabilities: TUIC_CAPABILITIES,
            selection_priority: 200,
            validated_version: "tuic-server-1.0.0",
            version_file: None,
        }),
    ]
}

pub(super) fn registry() -> Result<CoreRegistry> {
    let mut registry = CoreRegistry::default();
    for adapter in built_in_adapters() {
        registry.register(Arc::new(adapter))?;
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet, os::unix::fs::PermissionsExt, process::Command, thread,
        time::Duration,
    };

    use super::*;

    fn minimal_plan(core_id: &str, capability: &str) -> CorePlan {
        CorePlan {
            generation: 1,
            core_id: core_id.to_string(),
            fragments: vec![crate::adapter::ServerFragment {
                profile_id: format!("test-{capability}"),
                capability: capability.to_string(),
                payload: json!({
                    "port": 24443,
                    "config": {
                        "server_name": "example.com",
                        "sni": "example.com",
                        "path": "/proxy",
                        "private_key_secret": "secret.private-key",
                        "short_id_secret": "secret.short-id",
                        "password_secret": "secret.password",
                        "shadow_tls_password_secret": "secret.shadow-tls",
                        "restls_password_secret": "secret.restls",
                        "jls_username_secret": "secret.jls-username",
                        "jls_password_secret": "secret.jls-password",
                        "psk_secret": "secret.psk",
                        "key_secret": "secret.sudoku-key",
                        "path_root": "infiproxy"
                    },
                    "users": [{"username": "alice", "uuid": "11111111-1111-4111-8111-111111111111"}],
                    "resolved_secrets": {
                        "secret.private-key": "private-key",
                        "secret.short-id": "0000000000000000",
                        "secret.password": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
                        "secret.shadow-tls": "shadow-tls-password",
                        "secret.restls": "restls-password",
                        "secret.jls-username": "jls-user",
                        "secret.jls-password": "jls-password",
                        "secret.psk": "pre-shared-key",
                        "secret.sudoku-key": "44444444-4444-4444-8444-444444444444"
                    }
                }),
                expected_user_ids: None,
                listeners: Vec::new(),
            }],
        }
    }

    fn test_adapter(
        flavor: Flavor,
        binary: &Path,
        config: &Path,
        version_file: &Path,
        validated_version: &'static str,
    ) -> Result<ManagedCoreAdapter> {
        Ok(ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "test-runtime",
            display_name: "Test runtime",
            service: "infiproxy-test.service",
            flavor,
            binary: binary
                .to_str()
                .context("temporary binary path is not UTF-8")?,
            config: config
                .to_str()
                .context("temporary config path is not UTF-8")?,
            capabilities: XRAY_CAPABILITIES,
            selection_priority: 1,
            validated_version,
            version_file: Some(
                version_file
                    .to_str()
                    .context("temporary marker path is not UTF-8")?,
            ),
        }))
    }

    fn write_probe(path: &Path, expected_argument: &str, version: &str) -> Result<()> {
        fs::write(
            path,
            format!(
                "#!/bin/sh\n[ \"$1\" = \"{expected_argument}\" ] || exit 64\nprintf '%s\\n' '{version}'\n"
            ),
        )?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    #[test]
    fn listener_matching_does_not_confuse_port_suffixes() {
        assert!(listener_line_has_port("tcp LISTEN 0 128 [::]:7443", 7443));
        assert!(!listener_line_has_port("tcp LISTEN 0 128 [::]:17443", 7443));
    }

    #[test]
    fn live_user_discovery_is_runtime_specific_and_ignores_shared_credentials() {
        let xray = br#"{"inbounds":[{"settings":{"clients":[{"id":"user-a"},{"id":"user-b"}]}}]}"#;
        assert_eq!(
            discover_config_users(Flavor::Xray, xray).unwrap(),
            BTreeSet::from(["user-a".to_string(), "user-b".to_string()])
        );

        let sing_box = br#"{"inbounds":[{"users":[{"name":"shared","password":"secret"},{"name":"alice","uuid":"user-a"}]}]}"#;
        assert_eq!(
            discover_config_users(Flavor::SingBox, sing_box).unwrap(),
            BTreeSet::from(["user-a".to_string()])
        );

        let tuic = br#"{"users":{"user-a":"secret","user-b":"secret"}}"#;
        assert_eq!(
            discover_config_users(Flavor::Tuic, tuic).unwrap(),
            BTreeSet::from(["user-a".to_string(), "user-b".to_string()])
        );

        let mihomo = br#"listeners:
  - type: vless
    users:
      - username: alice
        uuid: 11111111-1111-4111-8111-111111111111
  - type: trojan
    users:
      - username: user-a
        password: user-a
  - type: mieru
    users:
      user-b: secret
"#;
        assert_eq!(
            discover_config_users(Flavor::Mihomo, mihomo).unwrap(),
            BTreeSet::from([
                "11111111-1111-4111-8111-111111111111".to_string(),
                "user-a".to_string(),
                "user-b".to_string(),
            ])
        );
    }

    #[test]
    fn mihomo_vless_user_lifecycle_observes_uuid_and_reports_count_only_drift() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let directory = std::env::temp_dir().join(format!("infiproxy-users-{suffix}"));
        fs::create_dir(&directory)?;
        let binary = directory.join("mihomo");
        let config = directory.join("config.yaml");
        let marker = directory.join("mihomo.version");
        fs::write(&binary, b"installed")?;
        let adapter = test_adapter(Flavor::Mihomo, &binary, &config, &marker, "v1.19.30")?;
        let expected_uuid = "11111111-1111-4111-8111-111111111111";
        let unexpected_uuid = "22222222-2222-4222-8222-222222222222";

        let mut created = minimal_plan("test-runtime", "vless-reality-tcp");
        created.fragments[0].expected_user_ids = Some(BTreeSet::from([expected_uuid.to_string()]));
        fs::write(&config, adapter.compose(&created)?)?;
        assert_eq!(
            discover_config_users(Flavor::Mihomo, &fs::read(&config)?)?,
            BTreeSet::from([expected_uuid.to_string()])
        );
        assert_eq!(
            adapter.observe_users(&created)?,
            UserSyncObservation::InSync { user_count: 1 }
        );

        let mut drifted = minimal_plan("test-runtime", "vless-reality-tcp");
        drifted.fragments[0].payload["users"][0]["uuid"] = json!(unexpected_uuid);
        drifted.fragments[0].expected_user_ids = Some(BTreeSet::from([expected_uuid.to_string()]));
        fs::write(&config, adapter.compose(&drifted)?)?;
        let observation = adapter.observe_users(&drifted)?;
        assert_eq!(
            observation,
            UserSyncObservation::Drift {
                expected_count: 1,
                observed_count: 1,
                missing_count: 1,
                unexpected_count: 1,
            }
        );
        let diagnostic = serde_json::to_string(&observation)?;
        assert!(!diagnostic.contains(expected_uuid));
        assert!(!diagnostic.contains(unexpected_uuid));
        assert!(!diagnostic.contains("alice"));

        let mut disabled = minimal_plan("test-runtime", "vless-reality-tcp");
        disabled.fragments[0].payload["users"] = json!([]);
        disabled.fragments[0].expected_user_ids = Some(BTreeSet::new());
        fs::write(&config, adapter.compose(&disabled)?)?;
        assert_eq!(
            adapter.observe_users(&disabled)?,
            UserSyncObservation::InSync { user_count: 0 }
        );

        let deleted = CorePlan {
            generation: 2,
            core_id: "test-runtime".to_string(),
            fragments: Vec::new(),
        };
        fs::write(&config, adapter.compose(&deleted)?)?;
        assert_eq!(
            adapter.observe_users(&deleted)?,
            UserSyncObservation::InSync { user_count: 0 }
        );
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn mixed_mihomo_listeners_observe_only_adapter_selected_identities() -> Result<()> {
        let config = br#"listeners:
  - type: vless
    users:
      - username: alice
        uuid: 11111111-1111-4111-8111-111111111111
  - type: trojan
    users:
      - username: 22222222-2222-4222-8222-222222222222
        password: never-observe-this-password
  - type: mieru
    users:
      33333333-3333-4333-8333-333333333333: never-observe-this-password
"#;
        let observed = discover_config_users(Flavor::Mihomo, config)?;
        assert_eq!(
            observed,
            BTreeSet::from([
                "11111111-1111-4111-8111-111111111111".to_string(),
                "22222222-2222-4222-8222-222222222222".to_string(),
                "33333333-3333-4333-8333-333333333333".to_string(),
            ])
        );
        assert!(!format!("{observed:?}").contains("never-observe"));
        Ok(())
    }

    #[test]
    fn runtime_version_contract_is_exact_and_missing_markers_probe_fail_closed() -> Result<()> {
        let cases = [
            (Flavor::Xray, "version", "Xray 26.3.27", "v26.3.27"),
            (Flavor::Mihomo, "-v", "Mihomo Meta v1.19.30", "v1.19.30"),
            (
                Flavor::SingBox,
                "version",
                "sing-box version 1.13.20",
                "v1.13.20",
            ),
            (
                Flavor::Hysteria,
                "version",
                "Version: v2.12.2",
                "app/v2.12.2",
            ),
            (
                Flavor::Tuic,
                "--version",
                "tuic-server 1.0.0",
                "tuic-server-1.0.0",
            ),
        ];
        for (flavor, argument, output, expected) in cases {
            let suffix = uuid::Uuid::new_v4();
            let directory = std::env::temp_dir().join(format!("infiproxy-version-{suffix}"));
            fs::create_dir(&directory)?;
            let binary = directory.join("runtime");
            let config = directory.join("config");
            let marker = directory.join("runtime.version");
            write_probe(&binary, argument, output)?;
            let adapter = test_adapter(flavor, &binary, &config, &marker, expected)?;
            assert!(adapter.compatible(&BTreeSet::new())?);

            write_probe(&binary, argument, "runtime v9.9.9")?;
            assert!(!adapter.compatible(&BTreeSet::new())?);
            fs::write(&marker, format!("{expected}\n"))?;
            assert!(adapter.compatible(&BTreeSet::new())?);
            fs::write(&marker, b"v9.9.9\n")?;
            assert!(!adapter.compatible(&BTreeSet::new())?);
            fs::remove_file(&binary)?;
            assert!(!adapter.compatible(&BTreeSet::new())?);
            fs::remove_dir_all(directory)?;
        }
        Ok(())
    }

    #[test]
    fn markerless_newer_xray_is_not_compatible_with_the_validated_pin() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let directory = std::env::temp_dir().join(format!("infiproxy-xray-{suffix}"));
        fs::create_dir(&directory)?;
        let binary = directory.join("xray");
        let config = directory.join("config.json");
        let marker = directory.join("xray.version");
        write_probe(&binary, "version", "Xray 26.7.11")?;
        let adapter = test_adapter(Flavor::Xray, &binary, &config, &marker, "v26.3.27")?;
        assert!(!adapter.compatible(&BTreeSet::new())?);
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn mihomo_composer_emits_valid_listener_yaml() {
        let fragment = |capability: &str, port: u16, config: Value, users: Vec<Value>| {
            crate::adapter::ServerFragment {
                profile_id: capability.to_string(),
                capability: capability.to_string(),
                payload: json!({
                    "port":port,"config":config,"users":users,
                    "resolved_secrets":{"snell.psk":"snell-secret","mieru.password":"mieru-secret"}
                }),
                expected_user_ids: None,
                listeners: Vec::new(),
            }
        };
        let identity = json!({"username":"alice","uuid":"user-a"});
        let plan = CorePlan {
            generation: 1,
            core_id: "mihomo".to_string(),
            fragments: vec![
                fragment(
                    "trojan-tls",
                    12443,
                    json!({"sni":"example.com"}),
                    vec![identity.clone()],
                ),
                fragment(
                    "snell-v5",
                    13443,
                    json!({"psk_secret":"snell.psk"}),
                    Vec::new(),
                ),
                fragment(
                    "mieru",
                    14443,
                    json!({"password_secret":"mieru.password"}),
                    vec![identity],
                ),
            ],
        };
        let rendered = compose_mihomo(&plan).unwrap();
        let yaml = serde_norway::to_string(&rendered).unwrap();
        let reparsed: Value = serde_norway::from_str(&yaml).unwrap();
        assert_eq!(reparsed["listeners"][0]["type"], "trojan");
        assert_eq!(reparsed["listeners"][1]["version"], 5);
        assert_eq!(reparsed["listeners"][2]["transport"], "TCP");
    }

    #[test]
    fn modern_mihomo_listeners_preserve_security_and_transport_invariants() -> Result<()> {
        let listener = |capability: &str| -> Result<Value> {
            Ok(compose_mihomo(&minimal_plan("mihomo", capability))?["listeners"][0].clone())
        };
        let wrappers = ["reality-config", "shadow-tls", "res-tls", "jls-config"];
        for capability in MIHOMO_CAPABILITIES {
            let rendered = listener(capability)?;
            assert!(
                wrappers
                    .iter()
                    .filter(|field| rendered.get(**field).is_some())
                    .count()
                    <= 1,
                "{capability} contains mutually exclusive wrappers"
            );
        }

        let reality = listener("vless-reality-tcp")?;
        assert_eq!(reality["users"][0]["flow"], "xtls-rprx-vision");
        let xhttp = listener("vless-reality-xhttp")?;
        assert!(xhttp["users"][0].get("flow").is_none());
        for (capability, wrapper) in [
            ("vless-shadowtls-v3", "shadow-tls"),
            ("vless-restls", "res-tls"),
            ("vless-jls", "jls-config"),
        ] {
            let rendered = listener(capability)?;
            assert!(rendered.get(wrapper).is_some());
            assert!(rendered["users"][0].get("flow").is_none());
        }

        let trusttunnel = listener("trusttunnel-h2")?;
        assert_eq!(trusttunnel["network"], json!(["tcp"]));
        assert_eq!(trusttunnel["certificate"], CERTIFICATE_PATH);
        assert_eq!(trusttunnel["private-key"], PRIVATE_KEY_PATH);
        assert_eq!(
            trusttunnel["users"][0]["username"],
            trusttunnel["users"][0]["password"]
        );

        let shadowquic = listener("shadowquic")?;
        assert_eq!(shadowquic["zero-rtt"], false);
        assert_eq!(shadowquic["alpn"], json!(["h3"]));
        assert!(shadowquic.get("jls-config").is_none());
        assert_eq!(
            discover_config_ports(
                Flavor::Mihomo,
                serde_norway::to_string(&compose_mihomo(&minimal_plan("mihomo", "shadowquic"))?)?
                    .as_bytes(),
            )?,
            vec![(24443, true)]
        );

        let sudoku = listener("sudoku-httpmask")?;
        assert_eq!(sudoku["aead-method"], "chacha20-poly1305");
        assert_ne!(sudoku["aead-method"], "none");
        assert_eq!(sudoku["httpmask"]["mode"], "legacy");
        assert_eq!(sudoku["httpmask"]["path-root"], "infiproxy");
        Ok(())
    }

    #[test]
    fn shipped_core_registry_declares_every_initial_capability() {
        let registry = registry().unwrap();
        let capabilities = registry
            .manifests()
            .into_iter()
            .flat_map(|manifest| manifest.capabilities)
            .collect::<BTreeSet<_>>();
        for capability in [
            "vless-reality-tcp",
            "vless-reality-xhttp",
            "shadowsocks2022-shadow-tls",
            "hysteria2",
            "any-tls",
            "tuic",
            "trojan-tls",
            "snell-v5",
            "mieru",
        ] {
            assert!(capabilities.contains(capability));
        }
    }

    #[test]
    fn built_in_capability_manifests_match_their_composers() {
        for adapter in built_in_adapters() {
            for capability in &adapter.manifest.capabilities {
                adapter
                    .compose(&minimal_plan(&adapter.manifest.id, capability))
                    .unwrap_or_else(|error| {
                        panic!(
                            "{} advertises unsupported capability {capability}: {error:#}",
                            adapter.manifest.id
                        )
                    });
            }
        }
    }

    #[test]
    fn mihomo_only_capabilities_are_not_advertised_or_selected_by_sing_box() -> Result<()> {
        let built_ins = registry()?;
        let manifests = built_ins.manifests();
        let mihomo = manifests
            .iter()
            .find(|manifest| manifest.id == "mihomo")
            .context("Mihomo manifest is missing")?;
        let sing_box = manifests
            .iter()
            .find(|manifest| manifest.id == "sing-box")
            .context("sing-box manifest is missing")?;

        for capability in MIHOMO_EXCLUSIVE_CAPABILITIES {
            assert!(mihomo.capabilities.contains(*capability));
            assert!(!sing_box.capabilities.contains(*capability));
        }

        let binary = std::env::temp_dir().join(format!(
            "infiproxy-installed-sing-box-{}",
            uuid::Uuid::new_v4()
        ));
        fs::write(&binary, b"installed")?;
        let mut selection_registry = CoreRegistry::default();
        selection_registry.register(Arc::new(ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "sing-box",
            display_name: "sing-box",
            service: "infiproxy-sing-box.service",
            flavor: Flavor::SingBox,
            binary: binary.to_str().context("temporary path is not UTF-8")?,
            config: "/tmp/infiproxy-unused-sing-box-config.json",
            capabilities: SING_BOX_CAPABILITIES,
            selection_priority: 10,
            validated_version: "v1.13.20",
            version_file: None,
        })))?;

        for capability in MIHOMO_EXCLUSIVE_CAPABILITIES {
            let required = BTreeSet::from([(*capability).to_string()]);
            assert!(selection_registry.select(&required, None)?.is_none());
        }
        fs::remove_file(binary)?;
        Ok(())
    }

    #[test]
    fn core_selection_refuses_an_installed_runtime_outside_its_exact_contract() -> Result<()> {
        let suffix = uuid::Uuid::new_v4();
        let binary = std::env::temp_dir().join(format!("infiproxy-core-{suffix}"));
        let version_file = std::env::temp_dir().join(format!("infiproxy-version-{suffix}"));
        fs::write(&binary, b"installed")?;
        fs::write(&version_file, b"v26.7.11\n")?;

        let mut registry = CoreRegistry::default();
        registry.register(Arc::new(ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "xray",
            display_name: "Xray",
            service: "infiproxy-xray.service",
            flavor: Flavor::Xray,
            binary: binary.to_str().context("temporary path is not UTF-8")?,
            config: "/tmp/infiproxy-unused-xray-config.json",
            capabilities: XRAY_CAPABILITIES,
            selection_priority: 100,
            validated_version: "v26.3.27",
            version_file: Some(
                version_file
                    .to_str()
                    .context("temporary path is not UTF-8")?,
            ),
        })))?;
        let required = BTreeSet::from(["vless-reality-tcp".to_string()]);
        assert!(registry.select(&required, None)?.is_none());
        assert!(registry.select(&required, Some("xray")).is_err());

        fs::remove_file(binary)?;
        fs::remove_file(version_file)?;
        Ok(())
    }

    fn replace_string(value: &mut Value, target: &str, replacement: &str) {
        match value {
            Value::String(text) if text == target => *text = replacement.to_string(),
            Value::Array(values) => {
                for value in values {
                    replace_string(value, target, replacement);
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    replace_string(value, target, replacement);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn exact_mihomo_parser_accepts_every_advertised_server_capability() -> Result<()> {
        let Some(binary) = std::env::var_os("INFIPROXY_TEST_MIHOMO_BIN") else {
            return Ok(());
        };
        let directory =
            std::env::temp_dir().join(format!("infiproxy-mihomo-server-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory)?;
        let certificate = directory.join("certificate.pem");
        let private_key = directory.join("private-key.pem");
        let certificate_status = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
            .args(["-subj", "/CN=example.com", "-days", "1"])
            .arg("-keyout")
            .arg(&private_key)
            .arg("-out")
            .arg(&certificate)
            .output()?;
        if !certificate_status.status.success() {
            bail!("could not generate isolated compatibility certificate");
        }

        for capability in MIHOMO_CAPABILITIES {
            let mut plan = minimal_plan("mihomo", capability);
            plan.fragments[0].payload["resolved_secrets"]["secret.private-key"] =
                json!("AG07sMd7f9K5EKNYf3tuSH3cc6AwZSBEX4t26cng-Vk");
            let mut rendered = compose_mihomo(&plan)?;
            replace_string(
                &mut rendered,
                CERTIFICATE_PATH,
                certificate
                    .to_str()
                    .context("certificate path is not UTF-8")?,
            );
            replace_string(
                &mut rendered,
                PRIVATE_KEY_PATH,
                private_key
                    .to_str()
                    .context("private key path is not UTF-8")?,
            );
            let candidate = directory.join(format!("{capability}.yaml"));
            fs::write(&candidate, serde_norway::to_string(&rendered)?)?;
            let output = Command::new(&binary)
                .args(["-t", "-f"])
                .arg(&candidate)
                .output()?;
            if !output.status.success() {
                bail!(
                    "Mihomo v1.19.30 rejected server capability {capability}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn exact_runtime_version_probes_accept_pinned_binaries() -> Result<()> {
        let cases = [
            ("INFIPROXY_TEST_XRAY_BIN", Flavor::Xray, "v26.3.27"),
            ("INFIPROXY_TEST_MIHOMO_BIN", Flavor::Mihomo, "v1.19.30"),
            ("INFIPROXY_TEST_SING_BOX_BIN", Flavor::SingBox, "v1.13.20"),
            (
                "INFIPROXY_TEST_HYSTERIA_BIN",
                Flavor::Hysteria,
                "app/v2.12.2",
            ),
            ("INFIPROXY_TEST_TUIC_BIN", Flavor::Tuic, "tuic-server-1.0.0"),
        ];
        for (variable, flavor, version) in cases {
            let Some(binary) = std::env::var_os(variable) else {
                continue;
            };
            let marker = std::env::temp_dir()
                .join(format!("infiproxy-absent-version-{}", uuid::Uuid::new_v4()));
            let config = std::env::temp_dir()
                .join(format!("infiproxy-unused-config-{}", uuid::Uuid::new_v4()));
            let adapter = test_adapter(flavor, Path::new(&binary), &config, &marker, version)?;
            assert!(
                adapter.compatible(&BTreeSet::new())?,
                "{variable} did not report exact pin {version}"
            );
        }
        Ok(())
    }

    #[test]
    fn exact_xray_and_sing_box_parsers_accept_advertised_capabilities() -> Result<()> {
        let xray = std::env::var_os("INFIPROXY_TEST_XRAY_BIN");
        let sing_box = std::env::var_os("INFIPROXY_TEST_SING_BOX_BIN");
        if xray.is_none() && sing_box.is_none() {
            return Ok(());
        }
        let directory =
            std::env::temp_dir().join(format!("infiproxy-pinned-cores-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory)?;
        let certificate = directory.join("certificate.pem");
        let private_key = directory.join("private-key.pem");
        let certificate_status = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
            .args(["-subj", "/CN=example.com", "-days", "1"])
            .arg("-keyout")
            .arg(&private_key)
            .arg("-out")
            .arg(&certificate)
            .output()?;
        if !certificate_status.status.success() {
            bail!("could not generate isolated compatibility certificate");
        }

        if let Some(binary) = xray {
            for capability in XRAY_CAPABILITIES {
                let mut plan = minimal_plan("xray", capability);
                plan.fragments[0].payload["resolved_secrets"]["secret.private-key"] =
                    json!("AG07sMd7f9K5EKNYf3tuSH3cc6AwZSBEX4t26cng-Vk");
                let candidate = directory.join(format!("xray-{capability}.json"));
                fs::write(
                    &candidate,
                    serde_json::to_vec_pretty(&compose_xray(&plan)?)?,
                )?;
                let output = Command::new(&binary)
                    .args(["run", "-test", "-config"])
                    .arg(&candidate)
                    .output()?;
                if !output.status.success() {
                    bail!(
                        "Xray v26.3.27 rejected {capability}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
        if let Some(binary) = sing_box {
            for capability in SING_BOX_CAPABILITIES {
                let mut plan = minimal_plan("sing-box", capability);
                plan.fragments[0].payload["resolved_secrets"]["secret.private-key"] =
                    json!("AG07sMd7f9K5EKNYf3tuSH3cc6AwZSBEX4t26cng-Vk");
                let mut rendered = compose_sing_box(&plan)?;
                replace_string(
                    &mut rendered,
                    CERTIFICATE_PATH,
                    certificate
                        .to_str()
                        .context("certificate path is not UTF-8")?,
                );
                replace_string(
                    &mut rendered,
                    PRIVATE_KEY_PATH,
                    private_key
                        .to_str()
                        .context("private key path is not UTF-8")?,
                );
                let candidate = directory.join(format!("sing-box-{capability}.json"));
                fs::write(&candidate, serde_json::to_vec_pretty(&rendered)?)?;
                let output = Command::new(&binary)
                    .args(["check", "-c"])
                    .arg(&candidate)
                    .output()?;
                if !output.status.success() {
                    bail!(
                        "sing-box v1.13.20 rejected {capability}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    #[test]
    fn exact_hysteria_and_tuic_accept_isolated_generated_configs() -> Result<()> {
        let hysteria = std::env::var_os("INFIPROXY_TEST_HYSTERIA_BIN");
        let tuic = std::env::var_os("INFIPROXY_TEST_TUIC_BIN");
        if hysteria.is_none() && tuic.is_none() {
            return Ok(());
        }
        let directory =
            std::env::temp_dir().join(format!("infiproxy-native-cores-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory)?;
        let certificate = directory.join("certificate.pem");
        let private_key = directory.join("private-key.pem");
        let certificate_status = Command::new("openssl")
            .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
            .args(["-subj", "/CN=example.com", "-days", "1"])
            .arg("-keyout")
            .arg(&private_key)
            .arg("-out")
            .arg(&certificate)
            .output()?;
        if !certificate_status.status.success() {
            bail!("could not generate isolated compatibility certificate");
        }

        if let Some(binary) = hysteria {
            let mut rendered = compose_hysteria(&minimal_plan("hysteria", "hysteria2"))?;
            replace_string(
                &mut rendered,
                CERTIFICATE_PATH,
                certificate
                    .to_str()
                    .context("certificate path is not UTF-8")?,
            );
            replace_string(
                &mut rendered,
                PRIVATE_KEY_PATH,
                private_key
                    .to_str()
                    .context("private key path is not UTF-8")?,
            );
            rendered["listen"] = json!("127.0.0.1:0");
            let candidate = directory.join("hysteria.yaml");
            fs::write(&candidate, serde_norway::to_string(&rendered)?)?;
            assert_starts_under_timeout(
                Command::new(binary)
                    .args(["server", "--disable-update-check", "-c"])
                    .arg(candidate),
                "Hysteria app/v2.12.2",
            )?;
        }
        if let Some(binary) = tuic {
            let mut rendered = compose_tuic(&minimal_plan("tuic", "tuic"))?;
            replace_string(
                &mut rendered,
                CERTIFICATE_PATH,
                certificate
                    .to_str()
                    .context("certificate path is not UTF-8")?,
            );
            replace_string(
                &mut rendered,
                PRIVATE_KEY_PATH,
                private_key
                    .to_str()
                    .context("private key path is not UTF-8")?,
            );
            rendered["server"] = json!("127.0.0.1:0");
            let candidate = directory.join("tuic.json");
            fs::write(&candidate, serde_json::to_vec_pretty(&rendered)?)?;
            assert_starts_under_timeout(
                Command::new(binary).arg("-c").arg(candidate),
                "TUIC server 1.0.0",
            )?;
        }
        fs::remove_dir_all(directory)?;
        Ok(())
    }

    fn assert_starts_under_timeout(command: &mut Command, runtime: &str) -> Result<()> {
        command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = command.spawn()?;
        thread::sleep(Duration::from_millis(500));
        if child.try_wait()?.is_some() {
            bail!("{runtime} rejected or could not start the isolated config");
        }
        child.kill()?;
        child.wait()?;
        Ok(())
    }
}
