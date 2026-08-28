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

const CERTIFICATE_PATH: &str = "/etc/infiproxy-cores/tls/fullchain.pem";
const PRIVATE_KEY_PATH: &str = "/etc/infiproxy-cores/tls/privkey.pem";
const RUNTIME_GROUP: &str = "infiproxy-runtime";

#[derive(Clone, Copy)]
enum Flavor {
    Xray,
    SingBox,
    Hysteria,
    Tuic,
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
            listeners: Mutex::new(ListenerState::default()),
        }
    }

    fn compose(&self, plan: &CorePlan) -> Result<Vec<u8>> {
        match self.flavor {
            Flavor::Xray => Ok(serde_json::to_vec_pretty(&compose_xray(plan)?)?),
            Flavor::SingBox => Ok(serde_json::to_vec_pretty(&compose_sing_box(plan)?)?),
            Flavor::Hysteria => Ok(serde_norway::to_string(&compose_hysteria(plan)?)?.into_bytes()),
            Flavor::Tuic => Ok(serde_json::to_vec_pretty(&compose_tuic(plan)?)?),
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
            Flavor::Hysteria => {
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

    fn stage_config(&self, plan: &CorePlan, transaction_dir: &Path) -> Result<PathBuf> {
        let candidate = transaction_dir.join(match self.flavor {
            Flavor::Hysteria => "candidate.yaml",
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
            .map(|user| json!({"id": user["uuid"], "email": user["username"]}))
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
            "vless-reality-tcp" | "vless-reality-xhttp" => {
                let user_entries = users(payload)?
                    .iter()
                    .map(|user| json!({"name":user["username"],"uuid":user["uuid"]}))
                    .collect::<Vec<_>>();
                let mut inbound = json!({
                    "type":"vless","tag":tag,"listen":"::","listen_port":listen_port,
                    "users":user_entries,
                    "tls":{"enabled":true,"server_name":config_text(config,"server_name")?,"reality":{"enabled":true,"handshake":{"server":config_text(config,"server_name")?,"server_port":443},"private_key":resolved_secret(payload,"private_key_secret")?,"short_id":[resolved_secret(payload,"short_id_secret")?]}}
                });
                if fragment.capability == "vless-reality-xhttp" {
                    inbound["transport"] =
                        json!({"type":"xhttp","path":config_text(config,"path")?});
                }
                inbound
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
    }
    Ok(users)
}

pub(super) fn registry() -> Result<CoreRegistry> {
    let all = [
        "vless-reality-tcp",
        "vless-reality-xhttp",
        "shadowsocks2022-shadow-tls",
        "hysteria2",
        "any-tls",
        "tuic",
    ];
    let adapters = [
        ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "xray",
            display_name: "Xray",
            service: "infiproxy-xray.service",
            flavor: Flavor::Xray,
            binary: "/opt/infiproxy/cores/xray/current/xray",
            config: "/etc/infiproxy-cores/xray/config.json",
            capabilities: &all[..2],
            selection_priority: 100,
        }),
        ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "sing-box",
            display_name: "sing-box",
            service: "infiproxy-sing-box.service",
            flavor: Flavor::SingBox,
            binary: "/opt/infiproxy/cores/sing-box/current/sing-box",
            config: "/etc/infiproxy-cores/sing-box/config.json",
            capabilities: &all,
            selection_priority: 10,
        }),
        ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "hysteria",
            display_name: "Hysteria",
            service: "infiproxy-hysteria.service",
            flavor: Flavor::Hysteria,
            binary: "/opt/infiproxy/cores/hysteria/current/hysteria",
            config: "/etc/infiproxy-cores/hysteria/config.yaml",
            capabilities: &all[3..4],
            selection_priority: 100,
        }),
        ManagedCoreAdapter::new(ManagedCoreSpec {
            id: "tuic",
            display_name: "TUIC",
            service: "infiproxy-tuic.service",
            flavor: Flavor::Tuic,
            binary: "/opt/infiproxy/cores/tuic/current/tuic-server",
            config: "/etc/infiproxy-cores/tuic/config.json",
            capabilities: &all[5..6],
            selection_priority: 100,
        }),
    ];
    let mut registry = CoreRegistry::default();
    for adapter in adapters {
        registry.register(Arc::new(adapter))?;
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

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
        ] {
            assert!(capabilities.contains(capability));
        }
    }
}
