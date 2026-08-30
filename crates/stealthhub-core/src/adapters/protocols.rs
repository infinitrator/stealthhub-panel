//! Built-in protocol adapters and their adapter-owned schemas.

use std::{collections::BTreeSet, sync::Arc};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::{
    adapter::{
        AdapterMaturity, ClientRenderContext, ConfigField, ConfigFieldKind, ListenerClaim,
        ListenerNetwork, ProtocolAdapter, ProtocolAdapterManifest, ProtocolComposition,
        ProtocolRegistry, SecretRef, ServerFragment, ServerRenderContext, UserParticipation,
        ValidatedRuntime, ADAPTER_API_VERSION,
    },
    models::{ProtocolProfile, ProxyRole},
};

#[derive(Clone, Copy)]
enum Implementation {
    VlessXhttp,
    VlessTcp,
    VlessWrapped(SecurityWrapper),
    ShadowsocksShadowTls,
    Hysteria,
    AnyTlsLegacy,
    AnyTls(SecurityWrapper),
    Tuic,
    Trojan(SecurityWrapper),
    SnellV5(Option<SecurityWrapper>),
    MieruTcp,
    TrustTunnelH2,
    ShadowQuic,
    SudokuHttpMask,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecurityWrapper {
    StandardTls,
    Reality,
    ShadowTlsV3,
    ResTls,
    Jls,
}

struct JsonProtocolAdapter {
    manifest: ProtocolAdapterManifest,
    fields: Vec<ConfigField>,
    implementation: Implementation,
}

impl JsonProtocolAdapter {
    fn new(
        id: &str,
        display_name: &str,
        implementation: Implementation,
        fields: Vec<ConfigField>,
        user_participation: UserParticipation,
        listener_network: ListenerNetwork,
    ) -> Self {
        Self {
            manifest: ProtocolAdapterManifest {
                api_version: ADAPTER_API_VERSION,
                id: id.to_string(),
                display_name: display_name.to_string(),
                schema_version: 1,
                required_core_capabilities: BTreeSet::from([id.to_string()]),
                user_participation,
                listener_network,
                composition: composition(implementation),
            },
            fields,
            implementation,
        }
    }

    fn required_text<'a>(&self, config: &'a Value, name: &str) -> Result<&'a str> {
        let value = config
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .with_context(|| format!("adapter field `{name}` is required"))?;
        Ok(value)
    }

    fn optional_text<'a>(&self, config: &'a Value, name: &str) -> Result<Option<&'a str>> {
        match config.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.trim())),
            Some(_) => bail!("adapter field `{name}` must be a string"),
        }
    }

    fn secret(&self, context: &ClientRenderContext<'_>, name: &str) -> Result<String> {
        let reference = SecretRef::parse(self.required_text(&context.profile.config, name)?)?;
        Ok(context.secrets.resolve(&reference)?.expose().to_string())
    }

    fn base(&self, context: &ClientRenderContext<'_>, kind: &str) -> Map<String, Value> {
        Map::from_iter([
            ("name".to_string(), json!(context.profile.name)),
            ("type".to_string(), json!(kind)),
            ("server".to_string(), json!(context.profile.server)),
            ("port".to_string(), json!(context.profile.port)),
        ])
    }
}

fn composition(implementation: Implementation) -> ProtocolComposition {
    let (protocol, transport, security, flow, maturity) = match implementation {
        Implementation::VlessXhttp => ("vless", "xhttp", "reality", None, AdapterMaturity::Stable),
        Implementation::VlessTcp => (
            "vless",
            "tcp",
            "reality",
            Some("xtls-rprx-vision"),
            AdapterMaturity::Stable,
        ),
        Implementation::VlessWrapped(wrapper) => (
            "vless",
            "tcp",
            wrapper.label(),
            None,
            AdapterMaturity::Experimental,
        ),
        Implementation::ShadowsocksShadowTls => (
            "shadowsocks-2022",
            "tcp",
            "shadow-tls-v3",
            None,
            AdapterMaturity::Stable,
        ),
        Implementation::Hysteria => (
            "hysteria2",
            "quic",
            "tls+salamander",
            None,
            AdapterMaturity::Stable,
        ),
        Implementation::AnyTlsLegacy => {
            ("anytls", "tcp", "tls", None, AdapterMaturity::Experimental)
        }
        Implementation::AnyTls(wrapper) => {
            ("anytls", "tcp", wrapper.label(), None, wrapper.maturity())
        }
        Implementation::Tuic => ("tuic-v5", "quic", "tls", None, AdapterMaturity::Stable),
        Implementation::Trojan(wrapper) => {
            ("trojan", "tcp", wrapper.label(), None, wrapper.maturity())
        }
        Implementation::SnellV5(wrapper) => (
            "snell-v5",
            "tcp",
            wrapper.map_or("psk", SecurityWrapper::label),
            None,
            wrapper.map_or(AdapterMaturity::Stable, SecurityWrapper::maturity),
        ),
        Implementation::MieruTcp => (
            "mieru",
            "tcp",
            "protocol-auth",
            None,
            AdapterMaturity::Stable,
        ),
        Implementation::TrustTunnelH2 => (
            "trusttunnel",
            "h2",
            "tls",
            None,
            AdapterMaturity::Experimental,
        ),
        Implementation::ShadowQuic => (
            "shadowquic",
            "quic",
            "jls",
            None,
            AdapterMaturity::Experimental,
        ),
        Implementation::SudokuHttpMask => (
            "sudoku",
            "httpmask",
            "chacha20-poly1305",
            None,
            AdapterMaturity::Experimental,
        ),
    };
    ProtocolComposition {
        protocol: protocol.to_string(),
        transport: transport.to_string(),
        security: security.to_string(),
        flow: flow.map(str::to_string),
        maturity,
        client_baseline: Some("Mihomo v1.19.30".to_string()),
        preferred_runtime: Some(validated_runtime(implementation)),
        fallback_runtime: fallback_runtime(implementation),
        compatibility_note: compatibility_note(implementation).map(str::to_string),
    }
}

impl SecurityWrapper {
    const fn label(self) -> &'static str {
        match self {
            Self::StandardTls => "tls",
            Self::Reality => "reality",
            Self::ShadowTlsV3 => "shadow-tls-v3",
            Self::ResTls => "restls",
            Self::Jls => "jls",
        }
    }

    const fn maturity(self) -> AdapterMaturity {
        match self {
            Self::StandardTls | Self::Reality | Self::ShadowTlsV3 => AdapterMaturity::Stable,
            Self::ResTls | Self::Jls => AdapterMaturity::Experimental,
        }
    }
}

fn validated_runtime(implementation: Implementation) -> ValidatedRuntime {
    let (adapter_id, version, incompatible_from) = match implementation {
        Implementation::ShadowsocksShadowTls | Implementation::AnyTlsLegacy => {
            ("sing-box", "v1.13.20", None)
        }
        Implementation::Hysteria => ("hysteria", "app/v2.12.2", None),
        Implementation::Tuic => ("tuic", "tuic-server-1.0.0", None),
        _ => ("mihomo", "v1.19.30", None),
    };
    ValidatedRuntime {
        adapter_id: adapter_id.to_string(),
        version: version.to_string(),
        exact_pin: true,
        incompatible_from: incompatible_from.map(str::to_string),
    }
}

fn fallback_runtime(implementation: Implementation) -> Option<ValidatedRuntime> {
    matches!(
        implementation,
        Implementation::VlessTcp | Implementation::VlessXhttp
    )
    .then(|| ValidatedRuntime {
        adapter_id: "xray".to_string(),
        version: "v26.3.27".to_string(),
        exact_pin: true,
        incompatible_from: Some("v26.7.11".to_string()),
    })
}

const fn compatibility_note(implementation: Implementation) -> Option<&'static str> {
    match implementation {
        Implementation::VlessXhttp => Some("XHTTP must not use Vision flow."),
        Implementation::VlessTcp => Some("Vision and XUDP are required by this profile."),
        Implementation::VlessWrapped(_) => {
            Some("This TCP profile uses exactly one TLS camouflage wrapper and no Vision flow.")
        }
        Implementation::AnyTlsLegacy | Implementation::AnyTls(_) => {
            Some("AnyTLS with REALITY is unsupported by Mihomo.")
        }
        Implementation::TrustTunnelH2 => {
            Some("HTTP/3 is intentionally not exposed until dual TCP/UDP claims are modeled.")
        }
        Implementation::ShadowQuic => {
            Some("JLS is intrinsic; 0-RTT is disabled to avoid pre-authentication replay risk.")
        }
        Implementation::SudokuHttpMask => Some(
            "Legacy HTTPMask is paired with authenticated AEAD and does not claim CDN support.",
        ),
        _ => None,
    }
}

impl ProtocolAdapter for JsonProtocolAdapter {
    fn manifest(&self) -> &ProtocolAdapterManifest {
        &self.manifest
    }

    fn fields(&self) -> &[ConfigField] {
        &self.fields
    }

    fn validate_config(&self, schema_version: u32, config: &Value) -> Result<()> {
        if schema_version != self.manifest.schema_version || !config.is_object() {
            bail!("unsupported adapter configuration schema");
        }
        for field in &self.fields {
            if field.required {
                self.required_text(config, &field.name)?;
            } else {
                self.optional_text(config, &field.name)?;
            }
            if field.kind == ConfigFieldKind::SecretRef {
                if let Some(value) = self.optional_text(config, &field.name)? {
                    SecretRef::parse(value)?;
                }
            }
        }
        Ok(())
    }

    fn migrate_config(&self, from_version: u32, mut config: Value) -> Result<(u32, Value)> {
        if from_version > self.manifest.schema_version {
            bail!("adapter configuration is newer than this adapter");
        }
        let object = config
            .as_object_mut()
            .context("adapter configuration must be an object")?;
        if matches!(
            self.implementation,
            Implementation::VlessXhttp
                | Implementation::VlessTcp
                | Implementation::Trojan(SecurityWrapper::Reality)
        ) {
            object
                .entry("private_key_secret")
                .or_insert_with(|| json!("xray.reality.private_key"));
        }
        self.validate_config(self.manifest.schema_version, &config)?;
        Ok((self.manifest.schema_version, config))
    }

    fn client_secret_references(&self, config: &Value) -> Result<Vec<SecretRef>> {
        self.validate_config(self.manifest.schema_version, config)?;
        self.fields
            .iter()
            .filter(|field| field.kind == ConfigFieldKind::SecretRef)
            .filter(|field| field.name != "private_key_secret")
            .filter_map(|field| config.get(&field.name).and_then(Value::as_str))
            .filter(|value| !value.trim().is_empty())
            .map(SecretRef::parse)
            .collect()
    }

    fn server_secret_references(&self, config: &Value) -> Result<Vec<SecretRef>> {
        self.validate_config(self.manifest.schema_version, config)?;
        self.fields
            .iter()
            .filter(|field| field.kind == ConfigFieldKind::SecretRef)
            .filter(|field| field.name != "public_key_secret")
            .filter_map(|field| config.get(&field.name).and_then(Value::as_str))
            .filter(|value| !value.trim().is_empty())
            .map(SecretRef::parse)
            .collect()
    }

    fn server_only_secret_references(&self, config: &Value) -> Result<Vec<SecretRef>> {
        self.validate_config(self.manifest.schema_version, config)?;
        if matches!(
            self.implementation,
            Implementation::VlessXhttp
                | Implementation::VlessTcp
                | Implementation::Trojan(SecurityWrapper::Reality)
        ) {
            return Ok(vec![SecretRef::parse(
                self.required_text(config, "private_key_secret")?,
            )?]);
        }
        Ok(Vec::new())
    }

    fn render_client(&self, context: &ClientRenderContext<'_>) -> Result<Value> {
        self.validate_config(context.profile.schema_version, &context.profile.config)?;
        let value = match self.implementation {
            Implementation::VlessXhttp => {
                let server_name = self.required_text(&context.profile.config, "server_name")?;
                let mut proxy = self.base(context, "vless");
                proxy.extend(Map::from_iter([
                    ("udp".to_string(), json!(true)),
                    ("uuid".to_string(), json!(context.user.uuid)),
                    ("encryption".to_string(), json!("")),
                    ("tls".to_string(), json!(true)),
                    ("servername".to_string(), json!(server_name)),
                    ("client-fingerprint".to_string(), json!("chrome")),
                    (
                        "reality-opts".to_string(),
                        json!({
                            "public-key": self.secret(context, "public_key_secret")?,
                            "short-id": self.secret(context, "short_id_secret")?
                        }),
                    ),
                    ("network".to_string(), json!("xhttp")),
                    (
                        "xhttp-opts".to_string(),
                        json!({
                            "path": self.required_text(&context.profile.config, "path")?,
                            "host": server_name
                        }),
                    ),
                ]));
                Value::Object(proxy)
            }
            Implementation::VlessTcp => {
                let mut proxy = self.base(context, "vless");
                proxy.extend(Map::from_iter([
                    ("udp".to_string(), json!(true)),
                    ("uuid".to_string(), json!(context.user.uuid)),
                    ("encryption".to_string(), json!("")),
                    ("network".to_string(), json!("tcp")),
                    ("flow".to_string(), json!("xtls-rprx-vision")),
                    ("packet-encoding".to_string(), json!("xudp")),
                    ("tls".to_string(), json!(true)),
                    (
                        "servername".to_string(),
                        json!(self.required_text(&context.profile.config, "server_name")?),
                    ),
                    ("client-fingerprint".to_string(), json!("chrome")),
                    (
                        "reality-opts".to_string(),
                        json!({
                            "public-key": self.secret(context, "public_key_secret")?,
                            "short-id": self.secret(context, "short_id_secret")?
                        }),
                    ),
                ]));
                Value::Object(proxy)
            }
            Implementation::VlessWrapped(wrapper) => {
                let mut proxy = self.base(context, "vless");
                proxy.extend(Map::from_iter([
                    ("udp".to_string(), json!(true)),
                    ("uuid".to_string(), json!(context.user.uuid)),
                    ("encryption".to_string(), json!("")),
                    ("network".to_string(), json!("tcp")),
                    ("tls".to_string(), json!(true)),
                    (
                        "servername".to_string(),
                        json!(self.required_text(&context.profile.config, "sni")?),
                    ),
                    ("client-fingerprint".to_string(), json!("chrome")),
                ]));
                apply_client_wrapper(self, context, &mut proxy, wrapper)?;
                Value::Object(proxy)
            }
            Implementation::ShadowsocksShadowTls => {
                let mut proxy = self.base(context, "ss");
                proxy.extend(Map::from_iter([
                    ("cipher".to_string(), json!("2022-blake3-aes-256-gcm")),
                    (
                        "password".to_string(),
                        json!(self.secret(context, "password_secret")?),
                    ),
                    ("udp".to_string(), json!(true)),
                    ("plugin".to_string(), json!("shadow-tls")),
                    ("client-fingerprint".to_string(), json!("chrome")),
                    (
                        "plugin-opts".to_string(),
                        json!({
                            "host": self.required_text(&context.profile.config, "server_name")?,
                            "password": self.secret(context, "shadow_tls_password_secret")?,
                            "version": 3
                        }),
                    ),
                ]));
                Value::Object(proxy)
            }
            Implementation::Hysteria => {
                let mut proxy = self.base(context, "hysteria2");
                proxy.extend(Map::from_iter([
                    (
                        "password".to_string(),
                        json!(self.secret(context, "password_secret")?),
                    ),
                    (
                        "sni".to_string(),
                        json!(self.required_text(&context.profile.config, "sni")?),
                    ),
                    ("alpn".to_string(), json!(["h3"])),
                ]));
                if let Some(reference) =
                    self.optional_text(&context.profile.config, "obfs_password_secret")?
                {
                    let value = context
                        .secrets
                        .resolve(&SecretRef::parse(reference)?)?
                        .expose()
                        .to_string();
                    proxy.insert("obfs".to_string(), json!("salamander"));
                    proxy.insert("obfs-password".to_string(), json!(value));
                }
                Value::Object(proxy)
            }
            Implementation::AnyTlsLegacy => {
                let mut proxy = self.base(context, "anytls");
                proxy.extend(Map::from_iter([
                    (
                        "password".to_string(),
                        json!(self.secret(context, "password_secret")?),
                    ),
                    ("client-fingerprint".to_string(), json!("chrome")),
                    ("udp".to_string(), json!(true)),
                    (
                        "sni".to_string(),
                        json!(self.required_text(&context.profile.config, "sni")?),
                    ),
                ]));
                Value::Object(proxy)
            }
            Implementation::AnyTls(wrapper) => {
                let mut proxy = self.base(context, "anytls");
                proxy.extend(Map::from_iter([
                    (
                        "password".to_string(),
                        json!(self.secret(context, "password_secret")?),
                    ),
                    ("client-fingerprint".to_string(), json!("chrome")),
                    ("udp".to_string(), json!(true)),
                    (
                        "sni".to_string(),
                        json!(self.required_text(&context.profile.config, "sni")?),
                    ),
                ]));
                apply_client_wrapper(self, context, &mut proxy, wrapper)?;
                Value::Object(proxy)
            }
            Implementation::Tuic => {
                let mut proxy = self.base(context, "tuic");
                proxy.extend(Map::from_iter([
                    ("uuid".to_string(), json!(context.user.uuid)),
                    (
                        "password".to_string(),
                        json!(self.secret(context, "password_secret")?),
                    ),
                    ("udp".to_string(), json!(true)),
                    (
                        "sni".to_string(),
                        json!(self.required_text(&context.profile.config, "sni")?),
                    ),
                    ("alpn".to_string(), json!(["h3"])),
                ]));
                Value::Object(proxy)
            }
            Implementation::Trojan(wrapper) => {
                let mut proxy = self.base(context, "trojan");
                proxy.extend(Map::from_iter([
                    ("password".to_string(), json!(context.user.uuid)),
                    ("udp".to_string(), json!(true)),
                    ("network".to_string(), json!("tcp")),
                    (
                        "sni".to_string(),
                        json!(self.required_text(&context.profile.config, "sni")?),
                    ),
                    ("alpn".to_string(), json!(["h2", "http/1.1"])),
                    ("client-fingerprint".to_string(), json!("chrome")),
                ]));
                apply_client_wrapper(self, context, &mut proxy, wrapper)?;
                Value::Object(proxy)
            }
            Implementation::SnellV5(wrapper) => {
                let mut proxy = self.base(context, "snell");
                proxy.extend(Map::from_iter([
                    (
                        "psk".to_string(),
                        json!(self.secret(context, "psk_secret")?),
                    ),
                    ("version".to_string(), json!(5)),
                    ("udp".to_string(), json!(true)),
                ]));
                if let Some(wrapper) = wrapper {
                    apply_snell_client_wrapper(self, context, &mut proxy, wrapper)?;
                }
                Value::Object(proxy)
            }
            Implementation::MieruTcp => {
                let mut proxy = self.base(context, "mieru");
                proxy.extend(Map::from_iter([
                    ("transport".to_string(), json!("TCP")),
                    ("username".to_string(), json!(context.user.uuid)),
                    (
                        "password".to_string(),
                        json!(self.secret(context, "password_secret")?),
                    ),
                    ("multiplexing".to_string(), json!("MULTIPLEXING_LOW")),
                    ("handshake-mode".to_string(), json!("HANDSHAKE_STANDARD")),
                ]));
                Value::Object(proxy)
            }
            Implementation::TrustTunnelH2 => {
                let mut proxy = self.base(context, "trusttunnel");
                proxy.extend(Map::from_iter([
                    ("username".to_string(), json!(context.user.uuid)),
                    ("password".to_string(), json!(context.user.uuid)),
                    ("health-check".to_string(), json!(true)),
                    ("udp".to_string(), json!(false)),
                    ("quic".to_string(), json!(false)),
                    (
                        "sni".to_string(),
                        json!(self.required_text(&context.profile.config, "sni")?),
                    ),
                    ("alpn".to_string(), json!(["h2"])),
                    ("client-fingerprint".to_string(), json!("chrome")),
                ]));
                Value::Object(proxy)
            }
            Implementation::ShadowQuic => {
                let mut proxy = self.base(context, "shadowquic");
                proxy.extend(Map::from_iter([
                    ("username".to_string(), json!(context.user.uuid)),
                    ("password".to_string(), json!(context.user.uuid)),
                    (
                        "sni".to_string(),
                        json!(self.required_text(&context.profile.config, "sni")?),
                    ),
                    ("alpn".to_string(), json!(["h3"])),
                    ("quic-versions".to_string(), json!(["v1"])),
                    ("udp-over-stream".to_string(), json!(false)),
                    ("zero-rtt".to_string(), json!(false)),
                    ("congestion-controller".to_string(), json!("cubic")),
                ]));
                Value::Object(proxy)
            }
            Implementation::SudokuHttpMask => {
                let mut proxy = self.base(context, "sudoku");
                proxy.extend(Map::from_iter([
                    (
                        "key".to_string(),
                        json!(self.secret(context, "key_secret")?),
                    ),
                    ("aead-method".to_string(), json!("chacha20-poly1305")),
                    ("padding-min".to_string(), json!(2)),
                    ("padding-max".to_string(), json!(7)),
                    ("table-type".to_string(), json!("prefer_ascii")),
                    ("multiplex".to_string(), json!("off")),
                    (
                        "httpmask".to_string(),
                        json!({
                            "disable": false,
                            "mode": "legacy",
                            "path-root": self.required_text(&context.profile.config, "path_root")?,
                            "multiplex": "off"
                        }),
                    ),
                    ("enable-pure-downlink".to_string(), json!(false)),
                ]));
                Value::Object(proxy)
            }
        };
        Ok(value)
    }

    fn render_server(&self, context: &ServerRenderContext<'_>) -> Result<ServerFragment> {
        self.validate_config(context.profile.schema_version, &context.profile.config)?;
        let secrets = self
            .server_secret_references(&context.profile.config)?
            .into_iter()
            .map(|reference| {
                let value = context.secrets.resolve(&reference)?;
                Ok((reference.as_str().to_string(), json!(value.expose())))
            })
            .collect::<Result<Map<String, Value>>>()?;
        let users = if self.manifest.user_participation.requires_individual_users() {
            context
                .users
                .iter()
                .map(|user| json!({"username": user.username, "uuid": user.uuid}))
                .collect()
        } else {
            Vec::new()
        };
        Ok(ServerFragment {
            profile_id: context.profile.name.clone(),
            capability: self.manifest.id.clone(),
            expected_user_ids: self
                .manifest
                .user_participation
                .requires_individual_users()
                .then(|| context.users.iter().map(|user| user.uuid.clone()).collect()),
            payload: json!({
            "server": context.profile.server,
            "port": context.profile.port,
            "config": context.profile.config,
            "users": users,
            "resolved_secrets": secrets,
            "managed_resource_id": context.profile.managed_resource_id,
            }),
            listeners: vec![ListenerClaim {
                network: self.manifest.listener_network,
                port: context.profile.port,
            }],
        })
    }
}

fn apply_client_wrapper(
    adapter: &JsonProtocolAdapter,
    context: &ClientRenderContext<'_>,
    proxy: &mut Map<String, Value>,
    wrapper: SecurityWrapper,
) -> Result<()> {
    match wrapper {
        SecurityWrapper::StandardTls => {}
        SecurityWrapper::Reality => {
            proxy.insert(
                "reality-opts".to_string(),
                json!({
                    "public-key": adapter.secret(context, "public_key_secret")?,
                    "short-id": adapter.secret(context, "short_id_secret")?
                }),
            );
        }
        SecurityWrapper::ShadowTlsV3 => {
            proxy.insert(
                "shadow-tls-opts".to_string(),
                json!({
                    "version": 3,
                    "password": adapter.secret(context, "shadow_tls_password_secret")?
                }),
            );
        }
        SecurityWrapper::ResTls => {
            proxy.insert(
                "restls-opts".to_string(),
                json!({
                    "password": adapter.secret(context, "restls_password_secret")?,
                    "version-hint": "tls13"
                }),
            );
        }
        SecurityWrapper::Jls => {
            proxy.insert(
                "jls-opts".to_string(),
                json!({
                    "username": adapter.secret(context, "jls_username_secret")?,
                    "password": adapter.secret(context, "jls_password_secret")?
                }),
            );
        }
    }
    Ok(())
}

fn apply_snell_client_wrapper(
    adapter: &JsonProtocolAdapter,
    context: &ClientRenderContext<'_>,
    proxy: &mut Map<String, Value>,
    wrapper: SecurityWrapper,
) -> Result<()> {
    let host = adapter.required_text(&context.profile.config, "sni")?;
    let options = match wrapper {
        SecurityWrapper::ShadowTlsV3 => json!({
            "mode": "shadow-tls", "host": host, "version": 3,
            "password": adapter.secret(context, "shadow_tls_password_secret")?
        }),
        SecurityWrapper::ResTls => json!({
            "mode": "restls", "host": host, "version-hint": "tls13",
            "password": adapter.secret(context, "restls_password_secret")?
        }),
        SecurityWrapper::Jls => json!({
            "mode": "jls", "host": host,
            "username": adapter.secret(context, "jls_username_secret")?,
            "password": adapter.secret(context, "jls_password_secret")?
        }),
        SecurityWrapper::StandardTls | SecurityWrapper::Reality => {
            bail!("unsupported Snell security wrapper")
        }
    };
    proxy.insert("obfs-opts".to_string(), options);
    Ok(())
}

fn text(name: &str, label: &str, help: &str) -> ConfigField {
    ConfigField {
        name: name.to_string(),
        label: label.to_string(),
        help: help.to_string(),
        kind: ConfigFieldKind::Text,
        required: true,
    }
}

fn secret(name: &str, label: &str, help: &str, required: bool) -> ConfigField {
    ConfigField {
        name: name.to_string(),
        label: label.to_string(),
        help: help.to_string(),
        kind: ConfigFieldKind::SecretRef,
        required,
    }
}

fn password_and_sni_fields() -> Vec<ConfigField> {
    vec![
        secret(
            "password_secret",
            "Password",
            "Secret reference containing the shared protocol password.",
            true,
        ),
        text("sni", "SNI", "TLS or camouflage destination hostname."),
    ]
}

fn wrapper_fields(wrapper: SecurityWrapper) -> Vec<ConfigField> {
    match wrapper {
        SecurityWrapper::StandardTls => Vec::new(),
        SecurityWrapper::Reality => vec![
            secret(
                "public_key_secret",
                "REALITY public key",
                "Client-visible REALITY public key reference.",
                true,
            ),
            secret(
                "short_id_secret",
                "REALITY short ID",
                "Client-visible REALITY short ID reference.",
                true,
            ),
            secret(
                "private_key_secret",
                "REALITY private key",
                "Root-resolved server-only private key reference.",
                true,
            ),
        ],
        SecurityWrapper::ShadowTlsV3 => vec![secret(
            "shadow_tls_password_secret",
            "ShadowTLS v3 password",
            "Shared ShadowTLS v3 credential reference.",
            true,
        )],
        SecurityWrapper::ResTls => vec![secret(
            "restls_password_secret",
            "ResTLS password",
            "Shared ResTLS credential reference.",
            true,
        )],
        SecurityWrapper::Jls => vec![
            secret(
                "jls_username_secret",
                "JLS username",
                "Shared JLS username reference.",
                true,
            ),
            secret(
                "jls_password_secret",
                "JLS password",
                "Shared JLS password reference.",
                true,
            ),
        ],
    }
}

fn wrapped_fields(mut base: Vec<ConfigField>, wrapper: SecurityWrapper) -> Vec<ConfigField> {
    base.extend(wrapper_fields(wrapper));
    base
}

pub(super) fn registry() -> Result<ProtocolRegistry> {
    let mut registry = ProtocolRegistry::default();
    let adapters = [
        JsonProtocolAdapter::new(
            "vless-reality-xhttp",
            "VLESS REALITY XHTTP",
            Implementation::VlessXhttp,
            vec![
                text("server_name", "Server name", "TLS camouflage hostname."),
                text("path", "XHTTP path", "Client HTTP transport path."),
                secret(
                    "public_key_secret",
                    "REALITY public key",
                    "Secret reference containing the public key.",
                    true,
                ),
                secret(
                    "short_id_secret",
                    "REALITY short ID",
                    "Secret reference containing the short ID.",
                    true,
                ),
                secret(
                    "private_key_secret",
                    "REALITY private key",
                    "Root-resolved server private key reference.",
                    true,
                ),
            ],
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "vless-reality-tcp",
            "VLESS REALITY TCP",
            Implementation::VlessTcp,
            vec![
                text("server_name", "Server name", "TLS camouflage hostname."),
                secret(
                    "public_key_secret",
                    "REALITY public key",
                    "Secret reference containing the public key.",
                    true,
                ),
                secret(
                    "short_id_secret",
                    "REALITY short ID",
                    "Secret reference containing the short ID.",
                    true,
                ),
                secret(
                    "private_key_secret",
                    "REALITY private key",
                    "Root-resolved server private key reference.",
                    true,
                ),
            ],
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "vless-shadowtls-v3",
            "VLESS + ShadowTLS v3",
            Implementation::VlessWrapped(SecurityWrapper::ShadowTlsV3),
            wrapped_fields(
                vec![text("sni", "SNI", "ShadowTLS destination hostname.")],
                SecurityWrapper::ShadowTlsV3,
            ),
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "vless-restls",
            "VLESS + ResTLS",
            Implementation::VlessWrapped(SecurityWrapper::ResTls),
            wrapped_fields(
                vec![text("sni", "SNI", "ResTLS destination hostname.")],
                SecurityWrapper::ResTls,
            ),
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "vless-jls",
            "VLESS + JLS",
            Implementation::VlessWrapped(SecurityWrapper::Jls),
            wrapped_fields(
                vec![text("sni", "SNI", "JLS destination hostname.")],
                SecurityWrapper::Jls,
            ),
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "shadowsocks2022-shadow-tls",
            "Shadowsocks 2022 + ShadowTLS",
            Implementation::ShadowsocksShadowTls,
            vec![
                text(
                    "server_name",
                    "Server name",
                    "ShadowTLS camouflage hostname.",
                ),
                secret(
                    "password_secret",
                    "Shadowsocks password",
                    "Secret reference containing the method key.",
                    true,
                ),
                secret(
                    "shadow_tls_password_secret",
                    "ShadowTLS password",
                    "Secret reference containing the plugin password.",
                    true,
                ),
            ],
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "hysteria2",
            "Hysteria 2",
            Implementation::Hysteria,
            vec![
                secret(
                    "password_secret",
                    "Password",
                    "Secret reference containing the authentication password.",
                    true,
                ),
                text("sni", "SNI", "TLS certificate hostname."),
                secret(
                    "obfs_password_secret",
                    "Obfuscation password",
                    "Optional salamander secret reference.",
                    false,
                ),
            ],
            UserParticipation::SharedCredential,
            ListenerNetwork::Udp,
        ),
        JsonProtocolAdapter::new(
            "any-tls",
            "AnyTLS TLS (legacy ID)",
            Implementation::AnyTlsLegacy,
            password_and_sni_fields(),
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "anytls-tls",
            "AnyTLS TLS",
            Implementation::AnyTls(SecurityWrapper::StandardTls),
            password_and_sni_fields(),
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "anytls-shadowtls-v3",
            "AnyTLS + ShadowTLS v3",
            Implementation::AnyTls(SecurityWrapper::ShadowTlsV3),
            wrapped_fields(password_and_sni_fields(), SecurityWrapper::ShadowTlsV3),
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "anytls-restls",
            "AnyTLS + ResTLS",
            Implementation::AnyTls(SecurityWrapper::ResTls),
            wrapped_fields(password_and_sni_fields(), SecurityWrapper::ResTls),
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "anytls-jls",
            "AnyTLS + JLS",
            Implementation::AnyTls(SecurityWrapper::Jls),
            wrapped_fields(password_and_sni_fields(), SecurityWrapper::Jls),
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "tuic",
            "TUIC",
            Implementation::Tuic,
            vec![
                secret(
                    "password_secret",
                    "Password",
                    "Secret reference containing the user password.",
                    true,
                ),
                text("sni", "SNI", "TLS certificate hostname."),
            ],
            UserParticipation::PerUserUuid,
            ListenerNetwork::Udp,
        ),
        JsonProtocolAdapter::new(
            "trojan-tls",
            "Trojan TLS/uTLS",
            Implementation::Trojan(SecurityWrapper::StandardTls),
            vec![text("sni", "SNI", "TLS certificate hostname.")],
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "trojan-shadowtls-v3",
            "Trojan + ShadowTLS v3",
            Implementation::Trojan(SecurityWrapper::ShadowTlsV3),
            wrapped_fields(
                vec![text("sni", "SNI", "ShadowTLS destination hostname.")],
                SecurityWrapper::ShadowTlsV3,
            ),
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "trojan-restls",
            "Trojan + ResTLS",
            Implementation::Trojan(SecurityWrapper::ResTls),
            wrapped_fields(
                vec![text("sni", "SNI", "ResTLS destination hostname.")],
                SecurityWrapper::ResTls,
            ),
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "trojan-jls",
            "Trojan + JLS",
            Implementation::Trojan(SecurityWrapper::Jls),
            wrapped_fields(
                vec![text("sni", "SNI", "JLS destination hostname.")],
                SecurityWrapper::Jls,
            ),
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "trojan-reality",
            "Trojan + REALITY",
            Implementation::Trojan(SecurityWrapper::Reality),
            wrapped_fields(
                vec![text("sni", "SNI", "REALITY destination hostname.")],
                SecurityWrapper::Reality,
            ),
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "snell-v5",
            "Snell v5",
            Implementation::SnellV5(None),
            vec![secret(
                "psk_secret",
                "Pre-shared key",
                "Secret reference containing the shared Snell key.",
                true,
            )],
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "snell-v5-shadowtls-v3",
            "Snell v5 + ShadowTLS v3",
            Implementation::SnellV5(Some(SecurityWrapper::ShadowTlsV3)),
            wrapped_fields(
                vec![
                    secret(
                        "psk_secret",
                        "Pre-shared key",
                        "Shared Snell key reference.",
                        true,
                    ),
                    text("sni", "SNI", "ShadowTLS destination hostname."),
                ],
                SecurityWrapper::ShadowTlsV3,
            ),
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "snell-v5-restls",
            "Snell v5 + ResTLS",
            Implementation::SnellV5(Some(SecurityWrapper::ResTls)),
            wrapped_fields(
                vec![
                    secret(
                        "psk_secret",
                        "Pre-shared key",
                        "Shared Snell key reference.",
                        true,
                    ),
                    text("sni", "SNI", "ResTLS destination hostname."),
                ],
                SecurityWrapper::ResTls,
            ),
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "snell-v5-jls",
            "Snell v5 + JLS",
            Implementation::SnellV5(Some(SecurityWrapper::Jls)),
            wrapped_fields(
                vec![
                    secret(
                        "psk_secret",
                        "Pre-shared key",
                        "Shared Snell key reference.",
                        true,
                    ),
                    text("sni", "SNI", "JLS destination hostname."),
                ],
                SecurityWrapper::Jls,
            ),
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "mieru",
            "Mieru TCP",
            Implementation::MieruTcp,
            vec![secret(
                "password_secret",
                "Password",
                "Shared password paired with each user's UUID username.",
                true,
            )],
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "trusttunnel-h2",
            "TrustTunnel HTTP/2",
            Implementation::TrustTunnelH2,
            vec![text("sni", "SNI", "TLS certificate hostname.")],
            UserParticipation::PerUserUuid,
            ListenerNetwork::Tcp,
        ),
        JsonProtocolAdapter::new(
            "shadowquic",
            "ShadowQUIC",
            Implementation::ShadowQuic,
            vec![text("sni", "SNI", "JLS camouflage upstream hostname.")],
            UserParticipation::PerUserUuid,
            ListenerNetwork::Udp,
        ),
        JsonProtocolAdapter::new(
            "sudoku-httpmask",
            "Sudoku HTTPMask",
            Implementation::SudokuHttpMask,
            vec![
                secret(
                    "key_secret",
                    "Shared key",
                    "Secret reference containing the shared Sudoku UUID or key.",
                    true,
                ),
                text(
                    "path_root",
                    "HTTPMask path root",
                    "Matching first-level path prefix used by both peers.",
                ),
            ],
            UserParticipation::SharedCredential,
            ListenerNetwork::Tcp,
        ),
    ];
    for adapter in adapters {
        registry.register(Arc::new(adapter))?;
    }
    Ok(registry)
}

/// Compatibility defaults inserted only when a profile name is absent.
pub fn default_profiles() -> Vec<ProtocolProfile> {
    vec![
        profile(
            "VLESS-XHTTP-SAFE",
            "vless-reality-xhttp",
            ProxyRole::AutoSafe,
            8443,
            json!({"server_name":"www.microsoft.com","path":"/api/v1","public_key_secret":"xray.reality.public_key","short_id_secret":"xray.reality.short_id","private_key_secret":"xray.reality.private_key"}),
        ),
        profile(
            "VLESS-REALITY-TCP-FALLBACK",
            "vless-reality-tcp",
            ProxyRole::Compatibility,
            7443,
            json!({"server_name":"www.microsoft.com","public_key_secret":"xray.reality.public_key","short_id_secret":"xray.reality.short_id","private_key_secret":"xray.reality.private_key"}),
        ),
        profile(
            "VLESS-SHADOWTLS-V3-EXPERIMENTAL",
            "vless-shadowtls-v3",
            ProxyRole::Compatibility,
            7543,
            json!({"sni":"www.apple.com","shadow_tls_password_secret":"shadowtls.password"}),
        ),
        profile(
            "VLESS-RESTLS-EXPERIMENTAL",
            "vless-restls",
            ProxyRole::Compatibility,
            7643,
            json!({"sni":"www.apple.com","restls_password_secret":"restls.password"}),
        ),
        profile(
            "VLESS-JLS-EXPERIMENTAL",
            "vless-jls",
            ProxyRole::Compatibility,
            7743,
            json!({"sni":"www.apple.com","jls_username_secret":"jls.username","jls_password_secret":"jls.password"}),
        ),
        profile(
            "SS2022-SHADOWTLS-FALLBACK",
            "shadowsocks2022-shadow-tls",
            ProxyRole::Compatibility,
            9443,
            json!({"server_name":"www.apple.com","password_secret":"shadowsocks.2022.password","shadow_tls_password_secret":"shadowtls.password"}),
        ),
        profile(
            "ANYTLS-EXPERIMENTAL",
            "any-tls",
            ProxyRole::Compatibility,
            10443,
            json!({"password_secret":"anytls.password","sni":"www.apple.com"}),
        ),
        profile(
            "ANYTLS-TLS",
            "anytls-tls",
            ProxyRole::Compatibility,
            10543,
            json!({"password_secret":"anytls.password","sni":"node.infiproxy.local"}),
        ),
        profile(
            "ANYTLS-SHADOWTLS-V3",
            "anytls-shadowtls-v3",
            ProxyRole::Compatibility,
            10643,
            json!({"password_secret":"anytls.password","sni":"www.apple.com","shadow_tls_password_secret":"shadowtls.password"}),
        ),
        profile(
            "ANYTLS-RESTLS-EXPERIMENTAL",
            "anytls-restls",
            ProxyRole::Compatibility,
            10743,
            json!({"password_secret":"anytls.password","sni":"www.apple.com","restls_password_secret":"restls.password"}),
        ),
        profile(
            "ANYTLS-JLS-EXPERIMENTAL",
            "anytls-jls",
            ProxyRole::Compatibility,
            10843,
            json!({"password_secret":"anytls.password","sni":"www.apple.com","jls_username_secret":"jls.username","jls_password_secret":"jls.password"}),
        ),
        profile(
            "HYSTERIA2-SPEED",
            "hysteria2",
            ProxyRole::Speed,
            443,
            json!({"password_secret":"hysteria2.password","sni":"www.bing.com","obfs_password_secret":"hysteria2.obfs_password"}),
        ),
        profile(
            "TUIC-SPEED",
            "tuic",
            ProxyRole::Speed,
            11443,
            json!({"password_secret":"tuic.password","sni":"www.github.com"}),
        ),
        profile(
            "TROJAN-TLS-COMPATIBILITY",
            "trojan-tls",
            ProxyRole::Compatibility,
            12443,
            json!({"sni":"node.infiproxy.local"}),
        ),
        profile(
            "TROJAN-SHADOWTLS-V3",
            "trojan-shadowtls-v3",
            ProxyRole::Compatibility,
            12543,
            json!({"sni":"www.apple.com","shadow_tls_password_secret":"shadowtls.password"}),
        ),
        profile(
            "TROJAN-RESTLS-EXPERIMENTAL",
            "trojan-restls",
            ProxyRole::Compatibility,
            12643,
            json!({"sni":"www.apple.com","restls_password_secret":"restls.password"}),
        ),
        profile(
            "TROJAN-JLS-EXPERIMENTAL",
            "trojan-jls",
            ProxyRole::Compatibility,
            12743,
            json!({"sni":"www.apple.com","jls_username_secret":"jls.username","jls_password_secret":"jls.password"}),
        ),
        profile(
            "TROJAN-REALITY",
            "trojan-reality",
            ProxyRole::Compatibility,
            12843,
            json!({"sni":"www.microsoft.com","public_key_secret":"xray.reality.public_key","short_id_secret":"xray.reality.short_id","private_key_secret":"xray.reality.private_key"}),
        ),
        profile(
            "SNELL-V5-COMPATIBILITY",
            "snell-v5",
            ProxyRole::Compatibility,
            13443,
            json!({"psk_secret":"snell.psk"}),
        ),
        profile(
            "SNELL-V5-SHADOWTLS-V3",
            "snell-v5-shadowtls-v3",
            ProxyRole::Compatibility,
            13543,
            json!({"psk_secret":"snell.psk","sni":"www.apple.com","shadow_tls_password_secret":"shadowtls.password"}),
        ),
        profile(
            "SNELL-V5-RESTLS-EXPERIMENTAL",
            "snell-v5-restls",
            ProxyRole::Compatibility,
            13643,
            json!({"psk_secret":"snell.psk","sni":"www.apple.com","restls_password_secret":"restls.password"}),
        ),
        profile(
            "SNELL-V5-JLS-EXPERIMENTAL",
            "snell-v5-jls",
            ProxyRole::Compatibility,
            13743,
            json!({"psk_secret":"snell.psk","sni":"www.apple.com","jls_username_secret":"jls.username","jls_password_secret":"jls.password"}),
        ),
        profile(
            "MIERU-TCP-COMPATIBILITY",
            "mieru",
            ProxyRole::Compatibility,
            14443,
            json!({"password_secret":"mieru.password"}),
        ),
        profile(
            "TRUSTTUNNEL-H2-EXPERIMENTAL",
            "trusttunnel-h2",
            ProxyRole::Compatibility,
            15443,
            json!({"sni":"node.infiproxy.local"}),
        ),
        profile(
            "SHADOWQUIC-EXPERIMENTAL",
            "shadowquic",
            ProxyRole::Speed,
            16443,
            json!({"sni":"www.apple.com"}),
        ),
        profile(
            "SUDOKU-HTTPMASK-EXPERIMENTAL",
            "sudoku-httpmask",
            ProxyRole::Compatibility,
            17443,
            json!({"key_secret":"sudoku.key","path_root":"infiproxy"}),
        ),
    ]
}

/// Preserves the pre-adapter runtime placement during the one-way schema lift.
#[must_use]
pub fn legacy_runtime_preference(protocol_id: &str) -> Option<&'static str> {
    match protocol_id {
        "shadowsocks2022-shadow-tls" | "any-tls" => Some("sing-box"),
        "hysteria2" => Some("hysteria"),
        "tuic" => Some("tuic"),
        "vless-reality-xhttp"
        | "vless-reality-tcp"
        | "vless-shadowtls-v3"
        | "vless-restls"
        | "vless-jls"
        | "anytls-tls"
        | "anytls-shadowtls-v3"
        | "anytls-restls"
        | "anytls-jls"
        | "trojan-tls"
        | "trojan-shadowtls-v3"
        | "trojan-restls"
        | "trojan-jls"
        | "trojan-reality"
        | "snell-v5"
        | "snell-v5-shadowtls-v3"
        | "snell-v5-restls"
        | "snell-v5-jls"
        | "mieru"
        | "trusttunnel-h2"
        | "shadowquic"
        | "sudoku-httpmask" => Some("mihomo"),
        _ => None,
    }
}

fn profile(
    name: &str,
    protocol_id: &str,
    role: ProxyRole,
    port: u16,
    config: Value,
) -> ProtocolProfile {
    ProtocolProfile {
        name: name.to_string(),
        protocol_id: protocol_id.to_string(),
        schema_version: 1,
        role,
        server: "node.infiproxy.local".to_string(),
        port,
        enabled: false,
        preferred_core_id: legacy_runtime_preference(protocol_id).map(str::to_string),
        managed_resource_id: None,
        config,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, process::Command};

    use super::*;
    use crate::{
        adapter::{ClientRenderContext, MapSecretResolver},
        models::SubscriptionUser,
    };

    #[test]
    fn built_in_adapters_validate_their_defaults() {
        let registry = registry().unwrap();
        for profile in default_profiles() {
            registry
                .get(&profile.protocol_id)
                .unwrap()
                .validate_config(profile.schema_version, &profile.config)
                .unwrap();
        }
    }

    #[test]
    fn vless_adapter_owns_client_rendering() {
        let registry = registry().unwrap();
        let profile = default_profiles().remove(0);
        let user = SubscriptionUser {
            username: "alice".to_string(),
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            subscription_token: "token".to_string(),
        };
        let secrets = BTreeMap::from([
            (
                "xray.reality.public_key".to_string(),
                "public-key".to_string(),
            ),
            ("xray.reality.short_id".to_string(), "short-id".to_string()),
            (
                "xray.reality.private_key".to_string(),
                "private-key".to_string(),
            ),
        ]);
        let resolver = MapSecretResolver::new(&secrets);
        let rendered = registry
            .get(&profile.protocol_id)
            .unwrap()
            .render_client(&ClientRenderContext {
                profile: &profile,
                user: &user,
                secrets: &resolver,
            })
            .unwrap();
        assert_eq!(rendered["type"], "vless");
        assert_eq!(rendered["network"], "xhttp");
        assert_eq!(rendered["reality-opts"]["public-key"], "public-key");
    }

    #[test]
    fn mihomo_protocols_render_parseable_subscription_objects() {
        let registry = registry().unwrap();
        let user = SubscriptionUser {
            username: "alice".to_string(),
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            subscription_token: "token".to_string(),
        };
        let secrets = BTreeMap::from([
            ("snell.psk".to_string(), "snell-secret".to_string()),
            ("mieru.password".to_string(), "mieru-secret".to_string()),
        ]);
        let resolver = MapSecretResolver::new(&secrets);
        for (protocol_id, expected_type) in [
            ("trojan-tls", "trojan"),
            ("snell-v5", "snell"),
            ("mieru", "mieru"),
        ] {
            let profile = default_profiles()
                .into_iter()
                .find(|profile| profile.protocol_id == protocol_id)
                .unwrap();
            let rendered = registry
                .get(protocol_id)
                .unwrap()
                .render_client(&ClientRenderContext {
                    profile: &profile,
                    user: &user,
                    secrets: &resolver,
                })
                .unwrap();
            assert_eq!(rendered["type"], expected_type);
            serde_norway::to_string(&rendered).unwrap();
        }
    }

    fn test_secrets() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "xray.reality.public_key".into(),
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            ),
            ("xray.reality.short_id".into(), "0123456789abcdef".into()),
            ("xray.reality.private_key".into(), "server-only".into()),
            (
                "shadowsocks.2022.password".into(),
                "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=".into(),
            ),
            ("shadowtls.password".into(), "shadow-tls-password".into()),
            ("anytls.password".into(), "anytls-password".into()),
            ("restls.password".into(), "restls-password".into()),
            ("jls.username".into(), "jls-user".into()),
            ("jls.password".into(), "jls-password".into()),
            ("hysteria2.password".into(), "hysteria-password".into()),
            (
                "hysteria2.obfs_password".into(),
                "salamander-password".into(),
            ),
            ("tuic.password".into(), "tuic-password".into()),
            ("snell.psk".into(), "snell-password".into()),
            ("mieru.password".into(), "mieru-password".into()),
            (
                "sudoku.key".into(),
                "44444444-4444-4444-8444-444444444444".into(),
            ),
        ])
    }

    #[test]
    fn every_default_client_composition_renders_without_conflicting_security() {
        let registry = registry().unwrap();
        let user = SubscriptionUser {
            username: "alice".to_string(),
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            subscription_token: "token".to_string(),
        };
        let secrets = test_secrets();
        let resolver = MapSecretResolver::new(&secrets);
        for profile in default_profiles() {
            let rendered = registry
                .get(&profile.protocol_id)
                .unwrap()
                .render_client(&ClientRenderContext {
                    profile: &profile,
                    user: &user,
                    secrets: &resolver,
                })
                .unwrap_or_else(|error| panic!("{}: {error:#}", profile.protocol_id));
            let wrappers = ["reality-opts", "shadow-tls-opts", "restls-opts", "jls-opts"]
                .into_iter()
                .filter(|field| rendered.get(field).is_some())
                .count();
            assert!(
                wrappers <= 1,
                "{} has conflicting wrappers",
                profile.protocol_id
            );
            if profile.protocol_id == "vless-reality-tcp" {
                assert_eq!(rendered["network"], "tcp");
                assert_eq!(rendered["flow"], "xtls-rprx-vision");
                assert_eq!(rendered["packet-encoding"], "xudp");
            }
            if profile.protocol_id == "vless-reality-xhttp" {
                assert_eq!(rendered["network"], "xhttp");
                assert!(rendered.get("flow").is_none());
            }
            if profile.protocol_id == "vless-shadowtls-v3" {
                assert!(rendered.get("shadow-tls-opts").is_some());
                assert!(rendered.get("flow").is_none());
            }
            if profile.protocol_id == "vless-restls" {
                assert!(rendered.get("restls-opts").is_some());
                assert!(rendered.get("flow").is_none());
            }
            if profile.protocol_id == "vless-jls" {
                assert!(rendered.get("jls-opts").is_some());
                assert!(rendered.get("flow").is_none());
            }
            if profile.protocol_id == "anytls-jls" {
                assert!(rendered.get("jls-opts").is_some());
                assert!(rendered.get("reality-opts").is_none());
            }
            if profile.protocol_id == "trusttunnel-h2" {
                assert_eq!(rendered["quic"], false);
                assert_eq!(rendered["alpn"], json!(["h2"]));
            }
            if profile.protocol_id == "shadowquic" {
                assert_eq!(rendered["zero-rtt"], false);
                assert!(rendered.get("jls-opts").is_none());
            }
            if profile.protocol_id == "sudoku-httpmask" {
                assert_eq!(rendered["aead-method"], "chacha20-poly1305");
                assert_ne!(rendered["aead-method"], "none");
                assert_eq!(rendered["httpmask"]["path-root"], "infiproxy");
            }
        }
    }

    #[test]
    fn anytls_reality_is_not_an_exposed_capability() {
        let manifests = registry().unwrap().manifests();
        assert!(manifests
            .iter()
            .all(|manifest| manifest.id != "anytls-reality"));
    }

    #[test]
    fn exact_mihomo_client_parser_accepts_all_generated_compositions() {
        let Some(binary) = std::env::var_os("INFIPROXY_TEST_MIHOMO_BIN") else {
            return;
        };
        let registry = registry().unwrap();
        let user = SubscriptionUser {
            username: "alice".to_string(),
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            subscription_token: "token".to_string(),
        };
        let mut secrets = test_secrets();
        secrets.insert(
            "xray.reality.public_key".to_string(),
            "w1LlLliIbRGiRssXh-yKrLONwRaYlezwfihTFaCEaUw".to_string(),
        );
        let resolver = MapSecretResolver::new(&secrets);
        let proxies = default_profiles()
            .iter()
            .map(|profile| {
                registry
                    .get(&profile.protocol_id)
                    .unwrap()
                    .render_client(&ClientRenderContext {
                        profile,
                        user: &user,
                        secrets: &resolver,
                    })
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let names = proxies
            .iter()
            .filter_map(|proxy| proxy.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        let config = json!({
            "mode": "rule",
            "proxies": proxies,
            "proxy-groups": [{"name":"COMPATIBILITY","type":"select","proxies":names}],
            "rules": ["MATCH,COMPATIBILITY"]
        });
        let path = std::env::temp_dir().join(format!(
            "infiproxy-mihomo-client-{}.yaml",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, serde_norway::to_string(&config).unwrap()).unwrap();
        let output = Command::new(binary)
            .args(["-t", "-f"])
            .arg(&path)
            .output()
            .unwrap();
        fs::remove_file(path).unwrap();
        assert!(
            output.status.success(),
            "Mihomo v1.19.30 rejected generated client config: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
