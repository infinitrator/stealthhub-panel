//! Built-in protocol adapters and their adapter-owned schemas.

use std::{collections::BTreeSet, sync::Arc};

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

use crate::{
    adapter::{
        ClientRenderContext, ConfigField, ConfigFieldKind, ProtocolAdapter,
        ProtocolAdapterManifest, ProtocolRegistry, SecretRef, ServerFragment, ServerRenderContext,
        ADAPTER_API_VERSION,
    },
    models::{ProtocolProfile, ProxyRole},
};

#[derive(Clone, Copy)]
enum Implementation {
    VlessXhttp,
    VlessTcp,
    ShadowsocksShadowTls,
    Hysteria,
    AnyTls,
    Tuic,
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
        user_participates: bool,
    ) -> Self {
        Self {
            manifest: ProtocolAdapterManifest {
                api_version: ADAPTER_API_VERSION,
                id: id.to_string(),
                display_name: display_name.to_string(),
                schema_version: 1,
                required_core_capabilities: BTreeSet::from([id.to_string()]),
                user_participates,
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
            Implementation::VlessXhttp | Implementation::VlessTcp
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
            Implementation::VlessXhttp | Implementation::VlessTcp
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
            Implementation::AnyTls => {
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
        let users = if self.manifest.user_participates {
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
            payload: json!({
                "server": context.profile.server,
                "port": context.profile.port,
                "config": context.profile.config,
                "users": users,
                "resolved_secrets": secrets,
                "managed_resource_id": context.profile.managed_resource_id,
            }),
        })
    }
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
            true,
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
            true,
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
            false,
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
            false,
        ),
        JsonProtocolAdapter::new(
            "any-tls",
            "AnyTLS",
            Implementation::AnyTls,
            vec![
                secret(
                    "password_secret",
                    "Password",
                    "Secret reference containing the authentication password.",
                    true,
                ),
                text("sni", "SNI", "TLS certificate hostname."),
            ],
            false,
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
            true,
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
    ]
}

/// Preserves the pre-adapter runtime placement during the one-way schema lift.
#[must_use]
pub fn legacy_runtime_preference(protocol_id: &str) -> Option<&'static str> {
    match protocol_id {
        "vless-reality-xhttp" | "vless-reality-tcp" => Some("xray"),
        "shadowsocks2022-shadow-tls" | "any-tls" => Some("sing-box"),
        "hysteria2" => Some("hysteria"),
        "tuic" => Some("tuic"),
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
    use std::collections::BTreeMap;

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
}
