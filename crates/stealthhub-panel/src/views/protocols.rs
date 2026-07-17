//! Protocols-page presentation and form components.

use crate::{admin_bar, csrf_field, ui::layout, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::{html, Markup};
use stealthhub_core::models::{
    PanelSettings, ProtocolConfig, ProtocolProfile, ProxyKind, ProxyRole,
};

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    settings: &PanelSettings,
    profiles: &[ProtocolProfile],
    secret_names: &[String],
) -> Response {
    Html(
            layout(
                "Protocols",
                html! {
                    (admin_bar(auth))
                    h1 { "Protocols" }

                    div class="status-strip" {
                        div class="metric" {
                            span { "Profiles" }
                            strong { (profiles.len()) }
                        }
                        div class="metric" {
                            span { "Enabled" }
                            strong { (profiles.iter().filter(|profile| profile.enabled).count()) }
                        }
                        div class="metric" {
                            span { "Secrets" }
                            strong { (secret_names.len()) }
                        }
                        div class="metric" {
                            span { "Subscription host" }
                            strong { (&settings.subscription_domain) }
                        }
                    }

                    section {
                        h2 { "Mihomo subscription endpoint" }
                        dl class="details" {
                            dt { "Subscription domain" }
                            dd { code { (&settings.subscription_domain) } }
                            dt { "Node domain" }
                            dd { code { (&settings.node_domain) } }
                        }
                    }

                    section {
                        h2 { "Transport matrix" }
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        th { "Profile" }
                                        th { "Purpose" }
                                        th { "Masking knobs" }
                                        th { "Client impact" }
                                    }
                                }
                                tbody {
                                    tr {
                                        td { code { "vless-reality-xhttp" } }
                                        td { "Primary TLS-like profile for modern Mihomo clients." }
                                        td { code { "server_name" } " + " code { "path" } " + REALITY public key/short ID." }
                                        td { "Best default when client supports XHTTP." }
                                    }
                                    tr {
                                        td { code { "vless-reality-tcp" } }
                                        td { "Lean fallback with fewer moving parts." }
                                        td { code { "server_name" } " + REALITY public key/short ID." }
                                        td { "Useful for conservative client profiles." }
                                    }
                                    tr {
                                        td { code { "ss2022-shadowtls" } }
                                        td { "Compatibility transport with ShadowTLS front." }
                                        td { code { "server_name" } " + independent SS/ShadowTLS secrets." }
                                        td { "Good fallback when VLESS is undesirable." }
                                    }
                                    tr {
                                        td { code { "hysteria2" } " / " code { "tuic" } }
                                        td { "QUIC speed fallback for high-latency routes." }
                                        td { code { "sni" } " + password/obfs secrets." }
                                        td { "Enable only when UDP path is healthy." }
                                    }
                                }
                            }
                        }
                    }

                    section {
                        h2 { "Protocol profiles" }
                        @if profiles.is_empty() {
                            p { "No protocol profiles configured yet." }
                        } @else {
                            div class="table-wrap" {
                                table {
                                    thead {
                                        tr {
                                            th { "Name" }
                                            th { "Kind" }
                                            th { "Role" }
                                            th { "Enabled" }
                                            th { "Endpoint" }
                                            th { "Secrets" }
                                        }
                                    }
                                    tbody {
                                        @for profile in profiles {
                                            tr {
                                                td { code { (&profile.name) } }
                                                td { (proxy_kind_label(&profile.kind)) }
                                                td { (proxy_role_label(&profile.role)) }
                                                td {
                                                    @if profile.enabled {
                                                        span class="badge ok" { "on" }
                                                    } @else {
                                                        span class="badge off" { "off" }
                                                    }
                                                }
                                                td { code { (format!("{}:{}", profile.server, profile.port)) } }
                                                td {
                                                    @let missing = missing_secret_names(profile, secret_names);
                                                    @if profile.required_secret_names().is_empty() {
                                                        span class="badge ok" { "none" }
                                                    } @else if missing.is_empty() {
                                                        span class="badge ok" { "ready" }
                                                        br;
                                                        @for secret in profile.required_secret_names() {
                                                            code { (secret) }
                                                            " "
                                                        }
                                                    } @else {
                                                        span class="badge off" { "missing" }
                                                        br;
                                                        @for secret in missing {
                                                            code { (secret) }
                                                            " "
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    section {
                        h2 { "Profile parameters" }
                        datalist id="secret-names" {
                            @for secret in secret_names {
                                option value=(secret) {}
                            }
                        }
                        div class="config-list" {
                            @for profile in profiles {
                                (protocol_profile_editor(profile, auth, secret_names))
                            }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}

fn protocol_profile_editor(
    profile: &ProtocolProfile,
    auth: &AuthenticatedAdmin,
    secret_names: &[String],
) -> Markup {
    html! {
        section class="config-row" {
            div class="config-row-head" {
                h3 { (&profile.name) }
                div class="config-row-meta" {
                    span class=(format!("badge {}", if profile.enabled { "ok" } else { "off" })) {
                        @if profile.enabled { "enabled" } @else { "disabled" }
                    }
                    span class="badge neutral" { (proxy_kind_label(&profile.kind)) }
                    span class="badge neutral" { (proxy_role_label(&profile.role)) }
                }
            }
            form method="post" action=(format!("/admin/protocols/{}/update", profile.name)) class="config-form" {
                (csrf_field(&auth.csrf_token))
                label class="switch-field" {
                    input type="checkbox" name="enabled" checked[profile.enabled];
                    span class="switch-ui" {}
                    span {
                        strong { "Enabled" }
                        small { "Include this proxy in generated Mihomo subscriptions." }
                    }
                }
                label {
                    span { "Server address" }
                    input type="text" name="server" value=(&profile.server) required;
                    small { "Hostname or IP used by the Mihomo proxy object." }
                }
                label {
                    span { "Server port" }
                    input type="number" name="port" min="1" max="65535" value=(profile.port) required;
                    small { "Remote port used by the client." }
                }
                (protocol_specific_fields(profile, secret_names))
                button type="submit" { "Save profile" }
            }
        }
    }
}

fn protocol_specific_fields(profile: &ProtocolProfile, secret_names: &[String]) -> Markup {
    match &profile.config {
        ProtocolConfig::VlessRealityXhttp {
            server_name,
            path,
            public_key_secret,
            short_id_secret,
            ..
        } => html! {
            (text_input("server_name", "TLS server name", server_name, "SNI and XHTTP Host value used by Mihomo."))
            (text_input("path", "XHTTP path", path, "HTTP path sent by the xhttp transport."))
            (secret_input("public_key_secret", "REALITY public key secret", public_key_secret, secret_names))
            (secret_input("short_id_secret", "REALITY short ID secret", short_id_secret, secret_names))
        },
        ProtocolConfig::VlessRealityTcp {
            server_name,
            public_key_secret,
            short_id_secret,
            ..
        } => html! {
            (text_input("server_name", "TLS server name", server_name, "SNI value for REALITY verification."))
            (secret_input("public_key_secret", "REALITY public key secret", public_key_secret, secret_names))
            (secret_input("short_id_secret", "REALITY short ID secret", short_id_secret, secret_names))
        },
        ProtocolConfig::Shadowsocks2022ShadowTls {
            server_name,
            password_secret,
            shadow_tls_password_secret,
        } => html! {
            (text_input("server_name", "ShadowTLS server name", server_name, "TLS host presented by ShadowTLS v3."))
            (secret_input("password_secret", "Shadowsocks password secret", password_secret, secret_names))
            (secret_input(
                "shadow_tls_password_secret",
                "ShadowTLS password secret",
                shadow_tls_password_secret,
                secret_names
            ))
        },
        ProtocolConfig::Hysteria2 {
            password_secret,
            sni,
            obfs_password_secret,
        } => html! {
            (text_input("sni", "TLS SNI", sni, "Server name used by the TLS handshake."))
            (secret_input("password_secret", "Hysteria2 password secret", password_secret, secret_names))
            (optional_secret_input(
                "obfs_password_secret",
                "Salamander obfs secret",
                obfs_password_secret.as_deref().unwrap_or(""),
                secret_names
            ))
        },
        ProtocolConfig::AnyTls {
            password_secret,
            sni,
        } => html! {
            (text_input("sni", "TLS SNI", sni, "Server name used by AnyTLS."))
            (secret_input("password_secret", "AnyTLS password secret", password_secret, secret_names))
        },
        ProtocolConfig::Tuic {
            password_secret,
            sni,
            ..
        } => html! {
            (text_input("sni", "TLS SNI", sni, "Server name used by TUIC."))
            (secret_input("password_secret", "TUIC password secret", password_secret, secret_names))
        },
    }
}

fn text_input(name: &str, label: &str, value: &str, help: &str) -> Markup {
    html! {
        label {
            span { (label) }
            input type="text" name=(name) value=(value) required;
            small { (help) }
        }
    }
}

fn secret_input(name: &str, label: &str, value: &str, secret_names: &[String]) -> Markup {
    html! {
        label {
            span { (label) }
            input type="text" name=(name) value=(value) list="secret-names" required;
            small {
                "SQLite secret name. "
                @if secret_names.iter().any(|secret| secret == value) {
                    span class="inline-ok" { "present" }
                } @else {
                    span class="inline-warn" { "missing" }
                }
            }
        }
    }
}

fn optional_secret_input(name: &str, label: &str, value: &str, secret_names: &[String]) -> Markup {
    html! {
        label {
            span { (label) }
            input type="text" name=(name) value=(value) list="secret-names";
            small {
                "Optional SQLite secret name."
                @if !value.is_empty() && secret_names.iter().any(|secret| secret == value) {
                    " "
                    span class="inline-ok" { "present" }
                } @else if !value.is_empty() {
                    " "
                    span class="inline-warn" { "missing" }
                }
            }
        }
    }
}

fn missing_secret_names(profile: &ProtocolProfile, present_secret_names: &[String]) -> Vec<String> {
    profile
        .required_secret_names()
        .into_iter()
        .filter(|name| !present_secret_names.iter().any(|present| present == name))
        .map(str::to_string)
        .collect()
}

fn proxy_kind_label(kind: &ProxyKind) -> &'static str {
    match kind {
        ProxyKind::VlessRealityXhttp => "VLESS + REALITY + XHTTP",
        ProxyKind::VlessRealityTcp => "VLESS + REALITY + TCP",
        ProxyKind::Shadowsocks2022ShadowTls => "SS2022 + ShadowTLS",
        ProxyKind::Hysteria2 => "Hysteria2",
        ProxyKind::AnyTls => "AnyTLS",
        ProxyKind::Tuic => "TUIC",
    }
}

fn proxy_role_label(role: &ProxyRole) -> &'static str {
    match role {
        ProxyRole::AutoSafe => "AUTO-SAFE",
        ProxyRole::Speed => "SPEED",
        ProxyRole::Compatibility => "COMPAT",
        ProxyRole::RuAccess => "RU-ACCESS",
        ProxyRole::Manual => "MANUAL",
    }
}
