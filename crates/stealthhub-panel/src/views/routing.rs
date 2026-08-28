//! Routing-page presentation.

use crate::{admin_bar, csrf_field, ui::layout, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::{html, Markup};
use stealthhub_core::{
    models::ProtocolProfile,
    policy::{role_name, ClientPolicy, DnsPolicy, PoolMember, RoutingPolicyRule, TransportPool},
    rules::RoutingRuleSet,
};

pub(crate) fn render(
    auth: &AuthenticatedAdmin,
    rule_sets: &[RoutingRuleSet],
    policy: &ClientPolicy,
    dns: &DnsPolicy,
    profiles: &[ProtocolProfile],
) -> Response {
    let targets = ["DIRECT".to_string(), "REJECT".to_string()]
        .into_iter()
        .chain(
            policy
                .pools
                .iter()
                .filter(|pool| pool.enabled)
                .map(|pool| pool.id.clone()),
        )
        .collect::<Vec<_>>();
    Html(
            layout(
                "Routing",
                html! {
                    (admin_bar(auth))
                    h1 { "Routing" }

                    div class="status-strip" {
                        div class="metric" {
                            span { "Rule sets" }
                            strong { (rule_sets.len()) }
                        }
                        div class="metric" {
                            span { "Enabled" }
                            strong { (rule_sets.iter().filter(|rule_set| rule_set.enabled).count()) }
                        }
                        div class="metric" {
                            span { "Provider type" }
                            strong { "http / classical / yaml" }
                        }
                        div class="metric" {
                            span { "Import" }
                            strong { "RULE-SET" }
                        }
                        div class="metric" {
                            span { "Transport pools" }
                            strong { (policy.pools.iter().filter(|pool| pool.enabled).count()) }
                        }
                    }

                    section {
                        h2 { "DNS policy" }
                        form method="post" action="/admin/routing/dns" class="config-form wide" {
                            (csrf_field(&auth.csrf_token))
                            label class="switch-field" {
                                input type="checkbox" name="enabled" checked[dns.enabled];
                                span class="switch-ui" {}
                                span { strong { "Enabled" } small { "Generate a managed Mihomo DNS block." } }
                            }
                            label class="switch-field" {
                                input type="checkbox" name="respect_rules" checked[dns.respect_rules];
                                span class="switch-ui" {}
                                span { strong { "Respect routing rules" } small { "Route DNS connections according to policy; bootstrap resolvers prevent node-resolution loops." } }
                            }
                            label class="switch-field" {
                                input type="checkbox" name="ipv6" checked[dns.ipv6];
                                span class="switch-ui" {}
                                span { strong { "IPv6 answers" } small { "Return AAAA responses when the client network supports IPv6." } }
                            }
                            label { span { "Enhanced mode" } select name="enhanced_mode" {
                                option value="redir-host" selected[dns.enhanced_mode == "redir-host"] { "redir-host" }
                                option value="fake-ip" selected[dns.enhanced_mode == "fake-ip"] { "fake-ip" }
                            } }
                            label { span { "Bootstrap / node resolvers" } textarea name="bootstrap_resolvers" rows="4" { (dns.bootstrap_resolvers.join("\n")) } small { "One IP or supported resolver URL per line." } }
                            label { span { "Secure remote resolvers" } textarea name="remote_resolvers" rows="4" { (dns.remote_resolvers.join("\n")) } small { "Used by default and for proxied rule sets." } }
                            label { span { "Direct resolvers" } textarea name="direct_resolvers" rows="4" { (dns.direct_resolvers.join("\n")) } small { "Used for rule sets targeting DIRECT." } }
                            button type="submit" { "Save DNS policy" }
                        }
                    }

                    section {
                        h2 { "Transport pools" }
                        p { "Members use one selector per line: profile:NAME, capability:PROTOCOL, role:ROLE, pool:ID, all-profiles, DIRECT, or REJECT." }
                        div class="config-list" {
                            @for pool in &policy.pools {
                                (transport_pool_editor(pool, auth, &policy.pools))
                            }
                            (new_transport_pool_editor(auth))
                        }
                    }

                    section {
                        h2 { "Inline routing policies" }
                        p { "Targets may be DIRECT, REJECT, a pool ID, an exact profile name, or capability:PROTOCOL." }
                        datalist id="routing-targets" {
                            option value="DIRECT" {}
                            option value="REJECT" {}
                            @for pool in &policy.pools { option value=(&pool.id) {} }
                            @for profile in profiles { option value=(&profile.name) {} option value=(format!("capability:{}", profile.protocol_id)) {} }
                        }
                        div class="config-list" {
                            @for rule in &policy.rules {
                                (routing_policy_editor(rule, auth))
                            }
                            (new_routing_policy_editor(auth))
                        }
                    }

                    section {
                        h2 { "Mihomo rule sets" }
                        div class="table-wrap" {
                            table {
                                thead {
                                    tr {
                                        th { "Name" }
                                        th { "Target" }
                                        th { "Provider URL" }
                                        th { "Rules" }
                                        th { "State" }
                                    }
                                }
                                tbody {
                                    @for rule_set in rule_sets {
                                        tr {
                                            td { strong { (&rule_set.title) } br; code { (&rule_set.slug) } }
                                            td { code { (&rule_set.target) } }
                                            td { code { (format!("/rules/{}.yaml", rule_set.slug)) } }
                                            td { (rule_set.payload.lines().filter(|line| !line.trim().is_empty()).count()) }
                                            td {
                                                @if rule_set.enabled {
                                                    span class="badge ok" { "enabled" }
                                                } @else {
                                                    span class="badge off" { "disabled" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    section {
                        h2 { "Rule parameters" }
                        div class="config-list" {
                            @for rule_set in rule_sets {
                                (routing_rule_editor(rule_set, auth, &targets))
                            }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}

fn transport_pool_editor(
    pool: &TransportPool,
    auth: &AuthenticatedAdmin,
    pools: &[TransportPool],
) -> Markup {
    html! {
        section class="config-row" {
            div class="config-row-head" {
                h3 { (&pool.display_name) }
                div class="config-row-meta" {
                    code { (&pool.id) }
                    span class=(format!("badge {}", if pool.enabled { "ok" } else { "off" })) {
                        @if pool.enabled { "enabled" } @else { "disabled" }
                    }
                }
            }
            (transport_pool_form(pool, auth, true))
            form method="post" action="/admin/routing/pools/delete" class="inline-form" {
                (csrf_field(&auth.csrf_token))
                input type="hidden" name="id" value=(&pool.id);
                select name="replacement" aria-label="Replacement pool for existing references" {
                    option value="" { "No replacement" }
                    @for replacement in pools.iter().filter(|replacement| replacement.id != pool.id) {
                        option value=(&replacement.id) { "Replace references with " (&replacement.id) }
                    }
                }
                button class="danger compact" type="submit" { "Delete pool" }
            }
        }
    }
}

fn new_transport_pool_editor(auth: &AuthenticatedAdmin) -> Markup {
    let pool = TransportPool {
        id: String::new(),
        display_name: String::new(),
        kind: stealthhub_core::policy::PoolKind::Select,
        enabled: true,
        members: vec![PoolMember::AllProfiles, PoolMember::Direct],
        test_url: None,
        interval_seconds: None,
        timeout_ms: None,
        tolerance_ms: None,
        max_failures: None,
        lazy: true,
        minimum_healthy_count: None,
        fallback_pool: None,
        priority: 500,
        strategy: None,
    };
    html! {
        section class="config-row" {
            div class="config-row-head" { h3 { "Create transport pool" } }
            (transport_pool_form(&pool, auth, false))
        }
    }
}

fn transport_pool_form(pool: &TransportPool, auth: &AuthenticatedAdmin, editing: bool) -> Markup {
    html! {
        form method="post" action="/admin/routing/pools/save" class="config-form wide" {
            (csrf_field(&auth.csrf_token))
            input type="hidden" name="original_id" value=[editing.then_some(pool.id.as_str())];
            label { span { "Stable ID" } input name="id" value=(&pool.id) required maxlength="64"; }
            label { span { "Display name" } input name="display_name" value=(&pool.display_name) required maxlength="80"; }
            label { span { "Strategy" } select name="kind" {
                option value="manual" selected[pool.kind.mihomo_name() == "select"] { "Manual selection" }
                option value="url-test" selected[pool.kind.mihomo_name() == "url-test"] { "Lowest latency (url-test)" }
                option value="fallback" selected[pool.kind.mihomo_name() == "fallback"] { "Ordered fallback" }
                option value="load-balance" selected[pool.kind.mihomo_name() == "load-balance"] { "Load balance" }
            } }
            label { span { "Priority" } input type="number" name="priority" value=(pool.priority) required; }
            label class="switch-field" {
                input type="checkbox" name="enabled" checked[pool.enabled]; span class="switch-ui" {}
                span { strong { "Enabled" } small { "Expose this pool to routing and subscriptions." } }
            }
            label class="switch-field" {
                input type="checkbox" name="lazy" checked[pool.lazy]; span class="switch-ui" {}
                span { strong { "Lazy health checks" } small { "Do not test this group while it is not selected." } }
            }
            label class="full-span" { span { "Member selectors" } textarea name="members" rows="7" required { (pool_member_lines(&pool.members)) } }
            label class="full-span" { span { "Health URL" } input type="url" name="test_url" value=(pool.test_url.as_deref().unwrap_or("")) placeholder="https://www.gstatic.com/generate_204"; }
            label { span { "Interval (seconds)" } input type="number" min="1" name="interval_seconds" value=(optional_number(pool.interval_seconds)); }
            label { span { "Timeout (milliseconds)" } input type="number" min="1" name="timeout_ms" value=(optional_number(pool.timeout_ms)); }
            label { span { "Tolerance (milliseconds)" } input type="number" min="0" name="tolerance_ms" value=(optional_number(pool.tolerance_ms)); }
            label { span { "Maximum failures" } input type="number" min="1" name="max_failures" value=(optional_number(pool.max_failures)); }
            label { span { "Minimum healthy count" } input type="number" min="1" name="minimum_healthy_count" value=(optional_number(pool.minimum_healthy_count)); small { "Control-plane policy; not emitted as an unsupported Mihomo key." } }
            label { span { "Fallback pool" } input name="fallback_pool" value=(pool.fallback_pool.as_deref().unwrap_or("")); }
            label { span { "Load-balance algorithm" } select name="strategy" {
                option value="" { "Default" }
                option value="round-robin" selected[pool.strategy.as_deref() == Some("round-robin")] { "Round robin" }
                option value="consistent-hashing" selected[pool.strategy.as_deref() == Some("consistent-hashing")] { "Consistent hashing" }
                option value="sticky-sessions" selected[pool.strategy.as_deref() == Some("sticky-sessions")] { "Sticky sessions" }
            } }
            button type="submit" { @if editing { "Save pool" } @else { "Create pool" } }
        }
    }
}

fn routing_policy_editor(rule: &RoutingPolicyRule, auth: &AuthenticatedAdmin) -> Markup {
    html! {
        section class="config-row" {
            div class="config-row-head" { h3 { (&rule.display_name) } code { (&rule.id) } }
            (routing_policy_form(rule, auth, true))
            form method="post" action="/admin/routing/policies/delete" class="inline-form" {
                (csrf_field(&auth.csrf_token))
                input type="hidden" name="id" value=(&rule.id);
                button class="danger compact" type="submit" { "Delete policy" }
            }
        }
    }
}

fn new_routing_policy_editor(auth: &AuthenticatedAdmin) -> Markup {
    let rule = RoutingPolicyRule {
        id: String::new(),
        display_name: String::new(),
        enabled: true,
        priority: 500,
        condition: "DOMAIN-SUFFIX,example.com".to_string(),
        target: "DIRECT".to_string(),
    };
    html! { section class="config-row" { div class="config-row-head" { h3 { "Create routing policy" } } (routing_policy_form(&rule, auth, false)) } }
}

fn routing_policy_form(
    rule: &RoutingPolicyRule,
    auth: &AuthenticatedAdmin,
    editing: bool,
) -> Markup {
    html! {
        form method="post" action="/admin/routing/policies/save" class="config-form wide" {
            (csrf_field(&auth.csrf_token))
            input type="hidden" name="original_id" value=[editing.then_some(rule.id.as_str())];
            label { span { "Stable ID" } input name="id" value=(&rule.id) required maxlength="64"; }
            label { span { "Display name" } input name="display_name" value=(&rule.display_name) required maxlength="80"; }
            label { span { "Priority" } input type="number" name="priority" value=(rule.priority) required; }
            label class="switch-field" { input type="checkbox" name="enabled" checked[rule.enabled]; span class="switch-ui" {} span { strong { "Enabled" } } }
            label class="full-span" { span { "Mihomo condition" } input name="condition" value=(&rule.condition) required maxlength="512"; small { "Examples: DOMAIN,example.com; DOMAIN-SUFFIX,example.com; IP-CIDR,10.0.0.0/8,no-resolve; MATCH." } }
            label class="full-span" { span { "Target" } input name="target" list="routing-targets" value=(&rule.target) required maxlength="128"; }
            button type="submit" { @if editing { "Save policy" } @else { "Create policy" } }
        }
    }
}

fn optional_number(value: Option<u32>) -> String {
    value.map_or_else(String::new, |value| value.to_string())
}

fn pool_member_lines(members: &[PoolMember]) -> String {
    members
        .iter()
        .map(|member| match member {
            PoolMember::Profile(value) => format!("profile:{value}"),
            PoolMember::Capability(value) => format!("capability:{value}"),
            PoolMember::Role(value) => format!("role:{}", role_name(*value)),
            PoolMember::Pool(value) => format!("pool:{value}"),
            PoolMember::AllProfiles => "all-profiles".to_string(),
            PoolMember::Direct => "DIRECT".to_string(),
            PoolMember::Reject => "REJECT".to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn routing_rule_editor(
    rule_set: &stealthhub_core::rules::RoutingRuleSet,
    auth: &AuthenticatedAdmin,
    targets: &[String],
) -> Markup {
    html! {
        section class="config-row" {
            div class="config-row-head" {
                h3 { (&rule_set.title) }
                div class="config-row-meta" {
                    span class=(format!("badge {}", if rule_set.enabled { "ok" } else { "off" })) {
                        @if rule_set.enabled { "enabled" } @else { "disabled" }
                    }
                    span class="badge neutral" { (&rule_set.target) }
                    code { (format!("/rules/{}.yaml", rule_set.slug)) }
                }
            }
            form method="post" action="/admin/routing" class="config-form wide" {
                (csrf_field(&auth.csrf_token))
                input type="hidden" name="slug" value=(&rule_set.slug);
                label class="switch-field" {
                    input type="checkbox" name="enabled" checked[rule_set.enabled];
                    span class="switch-ui" {}
                    span {
                        strong { "Enabled" }
                        small { "Include this rule provider and RULE-SET line in generated Mihomo YAML." }
                    }
                }
                label {
                    span { "Target group" }
                    select name="target" {
                        @for target in targets {
                            option value=(target) selected[*target == rule_set.target] { (target) }
                        }
                    }
                    small { (&rule_set.effect) }
                }
                label class="full-span" {
                    span { "Classical payload" }
                    textarea name="payload" rows="10" spellcheck="false" { (&rule_set.payload) }
                    small { "One Mihomo classical rule per line, for example DOMAIN-SUFFIX,example.com or IP-CIDR,10.0.0.0/8,no-resolve." }
                }
                button type="submit" { "Save rule set" }
            }
        }
    }
}
