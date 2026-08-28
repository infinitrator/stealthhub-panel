//! Routing-page presentation.

use crate::{admin_bar, csrf_field, ui::layout, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::{html, Markup};
use std::collections::BTreeMap;
use stealthhub_core::{
    models::ProtocolProfile,
    policy::{role_name, ClientPolicy, DnsPolicy, PoolMember, RoutingPolicyRule, TransportPool},
    rules::{RoutingRuleSet, RuleEntry, RuleKind, RuleSetSource, RuleSourceFormat},
};

pub(crate) struct RoutingPageData<'a> {
    pub(crate) rule_sets: &'a [RoutingRuleSet],
    pub(crate) policy: &'a ClientPolicy,
    pub(crate) dns: &'a DnsPolicy,
    pub(crate) profiles: &'a [ProtocolProfile],
    pub(crate) entries: &'a BTreeMap<String, Vec<RuleEntry>>,
    pub(crate) sources: &'a BTreeMap<String, Vec<RuleSetSource>>,
    pub(crate) search: &'a str,
    pub(crate) kind_filter: &'a str,
}

pub(crate) fn render(auth: &AuthenticatedAdmin, data: RoutingPageData<'_>) -> Response {
    let RoutingPageData {
        rule_sets,
        policy,
        dns,
        profiles,
        entries,
        sources,
        search,
        kind_filter,
    } = data;
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
                        h2 { "Normalized rule filter" }
                        form method="get" action="/admin/routing" class="inline-form" {
                            input type="search" name="search" value=(search) placeholder="value or comment" maxlength="128";
                            (rule_kind_filter(kind_filter))
                            button class="secondary compact" type="submit" { "Filter" }
                            a class="button secondary compact" href="/admin/routing" { "Clear" }
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
                                (routing_rule_editor(
                                    rule_set,
                                    auth,
                                    &targets,
                                    entries.get(&rule_set.slug).map(Vec::as_slice).unwrap_or_default(),
                                    sources.get(&rule_set.slug).map(Vec::as_slice).unwrap_or_default(),
                                ))
                            }
                            (new_rule_set_editor(auth, &targets))
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
    entries: &[RuleEntry],
    sources: &[RuleSetSource],
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
            form method="post" action="/admin/routing/rule-sets/save" class="config-form wide" {
                (csrf_field(&auth.csrf_token))
                input type="hidden" name="slug" value=(&rule_set.slug);
                input type="hidden" name="create" value="false";
                label { span { "Display name" } input name="title" value=(&rule_set.title) required maxlength="80"; }
                label { span { "Description" } input name="effect" value=(&rule_set.effect) maxlength="256"; }
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
                    span { "Local advanced classical layer" }
                    textarea name="payload" rows="10" spellcheck="false" { (&rule_set.payload) }
                    small { "Normalized entries take precedence; imported source data is appended last. Empty is allowed when normalized entries or a source provide data." }
                }
                button type="submit" { "Save rule set" }
            }
            div class="module-actions" {
                a class="button secondary compact" href=(format!("/rules/{}.yaml", rule_set.slug)) { "Export / preview YAML" }
                form method="post" action="/admin/routing/rule-sets/clone" class="inline-form" {
                    (csrf_field(&auth.csrf_token)) input type="hidden" name="slug" value=(&rule_set.slug);
                    input name="new_slug" placeholder="new-stable-id" required maxlength="64";
                    button class="secondary compact" type="submit" { "Clone" }
                }
                form method="post" action="/admin/routing/rule-sets/delete" class="inline-form" {
                    (csrf_field(&auth.csrf_token)) input type="hidden" name="slug" value=(&rule_set.slug);
                    button class="danger compact" type="submit" { "Delete rule set" }
                }
            }

            h4 { "Normalized entries" }
            p { (entries.len()) " entries. The first 200 are rendered to keep this page bounded." }
            div class="table-wrap" { table {
                thead { tr { th { "Order" } th { "Kind / value" } th { "Metadata" } th { "State" } th { "Action" } } }
                tbody {
                    @for entry in entries.iter().take(200) {
                        tr {
                            td { (entry.priority) }
                            td { code { (entry.kind.mihomo_name()) "," (&entry.value) } }
                            td { (entry.comment.as_deref().unwrap_or("")) br; small { (entry.source_tag.as_deref().unwrap_or("manual")) } }
                            td { @if entry.enabled { span class="badge ok" { "enabled" } } @else { span class="badge off" { "disabled" } } }
                            td class="module-actions" {
                                details { summary { "Edit" } form method="post" action="/admin/routing/entries/save" class="config-form" {
                                    (csrf_field(&auth.csrf_token)) input type="hidden" name="id" value=(&entry.id);
                                    input type="hidden" name="rule_set_id" value=(&rule_set.slug);
                                    label class="switch-field" { input type="checkbox" name="enabled" checked[entry.enabled]; span class="switch-ui" {} span { "Enabled" } }
                                    label { span { "Kind" } (rule_kind_select("kind", entry.kind)) }
                                    label { span { "Value" } input name="value" value=(&entry.value) required maxlength="1024"; }
                                    label { span { "Comment" } input name="comment" value=(entry.comment.as_deref().unwrap_or("")) maxlength="256"; }
                                    label { span { "Source tag" } input name="source_tag" value=(entry.source_tag.as_deref().unwrap_or("")) maxlength="64"; }
                                    label { span { "Priority" } input type="number" name="priority" value=(entry.priority) required; }
                                    button class="compact" type="submit" { "Save" }
                                } }
                                form method="post" action="/admin/routing/entries/delete" class="inline-form" {
                                    (csrf_field(&auth.csrf_token)) input type="hidden" name="id" value=(&entry.id);
                                    input type="hidden" name="rule_set_id" value=(&rule_set.slug);
                                    button class="danger compact" type="submit" { "Delete" }
                                }
                            }
                        }
                    }
                }
            } }
            form method="post" action="/admin/routing/entries/save" class="config-form wide" {
                (csrf_field(&auth.csrf_token)) input type="hidden" name="rule_set_id" value=(&rule_set.slug);
                input type="hidden" name="enabled" value="true";
                label { span { "Kind" } (rule_kind_select("kind", RuleKind::DomainSuffix)) }
                label { span { "Value" } input name="value" required maxlength="1024" placeholder="example.com"; }
                label { span { "Comment" } input name="comment" maxlength="256"; }
                label { span { "Source tag" } input name="source_tag" maxlength="64" placeholder="manual"; }
                label { span { "Priority" } input type="number" name="priority" value="500" required; }
                button type="submit" { "Add normalized entry" }
            }
            form method="post" action="/admin/routing/entries/bulk" class="config-form wide" {
                (csrf_field(&auth.csrf_token)) input type="hidden" name="rule_set_id" value=(&rule_set.slug);
                label { span { "Bulk kind" } (rule_kind_select("kind", RuleKind::DomainSuffix)) }
                label { span { "Source tag" } input name="source_tag" maxlength="64" placeholder="bulk-manual"; }
                label class="full-span" { span { "Bulk values" } textarea name="input" rows="7" required {} small { "One value per line, or choose CLASSICAL for complete rules. Duplicate normalized entries are skipped." } }
                button type="submit" { "Import entries" }
            }
            form method="post" action="/admin/routing/entries/deduplicate" class="inline-form" {
                (csrf_field(&auth.csrf_token)) input type="hidden" name="rule_set_id" value=(&rule_set.slug);
                input type="hidden" name="id" value="unused";
                button class="secondary compact" type="submit" { "Deduplicate entries" }
            }

            h4 { "Remote data sources" }
            div class="table-wrap" { table {
                thead { tr { th { "Source" } th { "Format" } th { "Last success" } th { "Entries" } th { "Status" } th { "Actions" } } }
                tbody { @for source in sources { tr {
                    td { code { (&source.url) } br; small { (&source.id) } }
                    td { (rule_source_format_name(source.format)) br; (source.refresh_interval_seconds) " s" }
                    td { (source.last_successful_fetch.as_deref().unwrap_or("never")) }
                    td { (source.entry_count) }
                    td { @if let Some(error) = &source.last_error { span class="badge off" { "failed" } br; small { (error) } } @else { span class="badge ok" { "ready" } } }
                    td class="module-actions" {
                        details { summary { "Edit" } form method="post" action="/admin/routing/sources/save" class="config-form" {
                            (csrf_field(&auth.csrf_token)) input type="hidden" name="id" value=(&source.id);
                            input type="hidden" name="rule_set_id" value=(&rule_set.slug);
                            label class="switch-field" { input type="checkbox" name="enabled" checked[source.enabled]; span class="switch-ui" {} span { "Enabled" } }
                            label { span { "URL" } input type="url" name="url" value=(&source.url) required maxlength="2048"; }
                            label { span { "Format" } select name="format" {
                                option value="text" selected[source.format == RuleSourceFormat::Text] { "HTTP text" }
                                option value="yaml" selected[source.format == RuleSourceFormat::Yaml] { "HTTP YAML" }
                                option value="mihomo-classical" selected[source.format == RuleSourceFormat::MihomoClassical] { "Mihomo classical" }
                            } }
                            label { span { "Refresh seconds" } input type="number" name="refresh_interval_seconds" min="300" max="604800" value=(source.refresh_interval_seconds) required; }
                            button class="compact" type="submit" { "Save" }
                        } }
                        form method="post" action="/admin/routing/sources/refresh" class="inline-form" { (csrf_field(&auth.csrf_token)) input type="hidden" name="id" value=(&source.id); button class="compact" type="submit" { "Refresh" } }
                        form method="post" action="/admin/routing/sources/delete" class="inline-form" { (csrf_field(&auth.csrf_token)) input type="hidden" name="id" value=(&source.id); button class="danger compact" type="submit" { "Delete" } }
                    }
                } } }
            } }
            form method="post" action="/admin/routing/sources/save" class="config-form wide" {
                (csrf_field(&auth.csrf_token)) input type="hidden" name="rule_set_id" value=(&rule_set.slug);
                input type="hidden" name="enabled" value="true";
                label class="full-span" { span { "HTTPS source URL" } input type="url" name="url" required maxlength="2048" placeholder="https://example.org/rules.yaml"; }
                label { span { "Format" } select name="format" { option value="text" { "HTTP text" } option value="yaml" { "HTTP YAML" } option value="mihomo-classical" { "Mihomo classical provider" } } }
                label { span { "Refresh interval (seconds)" } input type="number" name="refresh_interval_seconds" min="300" max="604800" value="3600" required; }
                button type="submit" { "Add source" }
            }
        }
    }
}

fn new_rule_set_editor(auth: &AuthenticatedAdmin, targets: &[String]) -> Markup {
    html! { section class="config-row" {
        div class="config-row-head" { h3 { "Create rule set" } }
        form method="post" action="/admin/routing/rule-sets/save" class="config-form wide" {
            (csrf_field(&auth.csrf_token)) input type="hidden" name="create" value="true";
            label { span { "Stable ID" } input name="slug" required maxlength="64" placeholder="custom-rules"; }
            label { span { "Display name" } input name="title" required maxlength="80"; }
            label class="full-span" { span { "Description" } input name="effect" maxlength="256"; }
            label { span { "Target" } select name="target" { @for target in targets { option value=(target) { (target) } } } }
            label class="switch-field" { input type="checkbox" name="enabled"; span class="switch-ui" {} span { strong { "Enabled" } small { "Enable after at least one valid rule is present." } } }
            label class="full-span" { span { "Optional classical import" } textarea name="payload" rows="6" {} }
            button type="submit" { "Create rule set" }
        }
    } }
}

fn rule_kind_select(name: &str, selected: RuleKind) -> Markup {
    let kinds = [
        RuleKind::Domain,
        RuleKind::DomainSuffix,
        RuleKind::DomainKeyword,
        RuleKind::IpCidr,
        RuleKind::IpCidr6,
        RuleKind::Geoip,
        RuleKind::Geosite,
        RuleKind::Asn,
        RuleKind::ProcessName,
        RuleKind::DstPort,
        RuleKind::SrcPort,
        RuleKind::Network,
        RuleKind::Classical,
    ];
    html! { select name=(name) { @for kind in kinds { option value=(kind.mihomo_name()) selected[kind == selected] { (kind.mihomo_name()) } } } }
}

const fn rule_source_format_name(format: RuleSourceFormat) -> &'static str {
    match format {
        RuleSourceFormat::Text => "text",
        RuleSourceFormat::Yaml => "yaml",
        RuleSourceFormat::MihomoClassical => "mihomo classical",
    }
}

fn rule_kind_filter(selected: &str) -> Markup {
    let kinds = [
        RuleKind::Domain,
        RuleKind::DomainSuffix,
        RuleKind::DomainKeyword,
        RuleKind::IpCidr,
        RuleKind::IpCidr6,
        RuleKind::Geoip,
        RuleKind::Geosite,
        RuleKind::Asn,
        RuleKind::ProcessName,
        RuleKind::DstPort,
        RuleKind::SrcPort,
        RuleKind::Network,
        RuleKind::Classical,
    ];
    html! { select name="kind" aria-label="Rule kind filter" { option value="" { "All kinds" } @for kind in kinds { option value=(kind.mihomo_name()) selected[selected == kind.mihomo_name()] { (kind.mihomo_name()) } } } }
}
