//! Routing-page presentation.

use crate::{admin_bar, csrf_field, ui::layout, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::{html, Markup};
use stealthhub_core::rules::{RoutingRuleSet, ROUTING_TARGETS};

pub(crate) fn render(auth: &AuthenticatedAdmin, rule_sets: &[RoutingRuleSet]) -> Response {
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
                                (routing_rule_editor(rule_set, auth))
                            }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}

fn routing_rule_editor(
    rule_set: &stealthhub_core::rules::RoutingRuleSet,
    auth: &AuthenticatedAdmin,
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
                        @for target in ROUTING_TARGETS {
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
