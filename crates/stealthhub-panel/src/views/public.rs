//! Public home and authentication presentation.

use crate::{
    ui::{layout, APP_NAME},
    MIN_ADMIN_PASSWORD_LEN,
};
use axum::response::{Html, IntoResponse, Response};
use maud::html;

pub(crate) fn render_home() -> Response {
    Html(
        layout(
            APP_NAME,
            html! {
                h1 { (APP_NAME) }
                div class="cards" {
                    a class="card" href="/admin" {
                        h2 { "Dashboard" }
                        p { "Admin session, storage, subscription status." }
                    }
                    a class="card" href="/admin/users" {
                        h2 { "Users" }
                        p { "UUID, subscription token, traffic limit." }
                    }
                    a class="card" href="/admin/protocols" {
                        h2 { "Protocols" }
                        p { "Proxy profile parameters for Mihomo YAML." }
                    }
                    a class="card" href="/admin/routing" {
                        h2 { "Routing" }
                        p { "Rule providers imported by the subscription." }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}

pub(crate) fn render_setup() -> Response {
    Html(
                layout(
                    "Initial admin setup",
                    html! {
                        h1 { "Initial admin setup" }
                        div class="notice" {
                            "Create the first local administrator account. This page disappears after setup."
                        }
                        section {
                            h2 { "Admin account" }
                            form method="post" action="/admin/setup" class="form" {
                                label {
                                    span { "Username" }
                                    input type="text" name="username" minlength="3" maxlength="64" required autocomplete="username";
                                }
                                label {
                                    span { "Password" }
                                    input type="password" name="password" minlength=(MIN_ADMIN_PASSWORD_LEN) required autocomplete="new-password";
                                }
                                label {
                                    span { "Confirm password" }
                                    input type="password" name="password_confirm" minlength=(MIN_ADMIN_PASSWORD_LEN) required autocomplete="new-password";
                                }
                                button type="submit" { "Create admin" }
                            }
                        }
                    },
                )
                .into_string(),
            )
            .into_response()
}

pub(crate) fn render_login() -> Response {
    Html(
            layout(
                "Admin login",
                html! {
                    h1 { "Admin login" }
                    section {
                        h2 { "Sign in" }
                        form method="post" action="/admin/login" class="form" {
                            label {
                                span { "Username" }
                                input type="text" name="username" required autocomplete="username";
                            }
                            label {
                                span { "Password" }
                                input type="password" name="password" required autocomplete="current-password";
                            }
                            button type="submit" { "Login" }
                        }
                    }
                },
            )
            .into_string(),
        )
        .into_response()
}
