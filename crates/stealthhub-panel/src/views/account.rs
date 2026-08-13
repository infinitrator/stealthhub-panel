//! Administrator credential rotation page.

use crate::{admin_bar, csrf_field, ui::layout, AuthenticatedAdmin};
use axum::response::{Html, IntoResponse, Response};
use maud::html;

pub(crate) fn render(auth: &AuthenticatedAdmin) -> Response {
    Html(
        layout(
            "Account",
            html! {
                (admin_bar(auth))
                h1 { "Account" }
                section {
                    h2 { "Administrator" }
                    dl class="details" {
                        dt { "Username" } dd { code { (&auth.admin.username) } }
                        dt { "Role" } dd {
                            @if auth.is_owner { "owner" } @else { "administrator" }
                        }
                        dt { "Created" } dd { (auth.admin.created_at.format("%Y-%m-%d %H:%M UTC")) }
                    }
                }
                section {
                    h2 { "Change password" }
                    div class="notice" {
                        "A successful change revokes every administrator session, including this one. Sign in again with the new password."
                    }
                    form method="post" action="/admin/account" class="form" {
                        (csrf_field(&auth.csrf_token))
                        label {
                            span { "Current password" }
                            input type="password" name="current_password" maxlength="1024" required autocomplete="current-password";
                        }
                        label {
                            span { "New password" }
                            input type="password" name="new_password" minlength="12" maxlength="1024" required autocomplete="new-password";
                        }
                        label {
                            span { "Confirm new password" }
                            input type="password" name="new_password_confirm" minlength="12" maxlength="1024" required autocomplete="new-password";
                        }
                        button type="submit" { "Change Password" }
                    }
                }
            },
        )
        .into_string(),
    )
    .into_response()
}
