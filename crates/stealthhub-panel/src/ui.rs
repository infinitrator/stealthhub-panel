use maud::{html, Markup, PreEscaped, DOCTYPE};

pub(crate) const APP_NAME: &str = "Infiproxy";

pub(crate) fn layout(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="ru" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                style {
                    (PreEscaped(r#"
                    :root {
                        color-scheme: light;
                        font-family: "Aptos", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
                        background: #e5e7e3;
                        color: #202a33;
                        --bg: #e5e7e3;
                        --chrome: #4a5049;
                        --chrome-dark: #343933;
                        --chrome-soft: #dfe5dc;
                        --panel: #ffffff;
                        --panel-soft: #f6f7f4;
                        --panel-strong: #edf1ea;
                        --border: #c9cfc5;
                        --border-strong: #8d9a88;
                        --text: #232923;
                        --muted: #667064;
                        --accent: #4f7f35;
                        --accent-dark: #365f24;
                        --ok-bg: #e4f1df;
                        --ok-text: #315f24;
                        --warn-bg: #fff3d5;
                        --warn-text: #875600;
                        --danger-bg: #fbe4e4;
                        --danger-text: #9f1c1c;
                    }
                    * { box-sizing: border-box; }
                    body {
                        margin: 0;
                        min-height: 100vh;
                        background: var(--bg);
                        color: var(--text);
                    }
                    .app-chrome {
                        min-height: 100vh;
                        display: grid;
                        grid-template-rows: auto 1fr;
                    }
                    .masthead {
                        min-height: 46px;
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        gap: 18px;
                        padding: 8px 22px;
                        background: linear-gradient(180deg, var(--chrome) 0%, var(--chrome-dark) 100%);
                        border-bottom: 1px solid #2b302b;
                        color: #f6fbfd;
                        box-shadow: 0 1px 0 rgba(255,255,255,0.18) inset;
                    }
                    .masthead-title {
                        display: flex;
                        align-items: center;
                        gap: 10px;
                        font-weight: 750;
                        letter-spacing: 0.01em;
                    }
                    .masthead-meta {
                        color: #dce7d6;
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: 0.08em;
                    }
                    .layout-shell {
                        display: grid;
                        grid-template-columns: 232px minmax(0, 1fr);
                        min-height: 0;
                    }
                    .content {
                        width: 100%;
                        max-width: 1280px;
                        padding: 22px 26px 42px;
                    }
                    a {
                        color: inherit;
                        text-underline-offset: 3px;
                    }
                    h1 {
                        font-size: 26px;
                        line-height: 1.2;
                        margin: 0 0 12px;
                        color: #20261f;
                    }
                    h2 {
                        margin: 0 0 12px;
                        font-size: 16px;
                        color: #2c352b;
                    }
                    p { color: var(--muted); line-height: 1.55; }
                    code {
                        display: inline-block;
                        padding: 3px 6px;
                        border-radius: 3px;
                        background: #eef1eb;
                        border: 1px solid #c9d7df;
                        color: #2f4f25;
                        word-break: break-all;
                    }
                    .top-nav {
                        min-height: 100%;
                        padding: 16px 10px;
                        border-right: 1px solid var(--border);
                        background: linear-gradient(180deg, #f9faf7 0%, #edf1ea 100%);
                    }
                    .top-nav a {
                        display: block;
                        margin-bottom: 4px;
                        padding: 9px 10px;
                        border: 1px solid transparent;
                        border-radius: 3px;
                        color: #30382f;
                        text-decoration: none;
                        font-size: 14px;
                        font-weight: 650;
                    }
                    .top-nav a:hover {
                        color: var(--text);
                        border-color: #b5c8d3;
                        background: #ffffff;
                    }
                    .nav-section {
                        margin: 10px 8px 8px;
                        color: #6b7d89;
                        font-size: 11px;
                        font-weight: 800;
                        text-transform: uppercase;
                        letter-spacing: 0.08em;
                    }
                    .cards, .grid {
                        display: flex;
                        flex-direction: column;
                        gap: 7px;
                        margin-top: 16px;
                    }
                    .card, section, .notice {
                        background: var(--panel);
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        padding: 13px 14px;
                        text-decoration: none;
                        box-shadow: 0 1px 2px rgba(31, 55, 70, 0.06);
                    }
                    section {
                        margin-top: 12px;
                    }
                    .cards .card, .grid section {
                        min-height: 52px;
                        display: grid;
                        grid-template-columns: 220px minmax(0, 1fr) auto;
                        align-items: center;
                        gap: 12px;
                        margin-top: 0;
                        padding: 10px 12px;
                    }
                    .cards .card h2, .grid section h2 {
                        margin: 0;
                    }
                    .cards .card p, .grid section p {
                        margin: 0;
                    }
                    .grid section ul {
                        grid-column: 2 / -1;
                        columns: 2;
                        margin: 0;
                        padding-left: 18px;
                    }
                    .grid section .button {
                        justify-self: end;
                    }
                    .card:hover, .button:hover, button:hover {
                        border-color: var(--accent);
                    }
                    .notice {
                        margin: 14px 0;
                        background: var(--panel-soft);
                        color: var(--muted);
                        border-left: 4px solid var(--accent);
                    }
                    .error {
                        border-color: #c64d4d;
                        color: var(--danger-text);
                        background: #fff6f6;
                    }
                    li { margin: 6px 0; }
                    .button, button {
                        display: inline-block;
                        min-height: 34px;
                        padding: 7px 12px;
                        border-radius: 3px;
                        border: 1px solid var(--border-strong);
                        background: linear-gradient(180deg, #ffffff 0%, #e7eef2 100%);
                        color: #2a3926;
                        text-decoration: none;
                        cursor: pointer;
                        font-weight: 650;
                        box-shadow: 0 1px 0 rgba(255,255,255,0.9) inset;
                    }
                    .button.compact {
                        min-height: 30px;
                        padding: 6px 10px;
                        margin: 0 6px 6px 0;
                    }
                    .button.secondary {
                        border-color: var(--border);
                        background: #f7fafb;
                        color: var(--muted);
                    }
                    .form {
                        display: grid;
                        gap: 12px;
                        max-width: 520px;
                    }
                    label {
                        display: grid;
                        gap: 6px;
                    }
                    label span {
                        color: var(--muted);
                        font-size: 14px;
                    }
                    input, select, textarea {
                        width: 100%;
                        min-height: 38px;
                        padding: 9px 10px;
                        border-radius: 3px;
                        border: 1px solid var(--border);
                        background: #ffffff;
                        color: var(--text);
                        font-size: 15px;
                    }
                    textarea {
                        min-height: 180px;
                        resize: vertical;
                        font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
                        line-height: 1.45;
                    }
                    input:focus, select:focus, textarea:focus {
                        outline: 2px solid rgba(8, 125, 161, 0.22);
                        border-color: var(--accent);
                    }
                    small {
                        color: var(--muted);
                        font-size: 12px;
                        line-height: 1.35;
                    }
                    .table-wrap {
                        overflow-x: auto;
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        background: #ffffff;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        min-width: 860px;
                    }
                    th, td {
                        text-align: left;
                        border-bottom: 1px solid var(--border);
                        padding: 9px 10px;
                        vertical-align: top;
                        font-size: 14px;
                    }
                    tbody tr:hover {
                        background: #f3f7ef;
                    }
                    th {
                        color: #4f5a4d;
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: 0.05em;
                        background: linear-gradient(180deg, #f5f8fa 0%, #e7eef2 100%);
                    }
                    .badge {
                        display: inline-block;
                        padding: 3px 8px;
                        border-radius: 3px;
                        font-weight: 700;
                        font-size: 12px;
                        border: 1px solid transparent;
                    }
                    .badge.ok {
                        background: var(--ok-bg);
                        color: var(--ok-text);
                        border-color: #a8d9bb;
                    }
                    .badge.off {
                        background: var(--danger-bg);
                        color: var(--danger-text);
                        border-color: #e4b0b0;
                    }
                    .badge.neutral {
                        background: #eef1eb;
                        color: #3c5534;
                        border-color: #c9d7df;
                    }
                    .inline-ok {
                        color: var(--ok-text);
                        font-weight: 700;
                    }
                    .inline-warn {
                        color: var(--danger-text);
                        font-weight: 700;
                    }
                    .inline-form {
                        display: inline-block;
                        margin: 0 6px 6px 0;
                    }
                    .admin-bar {
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        gap: 12px;
                        margin-bottom: 16px;
                        padding: 10px 12px;
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        background: var(--panel-strong);
                    }
                    .status-strip {
                        display: flex;
                        flex-direction: column;
                        gap: 6px;
                        margin: 16px 0;
                    }
                    .metric {
                        min-height: 42px;
                        display: grid;
                        grid-template-columns: 180px minmax(0, 1fr);
                        align-items: center;
                        gap: 12px;
                        padding: 8px 12px;
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        background: linear-gradient(180deg, #ffffff 0%, #f5f8fa 100%);
                    }
                    .metric span {
                        display: block;
                        color: var(--muted);
                        font-size: 12px;
                        text-transform: uppercase;
                        letter-spacing: 0.04em;
                    }
                    .metric strong {
                        display: block;
                        margin-top: 0;
                    }
                    .actions {
                        display: flex;
                        flex-wrap: wrap;
                        align-items: center;
                        gap: 8px;
                        margin-top: 16px;
                    }
                    .eyebrow {
                        display: block;
                        margin-bottom: 6px;
                        color: var(--muted);
                        font-size: 11px;
                        font-weight: 850;
                        text-transform: uppercase;
                        letter-spacing: 0.1em;
                    }
                    .health-hero {
                        display: grid;
                        grid-template-columns: minmax(0, 1fr) 160px;
                        align-items: center;
                        gap: 18px;
                        border-left-width: 6px;
                        background:
                            linear-gradient(135deg, rgba(79,127,53,0.08) 0%, rgba(255,255,255,0) 42%),
                            #ffffff;
                    }
                    .health-hero.ok {
                        border-left-color: var(--accent);
                    }
                    .health-hero.warn {
                        border-left-color: #b68123;
                    }
                    .health-hero.off {
                        border-left-color: #b33a3a;
                    }
                    .health-hero h2 {
                        margin: 0;
                        font-size: 28px;
                        text-transform: uppercase;
                        letter-spacing: 0.03em;
                    }
                    .health-hero p {
                        max-width: 720px;
                        margin: 8px 0 0;
                    }
                    .health-ring {
                        min-height: 118px;
                        display: grid;
                        place-items: center;
                        align-content: center;
                        gap: 5px;
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        background: linear-gradient(180deg, #f8faf6 0%, #e8efe4 100%);
                    }
                    .health-ring strong {
                        font-size: 28px;
                        line-height: 1;
                    }
                    .health-ring small {
                        color: var(--muted);
                        text-transform: uppercase;
                        letter-spacing: 0.06em;
                    }
                    .health-led {
                        width: 12px;
                        height: 12px;
                        display: inline-block;
                        border-radius: 50%;
                        border: 1px solid rgba(0,0,0,0.2);
                        background: #9aa29a;
                        box-shadow: 0 0 0 3px rgba(154,162,154,0.18);
                    }
                    .health-led.ok {
                        background: #4f7f35;
                        box-shadow: 0 0 0 3px rgba(79,127,53,0.18);
                    }
                    .health-led.warn {
                        background: #b68123;
                        box-shadow: 0 0 0 3px rgba(182,129,35,0.18);
                    }
                    .health-led.off {
                        background: #b33a3a;
                        box-shadow: 0 0 0 3px rgba(179,58,58,0.16);
                    }
                    .health-grid {
                        display: grid;
                        grid-template-columns: repeat(4, minmax(0, 1fr));
                        gap: 8px;
                    }
                    .health-card {
                        min-height: 138px;
                        display: grid;
                        align-content: start;
                        gap: 10px;
                        padding: 12px;
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        background: linear-gradient(180deg, #ffffff 0%, #f5f8fa 100%);
                    }
                    .health-card-head {
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }
                    .health-card p {
                        margin: 0;
                        font-size: 13px;
                    }
                    .sys-grid {
                        display: grid;
                        grid-template-columns: repeat(4, minmax(0, 1fr));
                        gap: 8px;
                    }
                    .sys-card {
                        min-height: 88px;
                        padding: 10px 12px;
                        border: 1px solid var(--border);
                        border-radius: 4px;
                        background: linear-gradient(180deg, #ffffff 0%, #f5f8fa 100%);
                    }
                    .sys-card span {
                        display: block;
                        color: var(--muted);
                        font-size: 12px;
                        font-weight: 800;
                        text-transform: uppercase;
                        letter-spacing: 0.05em;
                    }
                    .sys-card strong {
                        display: block;
                        margin: 7px 0 4px;
                        font-size: 15px;
                    }
                    .meter {
                        height: 8px;
                        margin-top: 8px;
                        overflow: hidden;
                        border: 1px solid #b8c8b4;
                        border-radius: 999px;
                        background: #e8eee4;
                    }
                    .meter-fill {
                        height: 100%;
                        background: linear-gradient(90deg, #5f8f3f 0%, #8baa52 100%);
                    }
                    .command-output {
                        padding: 12px;
                    }
                    .command-output pre {
                        max-height: 260px;
                        overflow: auto;
                        margin: 8px 0 12px;
                        padding: 10px;
                        border: 1px solid var(--border);
                        border-radius: 3px;
                        background: #20251f;
                        color: #e7f1de;
                        font-size: 12px;
                        white-space: pre-wrap;
                    }
                    .command-output.compact-output pre {
                        max-height: 120px;
                    }
                    .product-card {
                        display: block;
                        background:
                            linear-gradient(135deg, rgba(79,127,53,0.1) 0%, rgba(255,255,255,0) 46%),
                            #ffffff;
                    }
                    .runbook ol {
                        margin: 0;
                        padding-left: 22px;
                    }
                    .config-list {
                        display: flex;
                        flex-direction: column;
                        gap: 10px;
                    }
                    .config-row {
                        padding: 0;
                    }
                    .config-row-head {
                        display: flex;
                        align-items: center;
                        justify-content: space-between;
                        gap: 12px;
                        padding: 10px 12px;
                        border-bottom: 1px solid var(--border);
                        background: var(--panel-strong);
                    }
                    .config-row h3 {
                        margin: 0;
                        font-size: 15px;
                    }
                    .config-row-meta {
                        display: flex;
                        flex-wrap: wrap;
                        align-items: center;
                        justify-content: flex-end;
                        gap: 6px;
                    }
                    .config-form {
                        display: grid;
                        grid-template-columns: repeat(2, minmax(0, 1fr));
                        gap: 12px;
                        padding: 12px;
                    }
                    .config-form.wide {
                        grid-template-columns: minmax(220px, 0.35fr) minmax(0, 0.65fr);
                    }
                    .config-form button {
                        justify-self: start;
                    }
                    .code-editor {
                        min-height: 320px;
                        resize: vertical;
                        font-family: "SFMono-Regular", "Cascadia Mono", "Liberation Mono", monospace;
                        line-height: 1.45;
                        white-space: pre;
                        overflow: auto;
                    }
                    .full-span {
                        grid-column: 1 / -1;
                    }
                    .switch-field {
                        display: grid;
                        grid-template-columns: 42px minmax(0, 1fr);
                        align-items: center;
                        gap: 10px;
                    }
                    .switch-field input {
                        position: absolute;
                        opacity: 0;
                        width: 1px;
                        height: 1px;
                    }
                    .switch-ui {
                        width: 38px;
                        height: 20px;
                        position: relative;
                        border-radius: 999px;
                        border: 1px solid #9fb2bf;
                        background: #d5dde3;
                    }
                    .switch-ui::after {
                        content: "";
                        position: absolute;
                        top: 2px;
                        left: 2px;
                        width: 14px;
                        height: 14px;
                        border-radius: 50%;
                        background: #ffffff;
                        border: 1px solid #9fb2bf;
                        transition: transform 120ms ease;
                    }
                    .switch-field input:checked + .switch-ui {
                        background: #5f8f3f;
                        border-color: #4f7f35;
                    }
                    .switch-field input:checked + .switch-ui::after {
                        transform: translateX(18px);
                    }
                    .details {
                        display: grid;
                        grid-template-columns: max-content minmax(0, 1fr);
                        gap: 8px 14px;
                        margin: 16px 0 0;
                    }
                    .details dt {
                        color: var(--muted);
                        font-size: 13px;
                    }
                    .details dd {
                        min-width: 0;
                        margin: 0;
                    }
                    .danger-zone {
                        border-color: #d88f8f;
                    }

                    .button.danger, button.danger {
                        border-color: #c64d4d;
                        background: var(--danger-bg);
                        color: var(--danger-text);
                    }
                    @media (max-width: 760px) {
                        .masthead {
                            align-items: flex-start;
                            flex-direction: column;
                            gap: 4px;
                            padding: 10px 14px;
                        }
                        .layout-shell {
                            display: block;
                        }
                        .top-nav {
                            min-height: auto;
                            display: flex;
                            flex-wrap: wrap;
                            gap: 6px;
                            padding: 10px;
                            border-right: 0;
                            border-bottom: 1px solid var(--border);
                        }
                        .top-nav a {
                            margin-bottom: 0;
                            padding: 7px 9px;
                        }
                        .nav-section {
                            width: 100%;
                            margin: 6px 4px 0;
                        }
                        .content {
                            padding: 16px 12px 32px;
                        }
                        .cards .card, .grid section, .metric {
                            grid-template-columns: 1fr;
                            align-items: start;
                            gap: 6px;
                        }
                        .health-hero {
                            grid-template-columns: 1fr;
                        }
                        .health-grid {
                            grid-template-columns: 1fr;
                        }
                        .product-card {
                            grid-template-columns: 1fr;
                        }
                        .sys-grid {
                            grid-template-columns: 1fr;
                        }
                        .config-row-head {
                            align-items: flex-start;
                            flex-direction: column;
                        }
                        .config-row-meta {
                            justify-content: flex-start;
                        }
                        .config-form, .config-form.wide {
                            grid-template-columns: 1fr;
                        }
                        .full-span {
                            grid-column: auto;
                        }
                        .grid section ul {
                            grid-column: auto;
                            columns: 1;
                        }
                        .grid section .button {
                            justify-self: start;
                        }
                        h1 { font-size: 24px; }
                        .admin-bar {
                            align-items: flex-start;
                            flex-direction: column;
                        }
                        .details {
                            grid-template-columns: 1fr;
                        }
                    }
                    "#))
                }
            }
            body {
                div class="app-chrome" {
                    header class="masthead" {
                        div class="masthead-title" {
                            span { (APP_NAME) }
                        }
                        div class="masthead-meta" { "server console" }
                    }
                    div class="layout-shell" {
                        nav class="top-nav" aria-label="Main navigation" {
                            div class="nav-section" { "Operate" }
                            a href="/" { "Home" }
                            a href="/admin" { "Dashboard" }
                            a href="/admin/users" { "Users" }
                            a href="/admin/settings" { "Settings" }
                            a href="/admin/protocols" { "Protocols" }
                            a href="/admin/routing" { "Routing" }
                            a href="/admin/cores" { "Cores" }
                            a href="/admin/ip" { "IP Check" }
                            div class="nav-section" { "Maintenance" }
                            a href="/admin/system" { "System" }
                            a href="/admin/configs" { "Configs" }
                            a href="/health" { "Health" }
                            a href="/admin/credits" { "Credits" }
                        }
                        main class="content" {
                            (body)
                        }
                    }
                }
            }
        }
    }
}
