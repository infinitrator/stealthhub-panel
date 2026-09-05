//! Terminal-safe Node Control theme and responsive rendering.

use crate::app::{App, SCREENS};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorMode {
    TrueColor,
    Indexed,
    Ansi,
    None,
}

#[derive(Clone, Copy)]
pub struct Theme {
    pub mode: ColorMode,
    pub ascii: bool,
}
impl Theme {
    pub fn from_environment() -> Self {
        let term = std::env::var("TERM").unwrap_or_default();
        let mode = if std::env::var_os("NO_COLOR").is_some() {
            ColorMode::None
        } else if std::env::var("COLORTERM").is_ok_and(|v| v == "truecolor" || v == "24bit") {
            ColorMode::TrueColor
        } else if term.contains("256color") {
            ColorMode::Indexed
        } else {
            ColorMode::Ansi
        };
        let locale = std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_CTYPE"))
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        Self {
            mode,
            ascii: std::env::var_os("INFIPROXY_TUI_ASCII").is_some()
                || !(locale.contains("utf-8") || locale.contains("utf8")),
        }
    }
    fn base(self) -> Style {
        match self.mode {
            ColorMode::TrueColor => Style::default()
                .fg(Color::Rgb(240, 238, 232))
                .bg(Color::Rgb(23, 25, 28)),
            ColorMode::Indexed => Style::default()
                .fg(Color::Indexed(255))
                .bg(Color::Indexed(234)),
            ColorMode::Ansi => Style::default().fg(Color::White).bg(Color::Black),
            ColorMode::None => Style::default(),
        }
    }
    fn accent(self) -> Style {
        match self.mode {
            ColorMode::TrueColor => self.base().bg(Color::Rgb(147, 58, 61)),
            ColorMode::Indexed => self.base().bg(Color::Indexed(88)),
            ColorMode::Ansi => self.base().bg(Color::Red),
            ColorMode::None => Style::default().add_modifier(Modifier::REVERSED),
        }
    }
    fn border(self) -> border::Set<'static> {
        if self.ascii {
            border::Set {
                top_left: "+",
                top_right: "+",
                bottom_left: "+",
                bottom_right: "+",
                vertical_left: "|",
                vertical_right: "|",
                horizontal_top: "-",
                horizontal_bottom: "-",
            }
        } else {
            border::PLAIN
        }
    }
    fn block(self, title: &str, focused: bool) -> Block<'_> {
        Block::default()
            .borders(Borders::ALL)
            .border_set(self.border())
            .title(title.to_string())
            .border_style(if focused { self.accent() } else { self.base() })
    }
}

/// All external observations are sanitized once more for ASCII terminals.
fn terminal_text(text: &str, ascii: bool) -> String {
    text.chars()
        .map(|c| {
            if c == '\n' || c == '\t' {
                c
            } else if c.is_control() || (ascii && !c.is_ascii()) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn clipped(text: &str, width: usize) -> String {
    let mut value = text.chars().take(width).collect::<String>();
    if text.chars().count() > width && width >= 3 {
        value.truncate(width - 3);
        value.push_str("...");
    }
    value
}

pub fn draw(frame: &mut Frame, app: &App, theme: Theme) {
    let area = frame.area();
    frame.render_widget(Block::default().style(theme.base()), area);
    if area.width < 80 || area.height < 24 {
        frame.render_widget(
            Paragraph::new(
                "Infiproxy requires at least 80 x 24.\nResize the terminal or press Q to exit.",
            )
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let vertical = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(12),
        Constraint::Length(2),
    ])
    .split(area);
    let heading = vec![
        Line::from(Span::styled(
            " INFIPROXY  /  NODE CONTROL",
            theme.accent().add_modifier(Modifier::BOLD),
        )),
        Line::from(terminal_text(
            &format!(
                " NODE {}  |  PANEL {}  |  REV {}",
                app.snapshot.hostname, app.snapshot.panel, app.snapshot.revision
            ),
            theme.ascii,
        )),
        Line::from(terminal_text(
            &format!(
                " RECONCILE {}  |  {}",
                app.snapshot.reconcile,
                if app.busy {
                    "WORKING"
                } else {
                    "OBSERVATION READY / R refresh"
                }
            ),
            theme.ascii,
        )),
    ];
    frame.render_widget(Paragraph::new(heading), vertical[0]);
    let horizontal =
        Layout::horizontal([Constraint::Length(17), Constraint::Min(30)]).split(vertical[1]);
    let list = List::new(SCREENS.iter().map(|s| ListItem::new(*s)))
        .block(theme.block(" WORKSPACES ", app.focus == 0))
        .highlight_style(theme.accent())
        .highlight_symbol("> ");
    frame.render_stateful_widget(
        list,
        horizontal[0],
        &mut ListState::default().with_selected(Some(app.screen)),
    );
    let actions = app.actions();
    let action_height = (actions.len() as u16 + 2).clamp(3, 8);
    let workspace = Layout::vertical([Constraint::Min(6), Constraint::Length(action_height)])
        .split(horizontal[1]);
    let content = terminal_text(&app.content(), theme.ascii);
    frame.render_widget(
        Paragraph::new(content)
            .block(theme.block(app.screen_name(), app.focus == 2))
            .wrap(Wrap { trim: false })
            .scroll((app.scroll, 0)),
        workspace[0],
    );
    let list = List::new(actions.iter().map(|a| ListItem::new(a.label)))
        .block(theme.block(" ACTIONS / Enter to open ", app.focus == 1))
        .highlight_style(theme.accent())
        .highlight_symbol("> ");
    frame.render_stateful_widget(
        list,
        workspace[1],
        &mut ListState::default().with_selected(if actions.is_empty() {
            None
        } else {
            Some(app.selected)
        }),
    );
    frame.render_widget(Paragraph::new(" Arrows: navigate  Tab: focus  Enter: open  PgUp/PgDn: scroll\n R: refresh  ?: help  Esc: back/cancel  Q: quit").style(theme.accent()),vertical[2]);
    if app.help {
        let area = center(area, 74, 14);
        frame.render_widget(Clear, area);
        frame.render_widget(Paragraph::new("INFIPROXY KEYBOARD\n\nTab / Shift-Tab moves between navigation, actions and output.\nArrows choose workspaces/actions; PgUp/PgDn scroll output.\nEnter opens a form, then advances to its confirmation.\nLeft/Right selects registered modules/services in a choice field.\nEsc cancels a form without running any operation.\nQ / Ctrl-C exits. Closing cancels the active helper process group.\nAn interrupted operation may have partially completed: inspect state.\n\nAny key closes help.").wrap(Wrap {trim:false}).style(theme.base()).block(theme.block(" HELP ",true)),area);
    }
    if let Some(form) = &app.form {
        let area = center(area, 74, (form.values.len() as u16 * 3 + 8).min(23));
        frame.render_widget(Clear, area);
        let mut lines = Vec::new();
        for (i, (field, value)) in form.action.fields.iter().zip(&form.values).enumerate() {
            let shown = if field.secret {
                clipped(
                    &"*".repeat(value.chars().count().min(40)),
                    area.width.saturating_sub(4) as usize,
                )
            } else {
                clipped(
                    &terminal_text(value, theme.ascii),
                    area.width.saturating_sub(4) as usize,
                )
            };
            lines.push(Line::from(format!(
                "{} {}{}",
                if i == form.field { ">" } else { " " },
                field.label,
                if field.choices.is_empty() {
                    ""
                } else {
                    " [Left/Right]"
                }
            )));
            lines.push(Line::styled(
                format!("  {shown}"),
                if i == form.field {
                    theme.accent()
                } else {
                    theme.base()
                },
            ));
            lines.push(Line::from(""));
        }
        let expected = form
            .action
            .confirmation
            .unwrap_or("Enter to run read-only operation");
        lines.push(Line::from(format!(
            "{} Confirm: {}",
            if form.field == form.values.len() {
                ">"
            } else {
                " "
            },
            expected
        )));
        lines.push(Line::styled(
            format!(
                "  {}",
                clipped(&form.confirmation, area.width.saturating_sub(4) as usize)
            ),
            theme.accent(),
        ));
        lines.push(Line::from(form.error.clone()));
        lines.push(Line::from(
            "Tab: next field / Enter: next or submit / Esc: cancel",
        ));
        frame.render_widget(
            Paragraph::new(lines)
                .style(theme.base())
                .wrap(Wrap { trim: false })
                .block(theme.block(form.action.label, true)),
            area,
        );
    }
}

fn center(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};
    fn render(app: &App, width: u16, height: u16, theme: Theme) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| draw(frame, app, theme)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect()
    }
    #[test]
    fn renders_dashboard_at_minimum_size_and_resize() {
        let mut app = App::new(false);
        app.snapshot.hostname = "very-long-node-name.example.com".repeat(5);
        app.snapshot.panel = "active".into();
        let theme = Theme {
            mode: ColorMode::None,
            ascii: true,
        };
        for (w, h) in [(80, 24), (120, 40), (200, 60)] {
            let output = render(&app, w, h, theme);
            assert!(output.contains("NODE CONTROL"));
            assert!(output.contains("WORKSPACES"));
            assert!(output.is_ascii());
        }
        assert!(render(&app, 40, 10, theme).contains("80 x 24"));
    }
    #[test]
    fn modal_never_renders_secret_and_all_screens_fit() {
        let mut app = App::new(false);
        app.busy = false;
        app.screen = 8;
        app.focus = 1;
        app.key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Enter,
            crossterm::event::KeyModifiers::NONE,
        ));
        app.form.as_mut().unwrap().values[1] = "SECRET_CANARY".into();
        let theme = Theme {
            mode: ColorMode::Indexed,
            ascii: false,
        };
        let output = render(&app, 80, 24, theme);
        assert!(!output.contains("SECRET_CANARY"));
        assert!(output.contains("********"));
        app.form = None;
        for (index, screen) in SCREENS.iter().enumerate() {
            app.screen = index;
            assert!(render(&app, 80, 24, theme).contains(screen));
        }
    }
    #[test]
    fn no_color_has_no_styled_color() {
        let theme = Theme {
            mode: ColorMode::None,
            ascii: true,
        };
        assert_eq!(theme.base().fg, None);
        assert_eq!(theme.accent().bg, None);
    }
}
