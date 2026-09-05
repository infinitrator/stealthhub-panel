//! Deterministic TUI state machine. Rendering and key handling perform no I/O.

use crate::{
    data::Snapshot,
    operation::{self, Action},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

pub const SCREENS: &[&str] = &[
    "Dashboard",
    "System",
    "Users",
    "Profiles",
    "Runtimes",
    "Updates",
    "Logs",
    "Diagnostics",
    "Secrets",
    "HTTPS",
    "Deployment",
    "Danger",
];

pub struct Form {
    pub action: Action,
    pub values: Vec<String>,
    pub field: usize,
    pub confirmation: String,
    pub error: String,
}

pub enum Intent {
    None,
    Quit,
    Refresh,
    Execute(Action, Vec<String>),
}

pub struct App {
    pub snapshot: Snapshot,
    pub screen: usize,
    pub selected: usize,
    pub focus: u8,
    pub scroll: u16,
    pub form: Option<Form>,
    pub help: bool,
    pub busy: bool,
    pub output: String,
    pub completed_steps: Vec<&'static str>,
}

impl App {
    pub fn new(guided: bool) -> Self {
        Self {
            snapshot: Snapshot::default(),
            screen: if guided { 10 } else { 0 },
            selected: 0,
            focus: 0,
            scroll: 0,
            form: None,
            help: false,
            busy: true,
            output: "Loading local node observations...".into(),
            completed_steps: vec![],
        }
    }
    pub fn screen_name(&self) -> &'static str {
        SCREENS[self.screen]
    }
    pub fn actions(&self) -> Vec<Action> {
        operation::actions(self.screen_name(), &self.snapshot)
    }
    pub fn content(&self) -> String {
        let default=match self.screen_name() {
            "HTTPS" => "Cloudflare DNS-01 / panel HTTPS\nUse a zone-scoped DNS Edit + Zone Read credential.\nThe API credential is hidden and sent through stdin.\nDNS record is DNS-only. TLS terminates at nginx.\nPorts 80/443 must be available.\nCertificate renewal uses Certbot's timer.",
            "Deployment" => "GUIDED DEPLOYMENT\nComplete steps in order; optional HTTPS/runtime steps may be skipped.\nEach action reports its own result; failed steps stay incomplete.\nRepeat runtime step for each required module.\nAt completion use HTTPS /admin/setup or an SSH tunnel.\nRetrieve the one-time setup credential locally from the root env file.\nProfiles remain disabled until explicitly configured in the web panel.",
            "Danger" => "DESTRUCTIVE OPERATIONS\nInspect the removal preview and verify your backup first.\nPanel: preserves runtimes and third-party packages.\nFull: removes the Infiproxy runtime/config footprint.\nFactory: also removes /opt/infiproxy.\nNeither mode recreates a clean operating-system image.",
            "Logs" => "Select a known service to read its bounded journal.\nOutput is limited; credential-bearing lines are redacted.",
            "Users"|"Profiles" => "No records available. Edit through the authenticated web panel.",
            _ => "No observations available. Press R to refresh.",
        };
        let mut value = self
            .snapshot
            .sections
            .get(self.screen_name())
            .cloned()
            .unwrap_or(default.into());
        if matches!(self.screen_name(), "Users" | "Profiles") {
            value.push_str(
                "\n\nRead-only view, up to 500 records. Edit through the authenticated web panel.",
            );
        }
        if self.screen_name() == "Deployment" && !self.completed_steps.is_empty() {
            value.push_str(&format!(
                "\nCompleted this session: {}",
                self.completed_steps.join(", ")
            ));
        }
        format!("{}\n\n{}", value, self.output)
    }
    pub fn key(&mut self, key: KeyEvent) -> Intent {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Intent::Quit;
        }
        if self.help {
            self.help = false;
            return Intent::None;
        }
        if let Some(form) = self.form.as_mut() {
            if key.code == KeyCode::Esc {
                self.form = None;
                return Intent::None;
            }
            let input_count = form.values.len();
            match key.code {
                KeyCode::Tab | KeyCode::Down => form.field = (form.field + 1) % (input_count + 1),
                KeyCode::BackTab | KeyCode::Up => {
                    form.field = (form.field + input_count) % (input_count + 1)
                }
                KeyCode::Left | KeyCode::Right
                    if form.field < input_count
                        && !form.action.fields[form.field].choices.is_empty() =>
                {
                    let choices = &form.action.fields[form.field].choices;
                    let index = choices
                        .iter()
                        .position(|v| v == &form.values[form.field])
                        .unwrap_or(0);
                    let next = if key.code == KeyCode::Right {
                        (index + 1) % choices.len()
                    } else {
                        (index + choices.len() - 1) % choices.len()
                    };
                    form.values[form.field] = choices[next].clone();
                }
                KeyCode::Backspace => {
                    if form.field < input_count {
                        form.values[form.field].pop();
                    } else {
                        form.confirmation.pop();
                    }
                }
                KeyCode::Char(c) if !c.is_control() => {
                    let value = if form.field < input_count {
                        &mut form.values[form.field]
                    } else {
                        &mut form.confirmation
                    };
                    let max = if form.field < input_count && form.action.fields[form.field].secret {
                        8192
                    } else {
                        256
                    };
                    if value.len() + c.len_utf8() <= max {
                        value.push(c);
                    }
                }
                KeyCode::Enter => {
                    if form.field < input_count {
                        form.field += 1;
                        return Intent::None;
                    }
                    if let Err(e) = operation::validate(&form.action, &form.values) {
                        form.error = e.to_string();
                        return Intent::None;
                    }
                    if form
                        .action
                        .confirmation
                        .is_some_and(|expected| form.confirmation != expected)
                    {
                        form.error = "Enter the exact confirmation text to proceed".into();
                        return Intent::None;
                    }
                    let form = self.form.take().expect("form exists");
                    self.busy = true;
                    self.output =
                        "Operation running. Status will be reported when the helper exits.".into();
                    return Intent::Execute(form.action, form.values);
                }
                _ => {}
            }
            return Intent::None;
        }
        match key.code {
            KeyCode::Char('q') => return Intent::Quit,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('r' | 'R') if !self.busy => {
                self.busy = true;
                return Intent::Refresh;
            }
            KeyCode::Tab => self.focus = (self.focus + 1) % 3,
            KeyCode::BackTab => self.focus = (self.focus + 2) % 3,
            KeyCode::Esc => self.focus = 0,
            KeyCode::Up | KeyCode::Char('k') => match self.focus {
                0 => {
                    self.screen = self.screen.saturating_sub(1);
                    self.selected = 0;
                    self.scroll = 0;
                }
                1 => self.selected = self.selected.saturating_sub(1),
                _ => self.scroll = self.scroll.saturating_sub(1),
            },
            KeyCode::Down | KeyCode::Char('j') => match self.focus {
                0 => {
                    self.screen = (self.screen + 1).min(SCREENS.len() - 1);
                    self.selected = 0;
                    self.scroll = 0;
                }
                1 => {
                    self.selected = (self.selected + 1).min(self.actions().len().saturating_sub(1))
                }
                _ => self.scroll = self.scroll.saturating_add(1),
            },
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::Home => self.scroll = 0,
            KeyCode::End => {
                self.scroll = self
                    .content()
                    .lines()
                    .count()
                    .saturating_sub(5)
                    .min(u16::MAX as usize) as u16
            }
            KeyCode::Enter if self.focus == 0 => self.focus = 1,
            KeyCode::Enter if !self.busy && self.focus == 1 => {
                if let Some(action) = self.actions().get(self.selected).cloned() {
                    let values = action
                        .fields
                        .iter()
                        .map(|f| f.choices.first().cloned().unwrap_or_default())
                        .collect();
                    self.form = Some(Form {
                        action,
                        values,
                        field: 0,
                        confirmation: String::new(),
                        error: String::new(),
                    });
                }
            }
            _ => {}
        }
        Intent::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn press(app: &mut App, code: KeyCode) -> Intent {
        app.key(KeyEvent::new(code, KeyModifiers::NONE))
    }
    #[test]
    fn navigation_modal_cancel_and_typed_confirmation() {
        let mut app = App::new(false);
        app.busy = false;
        press(&mut app, KeyCode::Down);
        assert_eq!(app.screen_name(), "System");
        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Enter);
        assert!(app.form.is_some());
        assert!(matches!(press(&mut app, KeyCode::Enter), Intent::None));
        press(&mut app, KeyCode::Esc);
        assert!(app.form.is_none());
        press(&mut app, KeyCode::Enter);
        for c in "APPLY".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        assert!(matches!(
            press(&mut app, KeyCode::Enter),
            Intent::Execute(..)
        ));
    }
    #[test]
    fn busy_state_blocks_duplicate_mutation() {
        let mut app = App::new(false);
        app.focus = 1;
        press(&mut app, KeyCode::Enter);
        assert!(app.form.is_none());
    }
}
