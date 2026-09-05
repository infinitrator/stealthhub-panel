//! Full-screen SSH manager. Observation and operation tasks are separate from
//! rendering; all privileged mutations go through the installed finite helper.

mod app;
mod command;
mod data;
mod operation;
mod render;

use anyhow::{bail, Result};
use app::{App, Intent};
use crossterm::{
    cursor::Show,
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, LeaveAlternateScreen},
};
use std::{
    io::{self, IsTerminal},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}
fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
}

enum Completion {
    Snapshot(data::Snapshot),
    Operation(&'static str, Result<String>),
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|v| v == "--help" || v == "-h") {
        println!("Infiproxy Node Control\nUsage: infiproxy-manager [--guided | status [--json] | diagnostics | update check]\nInteractive: arrows, Tab, Enter, Esc, R, ?, Q.\nNO_COLOR and INFIPROXY_TUI_ASCII are supported.\nLegacy recovery: infiproxy-manager --legacy");
        return Ok(());
    }
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["status"] | ["status", "--json"] => {
            let snapshot = data::collect().await;
            if args.len() == 2 {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            } else {
                println!(
                    "{}",
                    snapshot.sections.get("Dashboard").unwrap_or(&String::new())
                );
            }
            return Ok(());
        }
        ["diagnostics"] => {
            let snapshot = data::collect().await;
            println!(
                "{}\n{}",
                snapshot.sections.get("Dashboard").unwrap_or(&String::new()),
                snapshot
                    .sections
                    .get("Diagnostics")
                    .unwrap_or(&String::new())
            );
            return Ok(());
        }
        ["update", "check"] => {
            let action = operation::actions("Updates", &data::Snapshot::default()).remove(0);
            println!("{}", operation::execute(action, vec![]).await?);
            return Ok(());
        }
        [] | ["--guided"] => {}
        _ => bail!("Unknown command. Use --help."),
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!("Interactive terminal required. Use status --json or diagnostics.");
    }
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = stop.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        if let (Ok(mut hangup), Ok(mut interrupt), Ok(mut terminate)) = (
            signal(SignalKind::hangup()),
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
        ) {
            tokio::select! {_=hangup.recv()=>{},_=interrupt.recv()=>{},_=terminate.recv()=>{}}
            signal_stop.store(true, Ordering::Relaxed);
        }
    });
    std::panic::set_hook(Box::new(|_| {
        restore();
        eprintln!("Infiproxy manager stopped unexpectedly. Terminal restored; inspect operation state before retrying.");
    }));
    let _guard = TerminalGuard;
    let mut terminal = ratatui::try_init()?;
    let theme = render::Theme::from_environment();
    let mut app = App::new(args.first().is_some_and(|v| v == "--guided"));
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    let tx = sender.clone();
    let mut task = tokio::spawn(async move {
        let _ = tx.send(Completion::Snapshot(data::collect().await)).await;
    });
    let result = (|| -> Result<()> {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            while let Ok(message) = receiver.try_recv() {
                app.busy = false;
                match message {
                    Completion::Snapshot(snapshot) => {
                        app.snapshot = snapshot;
                        app.output="Refreshed local observations. Process/listener status does not prove a proxy handshake.".into();
                    }
                    Completion::Operation(label, result) => match result {
                        Ok(text) => {
                            app.completed_steps.push(label);
                            app.output=format!("{label}: helper completed\n{text}\nPress R to refresh observations.");
                        }
                        Err(error) => app.output = error.to_string(),
                    },
                }
            }
            terminal.draw(|frame| render::draw(frame, &app, theme))?;
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Release {
                        continue;
                    }
                    match app.key(key) {
                        Intent::None => {}
                        Intent::Quit => break,
                        Intent::Refresh => {
                            let tx = sender.clone();
                            task = tokio::spawn(async move {
                                let _ = tx.send(Completion::Snapshot(data::collect().await)).await;
                            });
                        }
                        Intent::Execute(action, values) => {
                            let tx = sender.clone();
                            task = tokio::spawn(async move {
                                let label = action.label;
                                let result = operation::execute(action, values).await;
                                let _ = tx.send(Completion::Operation(label, result)).await;
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    })();
    task.abort();
    let _ = task.await;
    result
}
