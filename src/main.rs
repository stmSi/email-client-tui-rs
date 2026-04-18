mod app;
mod command;
mod config;
mod mail;

use std::io;
use std::time::Duration;

use anyhow::{Context, Result};
use app::App;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::config::AppConfig;

fn main() -> Result<()> {
    color_eyre::install().map_err(|error| anyhow::anyhow!("{error}"))?;

    let loaded = AppConfig::load().context("failed to load application config")?;
    let mut app = App::new(loaded)?;

    let mut terminal = setup_terminal()?;
    let run_result = run_app(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;
    run_result
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|frame| app.draw(frame))?;

        if app.should_quit() {
            return Ok(());
        }

        if !event::poll(Duration::from_millis(250))? {
            continue;
        }

        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if key.code == KeyCode::Char('c')
                    && key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL)
                {
                    return Ok(());
                }

                if let Err(error) = app.handle_key(key) {
                    app.set_status(format!("Error: {error:#}"));
                }
            }
            Event::Mouse(mouse) => {
                if let Err(error) = app.handle_mouse(mouse) {
                    app.set_status(format!("Error: {error:#}"));
                }
            }
            _ => {}
        }
    }
}
