use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
pub enum Style {
    Heading,
    Accent,
    Good,
    Warn,
    Error,
    Muted,
    Create,
    Merge,
    Keep,
}

pub fn stdout_color_enabled() -> bool {
    color_enabled(io::stdout().is_terminal())
}

pub fn stderr_color_enabled() -> bool {
    color_enabled(io::stderr().is_terminal())
}

fn color_enabled(is_terminal: bool) -> bool {
    if std::env::var("JANKURAI_COLOR").as_deref() == Ok("always") {
        return true;
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    is_terminal && std::env::var("TERM").as_deref() != Ok("dumb")
}

pub fn paint(style: Style, text: impl AsRef<str>, enabled: bool) -> String {
    let text = text.as_ref();
    if !enabled {
        return text.to_string();
    }
    let code = match style {
        Style::Heading => "1;38;5;51",
        Style::Accent => "1;38;5;207",
        Style::Good => "1;38;5;46",
        Style::Warn => "1;38;5;220",
        Style::Error => "1;38;5;196",
        Style::Muted => "1;38;5;159",
        Style::Create => "1;38;5;46",
        Style::Merge => "1;38;5;51",
        Style::Keep => "1;38;5;159",
    };
    format!("\x1b[{code}m{text}\x1b[0m")
}

pub fn epaint(style: Style, text: impl AsRef<str>) -> String {
    paint(style, text, stderr_color_enabled())
}

pub fn status(style: Style, label: &str, message: impl AsRef<str>) {
    eprintln!(
        "{} {}",
        epaint(style, format!("[{label}]")),
        message.as_ref()
    );
}

pub fn audit_banner() {
    if !progress_enabled() && !demo_enabled() {
        return;
    }
    eprintln!(
        "{}",
        epaint(
            Style::Heading,
            "╔════════════════════════════════════════════════════════════╗"
        )
    );
    eprintln!(
        "{}",
        epaint(
            Style::Heading,
            "║  JANKURAI AUDIT                                            ║"
        )
    );
    eprintln!(
        "{}",
        epaint(
            Style::Accent,
            "║  live score · ownership · proof · unsafe change detection  ║"
        )
    );
    eprintln!(
        "{}",
        epaint(
            Style::Heading,
            "╚════════════════════════════════════════════════════════════╝"
        )
    );
}

pub fn audit_scorecard(
    score: i32,
    raw: i32,
    findings: usize,
    minimum_score: Option<i32>,
    verdict: &str,
) {
    if !progress_enabled()
        && !demo_enabled()
        && std::env::var("JANKURAI_PROGRESS").as_deref() != Ok("always")
    {
        return;
    }
    let style = match verdict {
        "PASS" => Style::Good,
        "ADVISORY" => Style::Warn,
        _ => Style::Error,
    };
    let floor = minimum_score.map_or_else(|| "unknown".into(), |value| value.to_string());
    eprintln!("{}", epaint(style, "┌────────────── score ──────────────┐"));
    eprintln!(
        "{}",
        epaint(
            style,
            format!("│  {score:>3}/100   raw {raw:<3}   {verdict:<8}  │")
        )
    );
    eprintln!(
        "{}",
        epaint(
            Style::Warn,
            format!("│  findings {findings:<4}   floor {floor:<7}     │")
        )
    );
    eprintln!("{}", epaint(style, "└───────────────────────────────────┘"));
}

pub struct CliProgress {
    interactive: bool,
    forced_lines: bool,
    len: u64,
    pos: AtomicU64,
}

impl CliProgress {
    pub fn new(label: &str, len: u64) -> Self {
        let force = std::env::var("JANKURAI_PROGRESS").as_deref() == Ok("always");
        let len = len.max(1);
        if force && !io::stderr().is_terminal() {
            status(Style::Accent, "progress", label);
            return Self {
                interactive: false,
                forced_lines: true,
                len,
                pos: AtomicU64::new(0),
            };
        }
        if !force && !progress_enabled() {
            return Self {
                interactive: false,
                forced_lines: false,
                len,
                pos: AtomicU64::new(0),
            };
        }
        eprintln!("{}", epaint(Style::Accent, label));
        Self {
            interactive: true,
            forced_lines: false,
            len,
            pos: AtomicU64::new(0),
        }
    }

    pub fn tick(&self, message: impl Into<String>) {
        let message = message.into();
        let pos = self.pos.fetch_add(1, Ordering::Relaxed) + 1;
        if self.forced_lines {
            eprintln!("{}", forced_progress_line(pos, self.len, &message));
            return;
        }
        if self.interactive {
            eprint!("\r{}\x1b[K", forced_progress_line(pos, self.len, &message));
            let _ = io::stderr().flush();
        }
    }

    pub fn finish(&self, message: impl Into<String>) {
        let message = message.into();
        if self.forced_lines {
            eprintln!("{}", forced_progress_line(self.len, self.len, &message));
            return;
        }
        if self.interactive {
            self.pos.store(self.len, Ordering::Relaxed);
            eprintln!(
                "\r{}\x1b[K",
                forced_progress_line(self.len, self.len, &message)
            );
        }
    }
}

fn forced_progress_line(pos: u64, len: u64, message: &str) -> String {
    let width = 32usize;
    let ratio = (pos.min(len) as f64 / len.max(1) as f64).clamp(0.0, 1.0);
    let filled = (ratio * width as f64).round() as usize;
    let bar = format!(
        "{}{}",
        "█".repeat(filled),
        "░".repeat(width.saturating_sub(filled))
    );
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"][(pos as usize) % 8];
    let pct = (ratio * 100.0).round() as u64;
    let line = format!(
        "{spinner} {bar} {:>3}%  {:>2}/{}  {message}",
        pct,
        pos.min(len),
        len
    );
    let style = if pos >= len {
        Style::Good
    } else {
        Style::Accent
    };
    epaint(style, line)
}

fn demo_enabled() -> bool {
    std::env::var("JANKURAI_DEMO").as_deref() == Ok("1")
}

fn progress_enabled() -> bool {
    if std::env::var("JANKURAI_PROGRESS").as_deref() == Ok("always") {
        return true;
    }
    if std::env::var("JANKURAI_PROGRESS").as_deref() == Ok("never") {
        return false;
    }
    io::stderr().is_terminal() && std::env::var("TERM").as_deref() != Ok("dumb")
}

#[cfg(test)]
mod tests {
    use super::forced_progress_line;

    #[test]
    fn progress_bar_uses_block_cells() {
        let line = forced_progress_line(4, 8, "scan repository");
        assert!(line.contains('█') || line.contains('░'));
        assert!(line.contains("scan repository"));
        assert!(line.contains("50%"));
    }
}
