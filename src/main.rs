//! HWID Checker: prints hardware identifiers read directly from Windows APIs
//! (SMBIOS, CPUID, storage/NDIS IOCTLs, EDID, SetupAPI, TPM Base Services), no WMI.

mod changes;
mod collect;
mod overview;
mod report;
mod ui;
mod util;

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use ratatui::text::Line;

use collect::collect;
use ui::{tui, view};

use windows::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle, STD_OUTPUT_HANDLE, SetConsoleMode,
    SetConsoleOutputCP, SetConsoleTitleW,
};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::{PCWSTR, w};

const HELP: &str = "\
Usage: hwid_checker [--once] [--json] [--mask] [--no-color] [--compare <snapshot.json>]

  --once      print every tab once and exit (default when output is redirected)
  --json      print the report as JSON and exit
  --mask      hide the middle of serials and IDs (for screenshots)
  --no-color  disable colours (also honours NO_COLOR)
  --compare   compare against a saved snapshot (also: drop a .json onto the exe);
              with --once prints only the differences, exit code 1 if any

Interactive keys: ←/→ or 1-8 switch tabs, ↑/↓ PgUp/PgDn scroll, r refresh,
m mask identifiers, s save snapshot, c compare with a snapshot, a restart as admin, q quit.";

fn main() {
    let (mut once, mut json, mut mask, mut color) = (false, false, false, std::env::var_os("NO_COLOR").is_none());
    let mut compare: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => once = true,
            "--json" => json = true,
            "--mask" => mask = true,
            "--no-color" => color = false,
            "--compare" => match args.next() {
                Some(p) => compare = Some(PathBuf::from(p)),
                None => fail("--compare needs a snapshot file"),
            },
            "-h" | "--help" => return println!("{HELP}"),
            // A .json dropped onto the exe arrives as a bare path.
            p if p.to_ascii_lowercase().ends_with(".json") => compare = Some(PathBuf::from(p)),
            other => fail(&format!("unknown option: {other}")),
        }
    }

    let admin = util::is_admin();
    if json {
        let report = collect(admin);
        print!("{}", report.to_json(&overview::digest(&report).0));
        return;
    }
    let baseline = compare.map(|p| {
        changes::load(&p).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(2)
        })
    });

    let terminal = std::io::stdout().is_terminal();
    if terminal {
        unsafe {
            let _ = SetConsoleTitleW(w!("HWID Checker"));
        }
    }
    if !once && terminal && std::io::stdin().is_terminal() {
        let path = baseline.as_ref().map(|b| b.path.clone());
        match tui::run(&|| collect(admin), baseline) {
            Ok(tui::Exit::Elevate) => relaunch_elevated(path.as_deref()),
            Ok(tui::Exit::Quit) => {}
            Err(e) => eprintln!("terminal error: {e}"),
        }
        return;
    }

    let color = color && terminal && enable_ansi();
    let width = if terminal {
        ratatui::crossterm::terminal::size().map(|(w, _)| w as usize).unwrap_or(120).clamp(60, 160) - 1
    } else {
        120
    };
    let report = collect(admin);
    let opts = view::Opts { mask };
    let print = |lines: &[Line]| {
        let _ = std::io::stdout().lock().write_all(view::to_ansi(lines, color).as_bytes());
    };
    match &baseline {
        // With a snapshot, print only the comparison; exit code 1 means "differs".
        Some(b) => {
            let cmp = changes::compare(b, &report);
            let mut lines = vec![Line::from(view::header_spans(&report)), Line::default()];
            lines.extend(view::cards(&cmp.sections(b, &report, mask), width, &opts));
            print(&lines);
            std::process::exit(!cmp.changes.is_empty() as i32);
        }
        None => print(&view::document(&report, &overview::sections(&report), width, &opts)),
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("{msg}\n\n{HELP}");
    std::process::exit(2);
}

/// UTF-8 output and ANSI escapes for the plain (non-TUI) mode.
fn enable_ansi() -> bool {
    unsafe {
        let _ = SetConsoleOutputCP(65001);
        let Ok(h) = GetStdHandle(STD_OUTPUT_HANDLE) else { return false };
        let mut mode = CONSOLE_MODE::default();
        GetConsoleMode(h, &mut mode).is_ok() && SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING).is_ok()
    }
}

/// Restarts elevated, keeping the snapshot being compared against and the
/// working directory (runas would otherwise start in System32, where `s`
/// would then save snapshots).
fn relaunch_elevated(compare: Option<&Path>) {
    let Ok(exe) = std::env::current_exe() else { return };
    let exe = util::wide(&exe.to_string_lossy());
    let params = util::wide(&compare.map(|p| format!("--compare \"{}\"", p.display())).unwrap_or_default());
    let dir = util::wide(&std::env::current_dir().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default());
    unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            PCWSTR(exe.as_ptr()),
            PCWSTR(params.as_ptr()),
            PCWSTR(dir.as_ptr()),
            SW_SHOWNORMAL,
        );
    }
}
