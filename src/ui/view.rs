//! Turns sections into styled lines (rounded cards with tables or key/value
//! lists). The TUI renders these lines directly; `--once` converts them to ANSI.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use std::fmt::Write;

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::report::{Item, Report, Section};
use crate::util::{ADMIN, NA};

pub mod theme {
    use ratatui::style::Color;
    pub const ACCENT: Color = Color::Rgb(122, 162, 247);
    pub const BRAND: Color = Color::Rgb(187, 154, 247);
    pub const TEXT: Color = Color::Reset;
    pub const MUTED: Color = Color::Rgb(120, 128, 160);
    pub const FAINT: Color = Color::Rgb(68, 75, 106);
    pub const IDENT: Color = Color::Rgb(224, 175, 104);
    pub const GOOD: Color = Color::Rgb(158, 206, 106);
    pub const BAD: Color = Color::Rgb(247, 118, 142);
    pub const WARN: Color = Color::Rgb(255, 158, 100);
}
use theme::*;

/// Wide enough to place two small cards side by side.
const TWO_COLUMN_WIDTH: usize = 120;
const GAP: &str = "   ";

const IDENT_KEYS: &[&str] = &[
    "serial", "uuid", "id", "mac", "factory", "guid", "disk_id", "ek_sha256", "machine_guid", "product_id",
    "hw_profile_guid", "sus_client_id", "sqm_machine_id", "dhcpv6_duid", "machine_sid", "user_sid",
    "hardware_config", "computer_hardware_id", "digest", "identifier", "address", "digest_before", "digest_now",
];
const STATUS_KEYS: &[&str] =
    &["state", "status", "link", "secure_boot", "tpm", "privileges", "mac_status", "mac_addresses", "setup_mode", "result"];

pub fn is_identifier(key: &str) -> bool {
    IDENT_KEYS.contains(&key)
}

pub struct Opts {
    pub mask: bool,
}

// ---------------------------------------------------------------------------
// Labels and value styling

pub fn label(key: &str) -> String {
    key.split('_')
        .map(|w| match w {
            "id" => "ID", "mac" => "MAC", "guid" => "GUID", "sid" => "SID", "uuid" => "UUID", "os" => "OS",
            "ek" => "EK", "sha256" => "SHA-256", "vram" => "VRAM", "fs" => "FS", "sku" => "SKU", "duid" => "DUID",
            "sqm" => "SQM", "usb" => "USB", "cpu" => "CPU", "gpu" => "GPU", "tpm" => "TPM", "dhcpv6" => "DHCPv6",
            "hw" => "HW", "sus" => "SUS", "vid" => "VID", "pid" => "PID", "lmp" => "LMP",
            w => w,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// "NETWORK ADAPTERS" -> "Network adapters", keeping acronyms ("USB devices").
pub fn title_case(title: &str) -> String {
    const ACRONYMS: &[&str] = &["CPU", "GPU", "RAM", "TPM", "BIOS", "SMBIOS", "UUID", "USB", "MAC"];
    title
        .split(' ')
        .enumerate()
        .map(|(i, w)| match w {
            "GUIDS" => "GUIDs".to_string(),
            _ if ACRONYMS.contains(&w) => w.to_string(),
            _ if i == 0 => w[..1].to_string() + &w[1..].to_lowercase(),
            _ => w.to_lowercase(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn sentence(key: &str) -> String {
    let l = label(key);
    let mut c = l.chars();
    c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
}

fn is_placeholder(v: &str) -> bool {
    const KNOWN: &[&str] = &[
        "to be filled by o.e.m.", "default string", "system serial number", "system product name",
        "system manufacturer", "base board serial number", "chassis serial number", "not specified",
        "not applicable", "none", "unknown", "o.e.m.", "0123456789", "123456789", "123456",
    ];
    let l = v.trim().to_ascii_lowercase();
    v == ADMIN || v == NA || KNOWN.contains(&l.as_str()) || (!l.is_empty() && l.chars().all(|c| "0-: ".contains(c)))
}

fn value_style(key: &str, v: &str) -> Style {
    if is_placeholder(v) {
        return Style::new().fg(MUTED).add_modifier(Modifier::ITALIC);
    }
    if STATUS_KEYS.contains(&key) {
        let color = match v {
            _ if v.starts_with("On") || v == "original" || v == "Administrator" || v == "none changed" || v == "identical" => GOOD,
            "up" => GOOD,
            "down" => MUTED,
            "yes" if key == "setup_mode" => WARN,
            "no" if key == "setup_mode" => GOOD,
            _ if v.starts_with("Off") => BAD,
            _ if v.starts_with("spoofed") || v.contains("changed") || v.contains(" difference") => WARN,
            "Standard user" | "locally administered" => WARN,
            "not in snapshot" | "not comparable" => MUTED,
            _ => TEXT,
        };
        return Style::new().fg(color).add_modifier(Modifier::BOLD);
    }
    match (key, v) {
        ("after", "added") => return Style::new().fg(GOOD).add_modifier(Modifier::BOLD),
        ("after", "removed") => return Style::new().fg(BAD).add_modifier(Modifier::BOLD),
        ("before", _) => return Style::new().fg(BAD),
        ("after", _) => return Style::new().fg(GOOD),
        _ => {}
    }
    if key == "note" {
        return Style::new().fg(WARN).add_modifier(Modifier::ITALIC);
    }
    if IDENT_KEYS.contains(&key) {
        return Style::new().fg(IDENT);
    }
    Style::new().fg(TEXT)
}

/// Hides the middle of an identifier, keeping separators: `E3F5••••-…-••0A`.
pub fn mask(v: &str) -> String {
    let n = v.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    if n <= 4 {
        return v.into();
    }
    let mut seen = 0;
    v.chars()
        .map(|c| {
            if !c.is_ascii_alphanumeric() {
                return c;
            }
            seen += 1;
            if seen <= 2 || seen > n - 2 { c } else { '•' }
        })
        .collect()
}

fn display(key: &str, v: &str, o: &Opts) -> String {
    if o.mask && IDENT_KEYS.contains(&key) && !is_placeholder(v) { mask(v) } else { v.to_string() }
}

// ---------------------------------------------------------------------------
// Line helpers

fn truncate(s: &str, max: usize) -> String {
    if s.width() <= max {
        return s.into();
    }
    // Leave one column for the ellipsis.
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let cw = c.width().unwrap_or(0);
        if used + cw + 1 > max {
            break;
        }
        used += cw;
        out.push(c);
    }
    out + "…"
}

/// Truncates/pads spans to exactly `w` columns.
fn fit(spans: Vec<Span<'static>>, w: usize) -> Vec<Span<'static>> {
    let mut used = 0;
    let mut out = Vec::new();
    for s in spans {
        let sw = s.content.width();
        if used + sw <= w {
            used += sw;
            out.push(s);
        } else {
            let t = truncate(&s.content, w - used);
            used += t.width();
            out.push(Span::styled(t, s.style));
            break;
        }
    }
    if used < w {
        out.push(Span::raw(" ".repeat(w - used)));
    }
    out
}

fn pad(s: &str, w: usize) -> String {
    format!("{s}{}", " ".repeat(w.saturating_sub(s.width())))
}

// ---------------------------------------------------------------------------
// Section bodies

fn kv_lines(item: &Item, inner: usize, o: &Opts) -> Vec<Vec<Span<'static>>> {
    let fields: Vec<_> = item.0.iter().filter(|(_, v)| !v.is_empty()).collect();
    let kw = fields.iter().map(|(k, _)| sentence(k).width()).max().unwrap_or(0);
    fields
        .iter()
        .map(|(k, v)| {
            vec![
                Span::styled(pad(&sentence(k), kw), Style::new().fg(MUTED)),
                Span::raw("  "),
                Span::styled(truncate(&display(k, v, o), inner.saturating_sub(kw + 2)), value_style(k, v)),
            ]
        })
        .collect()
}

fn table_lines(items: &[Item], inner: usize, o: &Opts) -> Option<Vec<Vec<Span<'static>>>> {
    let mut cols: Vec<&'static str> = Vec::new();
    for item in items {
        for (k, v) in &item.0 {
            if !v.is_empty() && !cols.contains(k) {
                cols.push(k);
            }
        }
    }
    let cell = |item: &Item, k: &str| item.get(k).map(|v| display(k, v, o)).unwrap_or_default();
    let mut widths: Vec<usize> = cols
        .iter()
        .map(|k| items.iter().map(|i| cell(i, k).width()).max().unwrap_or(0).max(label(k).width()))
        .collect();
    let total = |w: &[usize]| w.iter().sum::<usize>() + GAP.len() * w.len().saturating_sub(1);
    // Squeeze the first (name) column before giving up on the table layout.
    let overflow = total(&widths).saturating_sub(inner);
    if overflow > 0 {
        let min_first = 18.min(widths[0]);
        if widths[0] - min_first < overflow {
            return None;
        }
        widths[0] -= overflow;
    }

    let row = |cells: Vec<(String, Style)>| -> Vec<Span<'static>> {
        let mut spans = Vec::new();
        for (i, ((text, style), w)) in cells.into_iter().zip(&widths).enumerate() {
            if i > 0 {
                spans.push(Span::raw(GAP));
            }
            spans.push(Span::styled(pad(&truncate(&text, *w), *w), style));
        }
        spans
    };
    let header = Style::new().fg(MUTED).add_modifier(Modifier::BOLD);
    let mut lines = vec![row(cols.iter().map(|k| (label(k).to_uppercase(), header)).collect())];
    lines.push(row(widths.iter().map(|w| ("─".repeat(*w), Style::new().fg(FAINT))).collect()));
    for item in items {
        lines.push(row(
            cols.iter()
                .enumerate()
                .map(|(i, k)| {
                    let raw = item.get(k).unwrap_or("");
                    let mut style = value_style(k, raw);
                    if i == 0 && !IDENT_KEYS.contains(k) && !is_placeholder(raw) {
                        style = style.add_modifier(Modifier::BOLD);
                    }
                    (cell(item, k), style)
                })
                .collect(),
        ));
    }
    Some(lines)
}

fn record_lines(items: &[Item], inner: usize, o: &Opts) -> Vec<Vec<Span<'static>>> {
    let mut lines = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            lines.push(vec![Span::styled("┄".repeat(inner), Style::new().fg(FAINT))]);
        }
        lines.extend(kv_lines(item, inner, o));
    }
    lines
}

/// A section as a rounded card exactly `w` columns wide.
pub fn card(s: &Section, w: usize, o: &Opts) -> Vec<Line<'static>> {
    let inner = w.saturating_sub(4);
    let body = if s.items.is_empty() {
        let note = s.note.clone().unwrap_or_else(|| "none found".into());
        vec![vec![Span::styled(note, Style::new().fg(MUTED).add_modifier(Modifier::ITALIC))]]
    } else if s.items.len() == 1 {
        kv_lines(&s.items[0], inner, o)
    } else {
        table_lines(&s.items, inner, o).unwrap_or_else(|| record_lines(&s.items, inner, o))
    };

    let faint = Style::new().fg(FAINT);
    let count = if s.items.len() > 1 { format!(" {}", s.items.len()) } else { String::new() };
    let title_w = s.title.width() + count.width() + 5;
    let mut lines = vec![Line::from(vec![
        Span::styled("╭─ ", faint),
        Span::styled(s.title, Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(count, Style::new().fg(MUTED)),
        Span::styled(format!(" {}╮", "─".repeat(w.saturating_sub(title_w))), faint),
    ])];
    for spans in body {
        let mut l = vec![Span::styled("│ ", faint)];
        l.extend(fit(spans, inner));
        l.push(Span::styled(" │", faint));
        lines.push(Line::from(l));
    }
    lines.push(Line::from(Span::styled(format!("╰{}╯", "─".repeat(w.saturating_sub(2))), faint)));
    lines
}

/// Width a single-item card needs to show everything untruncated.
fn natural_width(s: &Section) -> usize {
    let Some(item) = s.items.first() else {
        return s.note.as_deref().unwrap_or("none found").width() + 4;
    };
    let fields = item.0.iter().filter(|(_, v)| !v.is_empty());
    let kw = fields.clone().map(|(k, _)| sentence(k).width()).max().unwrap_or(0);
    let vw = fields.map(|(_, v)| v.width()).max().unwrap_or(0);
    (kw + 2 + vw + 4).max(s.title.width() + 8)
}

/// Stacks cards vertically; on wide screens pairs up adjacent single-item cards.
pub fn cards<'a>(sections: impl IntoIterator<Item = &'a Section>, w: usize, o: &Opts) -> Vec<Line<'static>> {
    let sections: Vec<&Section> = sections.into_iter().collect();
    let lw = w.saturating_sub(1) / 2;
    let rw = w.saturating_sub(lw + 1);
    // Pair single-item cards only when neither would need truncating.
    let fits = |s: &Section, avail: usize| s.items.len() <= 1 && natural_width(s) <= avail;
    let mut lines = Vec::new();
    let mut i = 0;
    while i < sections.len() {
        if !lines.is_empty() {
            lines.push(Line::default());
        }
        if w >= TWO_COLUMN_WIDTH && i + 1 < sections.len() && fits(sections[i], lw) && fits(sections[i + 1], rw) {
            let (mut left, mut right) = (card(sections[i], lw, o), card(sections[i + 1], rw, o));
            let h = left.len().max(right.len());
            left.resize(h, Line::raw(" ".repeat(lw)));
            right.resize(h, Line::raw(" ".repeat(rw)));
            for (l, r) in left.into_iter().zip(right) {
                let mut spans = l.spans;
                spans.push(Span::raw(" "));
                spans.extend(r.spans);
                lines.push(Line::from(spans));
            }
            i += 2;
        } else {
            lines.extend(card(sections[i], w, o));
            i += 1;
        }
    }
    lines
}

// ---------------------------------------------------------------------------
// Plain (non-interactive) output

pub fn header_spans(r: &Report) -> Vec<Span<'static>> {
    let (badge, color) = if r.admin { (" ADMIN ", GOOD) } else { (" STANDARD USER ", WARN) };
    vec![
        Span::styled(" ◆ HWID CHECKER ", Style::new().fg(BRAND).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" {} ", r.first("windows", "computer_name")), Style::new().fg(MUTED)),
        Span::styled(badge, Style::new().fg(Color::Black).bg(color).bold()),
    ]
}

pub fn document(r: &Report, overview: &[Section], w: usize, o: &Opts) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(header_spans(r)), Line::default()];
    for tab in crate::report::Tab::ALL {
        let secs: Vec<&Section> =
            if tab == crate::report::Tab::Overview { overview.iter().collect() } else { r.in_tab(tab).collect() };
        if secs.is_empty() {
            continue;
        }
        let title = format!(" {} ", tab.title().to_uppercase());
        lines.push(Line::from(vec![
            Span::styled(title.clone(), Style::new().fg(BRAND).add_modifier(Modifier::BOLD)),
            Span::styled("━".repeat(w.saturating_sub(title.width())), Style::new().fg(FAINT)),
        ]));
        lines.extend(cards(secs, w, o));
        lines.push(Line::default());
    }
    lines
}

pub fn to_ansi(lines: &[Line], color: bool) -> String {
    let mut out = String::new();
    let mut text = String::new();
    for line in lines {
        text.clear();
        for span in &line.spans {
            let sgr = if color { sgr(span.style) } else { String::new() };
            if sgr.is_empty() {
                text.push_str(&span.content);
            } else {
                let _ = write!(text, "\x1b[{sgr}m{}\x1b[0m", span.content);
            }
        }
        out.push_str(text.trim_end());
        out.push('\n');
    }
    out
}

fn sgr(style: Style) -> String {
    let mut codes = Vec::new();
    let m = style.add_modifier;
    if m.contains(Modifier::BOLD) {
        codes.push("1".to_string());
    }
    if m.contains(Modifier::ITALIC) {
        codes.push("3".to_string());
    }
    if let Some(Color::Rgb(r, g, b)) = style.fg {
        codes.push(format!("38;2;{r};{g};{b}"));
    } else if style.fg == Some(Color::Black) {
        codes.push("30".into());
    }
    if let Some(Color::Rgb(r, g, b)) = style.bg {
        codes.push(format!("48;2;{r};{g};{b}"));
    }
    codes.join(";")
}
