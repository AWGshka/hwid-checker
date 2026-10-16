//! Report model shared by every collector and renderer, plus JSON output.

use std::fmt::Write;

/// One row of a section: ordered key/value fields. Empty values are omitted.
#[derive(Default, Clone)]
pub struct Item(pub Vec<(&'static str, String)>);

impl Item {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.0.push((key, value.into()));
        self
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    System,
    Hardware,
    Storage,
    Network,
    Devices,
    Security,
    Changes,
}

impl Tab {
    pub const ALL: [Tab; 8] =
        [Tab::Overview, Tab::System, Tab::Hardware, Tab::Storage, Tab::Network, Tab::Devices, Tab::Security, Tab::Changes];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::System => "System",
            Tab::Hardware => "Hardware",
            Tab::Storage => "Storage",
            Tab::Network => "Network",
            Tab::Devices => "Devices",
            Tab::Security => "Security",
            Tab::Changes => "Changes",
        }
    }
}

#[derive(Clone)]
pub struct Section {
    pub key: &'static str,
    pub title: &'static str,
    pub tab: Tab,
    pub items: Vec<Item>,
    /// Shown when there are no items.
    pub note: Option<String>,
}

impl Section {
    pub fn new(key: &'static str, title: &'static str) -> Self {
        Self { key, title, tab: Tab::Overview, items: Vec::new(), note: None }
    }

    pub fn item(mut self, item: Item) -> Self {
        self.items.push(item);
        self
    }

    pub fn items(mut self, items: impl IntoIterator<Item = Item>) -> Self {
        self.items.extend(items);
        self
    }

    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// Assigns every section to `tab`.
pub fn tag(mut sections: Vec<Section>, tab: Tab) -> Vec<Section> {
    for s in &mut sections {
        s.tab = tab;
    }
    sections
}

pub struct Report {
    pub admin: bool,
    pub sections: Vec<Section>,
}

impl Report {
    pub fn section(&self, key: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.key == key)
    }

    /// First non-empty value of `field` in section `key`.
    pub fn first(&self, key: &str, field: &str) -> String {
        self.all(key, field).into_iter().next().unwrap_or_default()
    }

    /// Every non-empty value of `field` across the items of section `key`.
    pub fn all(&self, key: &str, field: &str) -> Vec<String> {
        self.section(key)
            .map(|s| s.items.iter().filter_map(|i| i.get(field)).map(str::to_string).collect())
            .unwrap_or_default()
    }

    pub fn in_tab(&self, tab: Tab) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(move |s| s.tab == tab)
    }

    pub fn to_json(&self, digest: &str) -> String {
        let generated = crate::util::utc_datetime(crate::util::unix_now());
        let mut out = format!(
            "{{\n  \"generated\": \"{generated}\",\n  \"admin\": {},\n  \"hwid_digest\": \"{digest}\",\n  \"sections\": {{",
            self.admin
        );
        for (si, s) in self.sections.iter().enumerate() {
            let _ = write!(out, "{}\n    \"{}\": [", if si > 0 { "," } else { "" }, s.key);
            for (ii, item) in s.items.iter().enumerate() {
                let fields: Vec<String> =
                    item.0.iter().map(|(k, v)| format!("\"{}\": \"{}\"", k, escape(v))).collect();
                let _ = write!(out, "{}\n      {{ {} }}", if ii > 0 { "," } else { "" }, fields.join(", "));
            }
            out.push_str(if s.items.is_empty() { "]" } else { "\n    ]" });
        }
        out.push_str("\n  }\n}\n");
        out
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
