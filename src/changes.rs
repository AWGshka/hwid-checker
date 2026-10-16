//! Compares the current report against a saved JSON snapshot.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::report::{Item, Report, Section, Tab, tag};
use crate::util::{ADMIN, NA};
use crate::ui::view;

type Fields = Vec<(String, String)>;

pub struct Baseline {
    pub path: PathBuf,
    pub generated: String,
    pub digest: String,
    pub admin: Option<bool>,
    sections: Vec<(String, Vec<Fields>)>,
}

pub fn load(path: &Path) -> Result<Baseline, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("can't read {}: {e}", path.display()))?;
    let v: Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| format!("not valid JSON: {e}"))?;
    let secs = v.get("sections").and_then(Value::as_object).ok_or("not an HWID Checker snapshot")?;
    let sections = secs
        .iter()
        .map(|(key, items)| {
            let items = items
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_object)
                        .map(|o| {
                            o.iter()
                                .map(|(k, v)| (k.clone(), v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
                                .collect()
                        })
                        .collect()
                })
                .unwrap_or_default();
            (key.clone(), items)
        })
        .collect();
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    Ok(Baseline {
        // Absolute, so it survives the working-directory change of an elevated restart.
        path: std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
        generated: s("generated"),
        digest: s("hwid_digest"),
        admin: v.get("admin").and_then(Value::as_bool),
        sections,
    })
}

/// A changed field, or a whole item added/removed (empty `field`).
pub struct Change {
    pub section: &'static str,
    pub item: String,
    pub field: String,
    pub before: String,
    pub after: String,
}

/// Per-section totals, so identical groups can be shown without listing
/// every matching field.
struct Group {
    title: &'static str,
    items: usize,
    /// Fields compared (both sides present and readable).
    fields: usize,
    changed: usize,
    in_snapshot: bool,
}

pub struct Comparison {
    pub changes: Vec<Change>,
    groups: Vec<Group>,
}

/// Fields that change during normal use and say nothing about the machine.
const IGNORED: &[&str] = &["link"];

fn get<'a>(f: &'a Fields, key: &str) -> Option<&'a str> {
    f.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Items keyed by their first value (adapter name, disk model, slot...),
/// numbered when the same name appears more than once.
fn keyed(items: &[Fields]) -> Vec<(String, &Fields)> {
    let mut seen: Vec<String> = Vec::new();
    items
        .iter()
        .map(|f| {
            let name = f.iter().map(|(_, v)| v.as_str()).find(|v| !v.is_empty()).unwrap_or("?").to_string();
            let n = seen.iter().filter(|s| **s == name).count();
            seen.push(name.clone());
            (if n == 0 { name } else { format!("{name} #{}", n + 1) }, f)
        })
        .collect()
}

pub fn compare(base: &Baseline, now: &Report) -> Comparison {
    let mut changes = Vec::new();
    let mut groups = Vec::new();
    for section in &now.sections {
        let mut group = Group { title: section.title, items: section.items.len(), fields: 0, changed: 0, in_snapshot: true };
        // Sections missing from the snapshot (older version) can't be compared.
        let Some((_, old_items)) = base.sections.iter().find(|(k, _)| k == section.key) else {
            group.in_snapshot = false;
            groups.push(group);
            continue;
        };
        let first_change = changes.len();
        let new_items: Vec<Fields> =
            section.items.iter().map(|i| i.0.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()).collect();

        let pairs: Vec<(String, Option<&Fields>, Option<&Fields>)> = if old_items.len() == 1 && new_items.len() == 1 {
            vec![(String::new(), Some(&old_items[0]), Some(&new_items[0]))]
        } else {
            let (old, new) = (keyed(old_items), keyed(&new_items));
            let mut v: Vec<_> = new
                .iter()
                .map(|(k, n)| (k.clone(), old.iter().find(|(ok, _)| ok == k).map(|(_, o)| *o), Some(*n)))
                .collect();
            v.extend(old.iter().filter(|(k, _)| !new.iter().any(|(nk, _)| nk == k)).map(|(k, o)| (k.clone(), Some(*o), None)));
            v
        };

        for (item, old, new) in pairs {
            let change = |field: &str, before: &str, after: &str| Change {
                section: section.key,
                item: item.clone(),
                field: field.to_string(),
                before: before.to_string(),
                after: after.to_string(),
            };
            match (old, new) {
                (Some(o), Some(n)) => {
                    for (k, after) in n {
                        let Some(before) = get(o, k) else { continue };
                        let comparable = |v: &str| v != ADMIN && v != NA;
                        if IGNORED.contains(&k.as_str()) || !comparable(before) || !comparable(after) {
                            continue;
                        }
                        group.fields += 1;
                        if before != after {
                            changes.push(change(k, before, after));
                        }
                    }
                }
                (None, Some(_)) => changes.push(change("", "", "added")),
                (Some(_), None) => changes.push(change("", "", "removed")),
                (None, None) => {}
            }
        }
        group.changed = changes.len() - first_change;
        groups.push(group);
    }
    Comparison { changes, groups }
}

/// Sections for the Changes tab.
pub fn sections(base: Option<&Baseline>, now: &Report, mask: bool) -> Vec<Section> {
    match base {
        Some(base) => compare(base, now).sections(base, now, mask),
        None => tag(
            vec![
                Section::new("compare_help", "COMPARE WITH A SNAPSHOT")
                    .note("Press s to save a snapshot, c to pick one to compare against (or drop a .json on the exe)."),
            ],
            Tab::Changes,
        ),
    }
}

impl Comparison {
    pub fn sections(&self, base: &Baseline, now: &Report, mask: bool) -> Vec<Section> {
        let changes = &self.changes;
        let (digest_now, _) = crate::overview::digest(now);
        let file = base.path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
        let compared = self.groups.iter().filter(|g| g.in_snapshot).count();
        let differing = self.groups.iter().filter(|g| g.changed > 0).count();
        let result = match changes.len() {
            0 => "identical".to_string(),
            n => format!(
                "{n} difference{} in {differing} section{}, {} identical",
                plural(n),
                plural(differing),
                compared - differing
            ),
        };
        let mut summary = Item::new()
            .add("snapshot", file)
            .add("saved", base.generated.clone())
            .add("digest_before", base.digest.clone())
            .add("digest_now", digest_now)
            .add("result", result);
        if base.admin.is_some_and(|a| a != now.admin) {
            summary = summary.add("note", "snapshot and current run differ in admin rights; admin-only fields were skipped");
        }
        let mut out = vec![Section::new("comparison", "COMPARISON").item(summary)];

        let rows: Vec<Item> = changes
            .iter()
            .map(|c| {
                let title = now.section(c.section).map(|s| view::title_case(s.title)).unwrap_or_default();
                let place = if c.item.is_empty() { title } else { format!("{title} · {}", c.item) };
                let shown = |v: &str| if mask && view::is_identifier(&c.field) { view::mask(v) } else { v.to_string() };
                Item::new()
                    .add("where", place)
                    .add("field", view::label(&c.field))
                    .add("before", shown(&c.before))
                    .add("after", shown(&c.after))
            })
            .collect();
        if !rows.is_empty() {
            out.push(Section::new("differences", "DIFFERENCES").items(rows));
        }
        out.push(self.by_section());
        tag(out, Tab::Changes)
    }

    /// One row per section: which groups are identical and which differ
    /// (differing ones first).
    fn by_section(&self) -> Section {
        let mut groups: Vec<&Group> = self.groups.iter().collect();
        groups.sort_by_key(|g| match (g.in_snapshot, g.changed) {
            (true, 1..) => 0,
            (true, 0) => 1,
            (false, _) => 2,
        });
        Section::new("by_section", "BY SECTION").items(groups.into_iter().map(|g| {
            let result = match (g.in_snapshot, g.changed, g.fields) {
                (false, ..) => "not in snapshot".to_string(),
                (true, 0, 0) if g.items > 0 => "not comparable".to_string(),
                (true, 0, _) => "identical".to_string(),
                // Added/removed items aren't field changes, so `c` can exceed `f`.
                (true, c, f) if c <= f => format!("{c} of {f} fields changed"),
                (true, c, _) => format!("{c} changes"),
            };
            let compared = match (g.in_snapshot, g.items, g.fields) {
                (false, ..) => String::new(),
                (true, 0, _) => "empty".to_string(),
                (true, 1, f) => format!("{f} field{}", plural(f)),
                (true, i, f) => format!("{i} items · {f} field{}", plural(f)),
            };
            Item::new().add("section", view::title_case(g.title)).add("result", result).add("compared", compared)
        }))
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}
