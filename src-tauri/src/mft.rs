//! Optional WizTree (NTFS MFT) turbo-scan integration.
//!
//! WizTree reads the NTFS Master File Table directly, which lets it enumerate every file on a
//! whole drive (name + size + modified time) in a few seconds — orders of magnitude faster than
//! walking the directory tree. This module shells out to a locally installed WizTree and parses
//! its CSV export. It is strictly optional: if WizTree is not installed, the built-in parallel
//! walker remains the (still fast) fallback.
//!
//! Note on last-used detection: the MFT gives us size and modified-time but not reliable
//! last-*access* time (Windows 10+ disables atime by default). The caller merges these rows with
//! UserAssist / Prefetch launch forensics for executables, exactly like the built-in scanner.

use std::path::{Path, PathBuf};

/// A single row parsed from WizTree's CSV export.
#[derive(Debug, Clone)]
pub struct WizTreeRow {
    pub path: String,
    pub size_bytes: u64,
    pub modified_at: i64,
    pub accessed_at: i64,
    pub created_at: i64,
}

/// Locate a WizTree binary on this machine, if one is installed.
pub fn detect_wiztree() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(pf) = std::env::var("ProgramFiles") {
        let base = PathBuf::from(pf).join("WizTree");
        candidates.push(base.join("WizTree64.exe"));
        candidates.push(base.join("WizTree.exe"));
    }
    if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
        let base = PathBuf::from(pf86).join("WizTree");
        candidates.push(base.join("WizTree64.exe"));
        candidates.push(base.join("WizTree.exe"));
    }
    // Portable copy dropped next to the app.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("WizTree64.exe"));
            candidates.push(dir.join("WizTree.exe"));
        }
    }

    candidates.into_iter().find(|p| p.exists())
}

/// Run a WizTree CSV export for `root` into `out_csv`. Returns an error string on any failure so
/// the caller can fall back to the built-in walker.
pub fn run_wiztree_export(wiztree: &Path, root: &str, out_csv: &Path) -> Result<(), String> {
    let out = std::process::Command::new(wiztree)
        .arg(root)
        .arg(format!("/export={}", out_csv.display()))
        .arg("/admin=1")
        .output()
        .map_err(|e| format!("Failed to launch WizTree: {}", e))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "WizTree export exited with {}: {}",
            out.status,
            stderr.trim()
        ));
    }
    if !out_csv.exists() {
        return Err("WizTree did not produce an export file".to_string());
    }
    Ok(())
}

/// Split a single CSV line into fields, honouring double-quoted fields (and escaped `""`).
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cur.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    fields.push(cur);
    fields
}

/// Parse an integer with optional surrounding whitespace and thousands separators.
fn parse_u64(s: &str) -> Option<u64> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    cleaned.parse::<u64>().ok()
}

/// Best-effort parse of WizTree's `Modified`/`Access`/`Created` columns into unix epoch seconds.
fn parse_timestamp(s: &str) -> i64 {
    let t = s.trim();
    if t.is_empty() {
        return 0;
    }
    // Plain unix epoch (seconds).
    if let Ok(epoch) = t.parse::<i64>() {
        return epoch;
    }
    // Common human-readable formats emitted by WizTree.
    const FORMATS: &[&str] = &[
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ];
    for fmt in FORMATS {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(t, fmt) {
            return dt.and_utc().timestamp();
        }
    }
    0
}

/// Parse a WizTree CSV export into rows, tolerating minor schema differences between versions.
pub fn parse_wiztree_csv(bytes: &[u8]) -> Vec<WizTreeRow> {
    let text = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = match lines.next() {
        Some(h) => h,
        None => return Vec::new(),
    };
    let columns = split_csv_line(header);

    let name_col = columns
        .iter()
        .position(|h| {
            let l = h.to_lowercase();
            l == "file name" || l == "name" || l.contains("file")
        })
        .or_else(|| columns.iter().position(|h| h.to_lowercase().contains("name")));
    let size_col = columns
        .iter()
        .position(|h| h.to_lowercase().contains("size"));
    let modified_col = columns
        .iter()
        .position(|h| h.to_lowercase().contains("modified"));
    let accessed_col = columns
        .iter()
        .position(|h| h.to_lowercase().contains("access"));
    let created_col = columns
        .iter()
        .position(|h| h.to_lowercase().contains("creat"));
    let attrs_col = columns
        .iter()
        .position(|h| h.to_lowercase().contains("attrib"));

    let name_col = match name_col {
        Some(c) => c,
        None => return Vec::new(), // schema not recognised → caller falls back
    };

    let mut rows = Vec::new();
    for line in lines {
        let fields = split_csv_line(line);
        if fields.len() <= name_col {
            continue;
        }
        let path = fields[name_col].trim().trim_matches('"').to_string();
        if path.is_empty() {
            continue;
        }
        let size_bytes = size_col.and_then(|c| fields.get(c)).and_then(|s| parse_u64(s)).unwrap_or(0);

        let is_dir = attrs_col
            .and_then(|c| fields.get(c))
            .map(|a| a.to_uppercase().contains('D'))
            .unwrap_or(false);

        // Directories are reported with the aggregate size of their children; skip them so we
        // don't double-count when the file rows are also present.
        if is_dir {
            continue;
        }

        let modified_at = modified_col
            .and_then(|c| fields.get(c))
            .map(|s| parse_timestamp(s))
            .unwrap_or(0);
        let accessed_at = accessed_col
            .and_then(|c| fields.get(c))
            .map(|s| parse_timestamp(s))
            .unwrap_or(0);
        let created_at = created_col
            .and_then(|c| fields.get(c))
            .map(|s| parse_timestamp(s))
            .unwrap_or(0);

        rows.push(WizTreeRow {
            path,
            size_bytes,
            modified_at,
            accessed_at,
            created_at,
        });
    }

    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_csv_line_quoted_comma() {
        let fields = split_csv_line("\"C:\\Program Files, Inc\\App.exe\",123,2023-01-01 00:00:00");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0], "C:\\Program Files, Inc\\App.exe");
        assert_eq!(fields[1], "123");
    }

    #[test]
    fn test_parse_timestamp_formats() {
        assert_eq!(parse_timestamp("1700000000"), 1_700_000_000);
        let dt = parse_timestamp("2023-01-01 00:00:00");
        assert!(dt > 0);
        assert_eq!(parse_timestamp(""), 0);
        assert_eq!(parse_timestamp("not-a-date"), 0);
    }

    #[test]
    fn test_parse_wiztree_csv_skips_folders() {
        let csv = "File Name,Size,Allocated,Modified,Attributes\n\
                    \"C:\\Stuff\",4096,4096,2023-01-01 00:00:00,D\n\
                    \"C:\\Stuff\\big.iso\",1073741824,1073741824,2022-05-01 00:00:00,A\n";
        let rows = parse_wiztree_csv(csv.as_bytes());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "C:\\Stuff\\big.iso");
        assert_eq!(rows[0].size_bytes, 1073741824);
    }
}
