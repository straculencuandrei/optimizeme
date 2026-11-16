use chrono::Utc;
use std::collections::HashMap;
use std::fs::{self, Metadata};
use std::path::Path;
use std::time::SystemTime;

#[derive(Clone, Copy)]
pub struct UserAssistEntry {
    /// Last execution time (unix epoch seconds).
    pub last_exec: i64,
    /// Number of times the binary was launched.
    pub run_count: u32,
}

pub struct ForensicSignals {
    /// Maps lowercase executable filename (e.g. "vlc.exe") -> last launch epoch seconds
    pub prefetch_times: HashMap<String, i64>,
    /// Maps lowercase file stem (without .lnk) -> recent shortcut modified epoch seconds
    pub recent_items: HashMap<String, i64>,
    /// Maps lowercase executable filename -> UserAssist launch count + last execution time.
    pub user_assist: HashMap<String, UserAssistEntry>,
}

pub fn system_time_to_epoch(t: std::io::Result<SystemTime>) -> Option<i64> {
    t.ok()
        .and_then(|st| st.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

pub fn now_epoch() -> i64 {
    Utc::now().timestamp()
}

/// ROT13 decode used by Windows UserAssist value names.
fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => ((c as u8) + 13) as char,
            'N'..='Z' | 'n'..='z' => ((c as u8) - 13) as char,
            _ => c,
        })
        .collect()
}

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to unix epoch seconds.
fn filetime_to_epoch(filetime: u64) -> i64 {
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let secs = filetime / 10_000_000;
    if secs > EPOCH_DIFF_SECS {
        (secs - EPOCH_DIFF_SECS) as i64
    } else {
        0
    }
}

/// Parse a UserAssist binary value. On Win8+ the record is 72 bytes with the FILETIME at
/// offset 60; on Win7 it is 16 bytes with the FILETIME at offset 8. Run count is always the
/// first little-endian u32.
fn parse_user_assist_value(data: &[u8]) -> Option<UserAssistEntry> {
    if data.len() < 16 {
        return None;
    }
    let run_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let filetime = if data.len() >= 72 {
        let off = 60;
        u64::from_le_bytes(data[off..off + 8].try_into().ok()?)
    } else {
        u64::from_le_bytes(data[8..16].try_into().ok()?)
    };
    let last_exec = filetime_to_epoch(filetime);
    if last_exec <= 0 {
        return None;
    }
    Some(UserAssistEntry {
        last_exec,
        run_count,
    })
}

/// Collect Windows UserAssist launch history (run counts + last execution time per executable).
#[cfg(target_os = "windows")]
fn collect_user_assist() -> HashMap<String, UserAssistEntry> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let mut out = HashMap::new();
    let base_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let base = match hkcu.open_subkey(base_path) {
        Ok(k) => k,
        Err(_) => return out,
    };

    for guid_key in base.enum_keys().flatten() {
        let guid = match base.open_subkey(&guid_key) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let count = match guid.open_subkey("Count") {
            Ok(k) => k,
            Err(_) => continue,
        };
        for (value_name, reg_value) in count.enum_values().flatten() {
            // Value name is ROT13-encoded full path to the launched binary.
            let decoded = rot13(&value_name);
            let file_name = Path::new(&decoded)
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if file_name.is_empty() {
                continue;
            }
            if let Some(entry) = parse_user_assist_value(&reg_value.bytes) {
                out.entry(file_name)
                    .and_modify(|cur: &mut UserAssistEntry| {
                        if entry.last_exec > cur.last_exec {
                            cur.last_exec = entry.last_exec;
                            cur.run_count = entry.run_count;
                        }
                    })
                    .or_insert(entry);
            }
        }
    }

    out
}

#[cfg(not(target_os = "windows"))]
fn collect_user_assist() -> HashMap<String, UserAssistEntry> {
    HashMap::new()
}

pub fn collect_os_forensic_signals() -> ForensicSignals {
    let mut prefetch_times = HashMap::new();
    let mut recent_items = HashMap::new();
    let user_assist = collect_user_assist();

    #[cfg(target_os = "windows")]
    {
        // 1. Windows Prefetch (if readable; gracefully skipped if elevation is required)
        let prefetch_dir = Path::new("C:\\Windows\\Prefetch");
        if let Ok(entries) = fs::read_dir(prefetch_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("pf"))
                    .unwrap_or(false)
                {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        // Prefetch format: EXENAME-HASH.pf
                        if let Some((exe_part, _hash)) = stem.rsplit_once('-') {
                            if let Ok(meta) = entry.metadata() {
                                let ts = system_time_to_epoch(meta.modified())
                                    .or_else(|| system_time_to_epoch(meta.accessed()))
                                    .unwrap_or(0);
                                if ts > 0 {
                                    let key = exe_part.to_lowercase();
                                    prefetch_times
                                        .entry(key)
                                        .and_modify(|cur| {
                                            if ts > *cur {
                                                *cur = ts;
                                            }
                                        })
                                        .or_insert(ts);
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Windows Recent Items (%APPDATA%\Microsoft\Windows\Recent)
        if let Some(roaming) = dirs::data_dir() {
            let recent_dir = roaming.join("Microsoft").join("Windows").join("Recent");
            if let Ok(entries) = fs::read_dir(&recent_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        let base = file_name
                            .strip_suffix(".lnk")
                            .or_else(|| file_name.strip_suffix(".LNK"))
                            .unwrap_or(file_name)
                            .to_lowercase();
                        if let Ok(meta) = entry.metadata() {
                            if let Some(ts) = system_time_to_epoch(meta.modified()) {
                                recent_items
                                    .entry(base)
                                    .and_modify(|cur| {
                                        if ts > *cur {
                                            *cur = ts;
                                        }
                                    })
                                    .or_insert(ts);
                            }
                        }
                    }
                }
            }
        }
    }

    ForensicSignals {
        prefetch_times,
        recent_items,
        user_assist,
    }
}

pub struct ExtractedTimestamps {
    pub created_at: i64,
    pub modified_at: i64,
    pub accessed_at: i64,
    pub last_used_at: i64,
    pub last_used_source: String,
    pub never_opened_since_creation: bool,
}

pub fn extract_timestamps(
    path: &Path,
    meta: &Metadata,
    signals: &ForensicSignals,
    now: i64,
) -> ExtractedTimestamps {
    let modified_at = system_time_to_epoch(meta.modified()).unwrap_or(now);
    let created_at = system_time_to_epoch(meta.created()).unwrap_or(modified_at);
    let accessed_at = system_time_to_epoch(meta.accessed()).unwrap_or(modified_at);

    let mut last_used_at = accessed_at.max(modified_at);
    let mut last_used_source = if accessed_at > modified_at + 60 {
        "File atime".to_string()
    } else {
        "Modified mtime".to_string()
    };

    if let Some(fname) = path.file_name().and_then(|f| f.to_str()) {
        let lower_name = fname.to_lowercase();
        if let Some(&pf_ts) = signals.prefetch_times.get(&lower_name) {
            if pf_ts > last_used_at {
                last_used_at = pf_ts;
                last_used_source = "Windows Prefetch".to_string();
            }
        }
        if let Some(&recent_ts) = signals.recent_items.get(&lower_name) {
            if recent_ts > last_used_at {
                last_used_at = recent_ts;
                last_used_source = "Windows Recent".to_string();
            }
        }
    }

    // Detect "never opened since download/creation":
    // On NTFS/APFS/ext4, freshly downloaded files have atime and mtime within ~2 minutes of ctime.
    let never_opened_since_creation = (accessed_at - created_at).abs() <= 180
        && (modified_at - created_at).abs() <= 180
        && (now - created_at) > 86_400
        && last_used_source != "Windows Prefetch"
        && last_used_source != "Windows Recent";

    ExtractedTimestamps {
        created_at,
        modified_at,
        accessed_at,
        last_used_at,
        last_used_source,
        never_opened_since_creation,
    }
}

pub fn format_duration_human(seconds: i64) -> String {
    if seconds < 3600 {
        let mins = (seconds / 60).max(1);
        return if mins == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", mins)
        };
    }
    if seconds < 86_400 {
        let hrs = seconds / 3600;
        return if hrs == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hrs)
        };
    }

    let total_days = seconds / 86_400;
    if total_days < 30 {
        return if total_days == 1 {
            "1 day ago".to_string()
        } else {
            format!("{} days ago", total_days)
        };
    }

    let years = total_days / 365;
    let rem_days = total_days % 365;
    let months = rem_days / 30;
    let days = rem_days % 30;

    if years > 0 {
        let y_str = if years == 1 { "1 year".to_string() } else { format!("{} years", years) };
        if months > 0 {
            let m_str = if months == 1 { "1 month".to_string() } else { format!("{} months", months) };
            format!("{}, {} ago", y_str, m_str)
        } else {
            format!("{} ago", y_str)
        }
    } else if months > 0 {
        let m_str = if months == 1 { "1 month".to_string() } else { format!("{} months", months) };
        if days >= 7 {
            let d_str = format!("{} days", days);
            format!("{}, {} ago", m_str, d_str)
        } else {
            format!("{} ago", m_str)
        }
    } else {
        format!("{} days ago", total_days)
    }
}

pub fn format_relative_last_used(
    ts: &ExtractedTimestamps,
    is_in_downloads: bool,
    now: i64,
) -> String {
    let delta = (now - ts.last_used_at).max(0);
    let human = format_duration_human(delta);
    if ts.never_opened_since_creation {
        if is_in_downloads {
            format!("Never opened since download {}", human)
        } else {
            format!("Never opened since created {}", human)
        }
    } else {
        format!("Last opened: {}", human)
    }
}

/// Space-Time Impact Score: combines file size (MB) and idle age (days^0.85)
/// so massive, long-forgotten files rise straight to the top.
pub fn compute_impact_score(size_bytes: u64, days_unused: i64) -> f64 {
    let size_mb = (size_bytes as f64) / (1024.0 * 1024.0);
    let age_weight = (days_unused.max(1) as f64).powf(0.85);
    (size_mb * age_weight * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_duration_formatting() {
        assert_eq!(format_duration_human(490 * 86_400), "1 year, 4 months ago");
        assert_eq!(format_duration_human(240 * 86_400), "8 months ago");
        assert_eq!(format_duration_human(15 * 86_400), "15 days ago");
    }

    #[test]
    fn test_never_opened_since_download_message() {
        let now = 1_700_000_000;
        let created = now - (240 * 86_400) - 10;
        let ts = ExtractedTimestamps {
            created_at: created,
            modified_at: created + 5,
            accessed_at: created + 10,
            last_used_at: created + 10,
            last_used_source: "Modified mtime".to_string(),
            never_opened_since_creation: true,
        };
        assert_eq!(
            format_relative_last_used(&ts, true, now),
            "Never opened since download 8 months ago"
        );
    }

    #[test]
    fn test_impact_score_prioritizes_large_stale_files() {
        let large_stale = compute_impact_score(2 * 1024 * 1024 * 1024, 400);
        let small_ancient = compute_impact_score(5 * 1024 * 1024, 1000);
        assert!(large_stale > small_ancient);
    }

    #[test]
    fn test_rot13_round_trip() {
        assert_eq!(rot13("uryyb"), "hello");
        assert_eq!(rot13("Hello.exe"), "Uryyb.rkr");
        assert_eq!(rot13("Uryyb.rkr"), "Hello.exe");
        assert_eq!(rot13("abcXYZ123"), "nopKLM123");
    }

    #[test]
    fn test_parse_user_assist_value_win8_layout() {
        let mut data = vec![0u8; 72];
        // run count = 7
        data[0..4].copy_from_slice(&7u32.to_le_bytes());
        // FILETIME at offset 60 = 10 seconds after the 1601 epoch (just a synthetic value)
        let ft = (11_644_473_600u64 + 1_600_000_000) * 10_000_000;
        data[60..68].copy_from_slice(&ft.to_le_bytes());
        let entry = parse_user_assist_value(&data).expect("should parse");
        assert_eq!(entry.run_count, 7);
        assert_eq!(entry.last_exec, 1_600_000_000);
    }

    #[test]
    fn test_parse_user_assist_value_win7_layout() {
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&3u32.to_le_bytes());
        let ft = (11_644_473_600u64 + 1_600_000_000) * 10_000_000;
        data[8..16].copy_from_slice(&ft.to_le_bytes());
        let entry = parse_user_assist_value(&data).expect("should parse");
        assert_eq!(entry.run_count, 3);
        assert_eq!(entry.last_exec, 1_600_000_000);
    }
}

#[cfg(target_os = "windows")]
pub fn query_recycle_bin() -> (u64, usize) {
    use windows_sys::Win32::UI::Shell::{SHQueryRecycleBinW, SHQUERYRBINFO};
    let mut info = SHQUERYRBINFO {
        cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
        i64Size: 0,
        i64NumItems: 0,
    };
    let hr = unsafe { SHQueryRecycleBinW(std::ptr::null(), &mut info) };
    if hr >= 0 {
        (info.i64Size.max(0) as u64, info.i64NumItems.max(0) as usize)
    } else {
        (0, 0)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn query_recycle_bin() -> (u64, usize) {
    let mut trash_dirs = Vec::new();
    if let Some(home) = dirs::home_dir() {
        #[cfg(target_os = "macos")]
        trash_dirs.push(home.join(".Trash"));
        #[cfg(target_os = "linux")]
        trash_dirs.push(home.join(".local/share/Trash/files"));
    }
    let mut total_bytes = 0u64;
    let mut total_count = 0usize;
    for dir in trash_dirs {
        if dir.exists() {
            for entry in walkdir::WalkDir::new(&dir).into_iter().flatten() {
                if entry.file_type().is_file() {
                    if let Ok(m) = entry.metadata() {
                        total_bytes += m.len();
                        total_count += 1;
                    }
                }
            }
        }
    }
    (total_bytes, total_count)
}

#[cfg(target_os = "windows")]
pub fn empty_recycle_bin() -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::{
        SHEmptyRecycleBinW, SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND,
    };
    let flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;
    let hr = unsafe { SHEmptyRecycleBinW(std::ptr::null_mut(), std::ptr::null(), flags) };
    // S_OK (0) or E_UNEXPECTED / empty bin sometimes returns -2147418113 when already empty
    if hr >= 0 || hr == -2147418113 {
        Ok(())
    } else {
        Err(format!("SHEmptyRecycleBinW failed with HRESULT {:#x}", hr))
    }
}

#[cfg(not(target_os = "windows"))]
pub fn empty_recycle_bin() -> Result<(), String> {
    if let Some(home) = dirs::home_dir() {
        #[cfg(target_os = "macos")]
        let dirs_to_clean = vec![home.join(".Trash")];
        #[cfg(target_os = "linux")]
        let dirs_to_clean = vec![
            home.join(".local/share/Trash/files"),
            home.join(".local/share/Trash/info"),
        ];
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let dirs_to_clean: Vec<std::path::PathBuf> = Vec::new();

        for dir in dirs_to_clean {
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        let _ = fs::remove_dir_all(&p);
                    } else {
                        let _ = fs::remove_file(&p);
                    }
                }
            }
        }
    }
    Ok(())
}
