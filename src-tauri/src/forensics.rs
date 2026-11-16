use crate::models::{
    AppCleanupResult, AppInstallStatus, AppUsageRecord, DefaultScanTarget, FileCategory, FileRecord,
    ForensicsBatchEvent, ForensicsScanResult, ScanProgressEvent, StorageBreakdownItem,
    WhitelistConfig,
};
use crate::os_metadata::{
    collect_os_forensic_signals, compute_impact_score, extract_timestamps, format_duration_human,
    format_relative_last_used, now_epoch,
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use walkdir::WalkDir;

pub fn get_default_scan_targets() -> Vec<DefaultScanTarget> {
    let mut targets = Vec::new();
    let candidates: Vec<(&str, &str, Option<PathBuf>)> = vec![
        ("downloads", "Downloads", dirs::download_dir()),
        ("desktop", "Desktop", dirs::desktop_dir()),
        ("documents", "Documents", dirs::document_dir()),
        ("videos", "Videos", dirs::video_dir()),
        ("pictures", "Pictures", dirs::picture_dir()),
        ("user_home", "User Home", dirs::home_dir()),
        ("appdata_local", "AppData Local", dirs::data_local_dir()),
    ];

    for (id, label, path_opt) in candidates {
        if let Some(p) = path_opt {
            targets.push(DefaultScanTarget {
                id: id.to_string(),
                label: label.to_string(),
                path: p.to_string_lossy().to_string(),
                exists: p.exists(),
            });
        }
    }

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
        const DRIVE_FIXED: u32 = 3;

        let pf = std::env::var("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("C:\\Program Files"));
        targets.push(DefaultScanTarget {
            id: "program_files".to_string(),
            label: "Program Files".to_string(),
            path: pf.to_string_lossy().to_string(),
            exists: pf.exists(),
        });

        if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
            let p = PathBuf::from(pf86);
            targets.push(DefaultScanTarget {
                id: "program_files_x86".to_string(),
                label: "Program Files (x86)".to_string(),
                path: p.to_string_lossy().to_string(),
                exists: p.exists(),
            });
        }

        if let Ok(pd) = std::env::var("ProgramData") {
            let p = PathBuf::from(pd);
            targets.push(DefaultScanTarget {
                id: "program_data".to_string(),
                label: "ProgramData".to_string(),
                path: p.to_string_lossy().to_string(),
                exists: p.exists(),
            });
        }

        if let Some(roaming) = dirs::data_dir() {
            targets.push(DefaultScanTarget {
                id: "appdata_roaming".to_string(),
                label: "AppData Roaming".to_string(),
                path: roaming.to_string_lossy().to_string(),
                exists: roaming.exists(),
            });
        }

        if let Some(home) = dirs::home_dir() {
            let public = home
                .parent()
                .map(|p| p.join("Public"))
                .unwrap_or_default();
            if public.exists() {
                targets.push(DefaultScanTarget {
                    id: "public".to_string(),
                    label: "Public".to_string(),
                    path: public.to_string_lossy().to_string(),
                    exists: true,
                });
            }
        }

        for letter in b'C'..=b'Z' {
            let root = format!("{}:\\", letter as char);
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            let dtype = unsafe { GetDriveTypeW(wide.as_ptr()) };
            if dtype == DRIVE_FIXED && Path::new(&root).exists() {
                targets.push(DefaultScanTarget {
                    id: format!("drive_{}", (letter as char).to_ascii_lowercase()),
                    label: format!("Drive ({}:)", letter as char),
                    path: root,
                    exists: true,
                });
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let apps = PathBuf::from("/Applications");
        targets.push(DefaultScanTarget {
            id: "applications".to_string(),
            label: "Applications".to_string(),
            path: apps.to_string_lossy().to_string(),
            exists: apps.exists(),
        });
    }

    targets
}

pub fn classify_extension(ext: &str) -> FileCategory {
    match ext.to_lowercase().as_str() {
        "exe" | "msi" | "msix" | "dmg" | "pkg" | "deb" | "rpm" | "appimage" | "bat" | "cmd" => {
            FileCategory::Installer
        }
        "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "zst" | "tgz" | "cab" => {
            FileCategory::Archive
        }
        "mp4" | "mkv" | "mov" | "avi" | "wmv" | "flv" | "webm" | "m4v" | "mp3" | "wav"
        | "flac" | "aac" | "ogg" | "raw" | "psd" | "ai" => FileCategory::Media,
        "iso" | "img" | "vhd" | "vhdx" | "vmdk" | "ova" | "qcow2" | "bin" | "cue" => {
            FileCategory::DiskImage
        }
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "csv" | "txt" | "md"
        | "rtf" | "odt" | "epub" => FileCategory::Document,
        "app" | "dll" | "so" | "dylib" => FileCategory::Application,
        "rs" | "ts" | "tsx" | "js" | "jsx" | "py" | "go" | "cpp" | "c" | "h" | "java"
        | "json" | "yaml" | "yml" | "toml" | "sql" | "db" | "sqlite" => FileCategory::Code,
        _ => FileCategory::Other,
    }
}

fn category_display_and_color(cat: &FileCategory) -> (&'static str, &'static str) {
    match cat {
        FileCategory::Installer => ("Installers", "#F59E0B"),
        FileCategory::Archive => ("Archives", "#8B5CF6"),
        FileCategory::Media => ("Media & Video", "#06B6D4"),
        FileCategory::DiskImage => ("Disk Images", "#EF4444"),
        FileCategory::Document => ("Documents", "#3B82F6"),
        FileCategory::Application => ("Apps & Binaries", "#10B981"),
        FileCategory::Code => ("Code & Data", "#6366F1"),
        FileCategory::Other => ("Other Files", "#64748B"),
    }
}

fn stable_id(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let res = hasher.finalize();
    format!("{:x}", res)[..16].to_string()
}

fn is_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

fn normalize_path_key(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    #[cfg(target_os = "windows")]
    let norm = s.replace('/', "\\").to_lowercase();
    #[cfg(not(target_os = "windows"))]
    let norm = s;
    if norm.len() > 3 && (norm.ends_with('\\') || norm.ends_with('/')) {
        norm[..norm.len() - 1].to_string()
    } else {
        norm
    }
}

/// Collapses overlapping roots (e.g. if both `C:\` and `C:\Users\x\Downloads` are selected,
/// only `C:\` is walked so files are never scanned or emitted twice).
fn deduplicate_roots(target_paths: &[String]) -> Vec<PathBuf> {
    let mut normalized: Vec<(String, PathBuf)> = target_paths
        .iter()
        .map(|s| PathBuf::from(s))
        .filter(|p| p.exists())
        .map(|p| (normalize_path_key(&p), p))
        .collect();

    normalized.sort_by(|a, b| a.0.len().cmp(&b.0.len()));

    let mut kept: Vec<(String, PathBuf)> = Vec::new();
    for (key, pb) in normalized {
        let covered = kept.iter().any(|(parent_key, _)| {
            if key == *parent_key {
                return true;
            }
            let sep_match = parent_key.ends_with('\\') || parent_key.ends_with('/');
            if sep_match {
                key.starts_with(parent_key)
            } else {
                key.starts_with(&format!("{}\\", parent_key))
                    || key.starts_with(&format!("{}/", parent_key))
            }
        });
        if !covered {
            kept.push((key, pb));
        }
    }
    kept.into_iter().map(|(_, pb)| pb).collect()
}

fn should_skip_dir(path: &Path, whitelist: &WhitelistConfig) -> bool {
    let lower = normalize_path_key(path);
    for ignored in &whitelist.ignored_folders {
        let ig = normalize_path_key(Path::new(ignored));
        if lower == ig
            || lower.starts_with(&format!("{}\\", ig))
            || lower.starts_with(&format!("{}/", ig))
        {
            return true;
        }
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let ln = name.to_lowercase();
        if ln == "node_modules"
            || ln == ".git"
            || ln == "$recycle.bin"
            || ln == "system volume information"
            || ln == "winsxs"
            || ln == "recovery"
        {
            return true;
        }
    }
    false
}

struct ParallelScanCtx<'a> {
    app: &'a AppHandle,
    scan_id: &'a str,
    now: i64,
    min_size_bytes: u64,
    signals: &'a crate::os_metadata::ForensicSignals,
    whitelist: &'a WhitelistConfig,
    ignored_files_lower: &'a HashSet<String>,
    cancel_flag: &'a AtomicBool,
    scanned_files: &'a AtomicUsize,
    scanned_bytes: &'a AtomicU64,
    last_emit: &'a Mutex<Instant>,
    batch_emitter: &'a Mutex<Vec<FileRecord>>,
    results: &'a Mutex<Vec<FileRecord>>,
}

fn build_file_record(
    path: &Path,
    meta: &fs::Metadata,
    ctx: &ParallelScanCtx<'_>,
) -> FileRecord {
    let size_bytes = meta.len();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let path_str = path.to_string_lossy().to_string();
    let parent_dir = path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let category = classify_extension(&extension);
    let ts = extract_timestamps(path, meta, ctx.signals, ctx.now);
    let days_unused = ((ctx.now - ts.last_used_at).max(0)) / 86_400;

    let lower_path = path_str.to_lowercase();
    let is_in_downloads =
        lower_path.contains("\\downloads\\") || lower_path.contains("/downloads/");
    let relative_last_used = format_relative_last_used(&ts, is_in_downloads, ctx.now);
    let impact_score = compute_impact_score(size_bytes, days_unused);

    let mut tags = Vec::new();
    if is_in_downloads
        && matches!(
            category,
            FileCategory::Installer | FileCategory::Archive | FileCategory::DiskImage
        )
        && (ts.never_opened_since_creation || days_unused >= 14)
    {
        tags.push("Download & Forget".to_string());
    }
    if ts.never_opened_since_creation && days_unused >= 30 {
        tags.push("Never Opened".to_string());
    }
    if size_bytes >= 500 * 1024 * 1024 && days_unused >= 180 {
        tags.push("Stale Giant".to_string());
    }
    if matches!(category, FileCategory::Installer) && days_unused >= 30 {
        tags.push("Forgotten Installer".to_string());
    }
    if matches!(category, FileCategory::DiskImage) && days_unused >= 30 {
        tags.push("Orphaned ISO".to_string());
    }

    FileRecord {
        id: stable_id(&normalize_path_key(path)),
        name,
        path: path_str,
        parent_dir,
        extension,
        category,
        size_bytes,
        created_at: ts.created_at,
        modified_at: ts.modified_at,
        accessed_at: ts.accessed_at,
        last_used_at: ts.last_used_at,
        last_used_source: ts.last_used_source,
        days_unused,
        relative_last_used,
        impact_score,
        tags,
        is_ignored: false,
    }
}

fn scan_dir_recursive(dir: &Path, ctx: &ParallelScanCtx<'_>) {
    if ctx.cancel_flag.load(Ordering::Relaxed) {
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };

    let mut subdirs: Vec<PathBuf> = Vec::new();
    let mut local_records: Vec<FileRecord> = Vec::new();

    for entry in entries.flatten() {
        if ctx.cancel_flag.load(Ordering::Relaxed) {
            return;
        }
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if is_reparse_or_symlink(&meta) {
            continue;
        }

        if meta.is_dir() {
            if !should_skip_dir(&path, ctx.whitelist) {
                subdirs.push(path);
            }
        } else if meta.is_file() {
            if ctx.ignored_files_lower.contains(&normalize_path_key(&path)) {
                continue;
            }
            let size_bytes = meta.len();
            ctx.scanned_bytes.fetch_add(size_bytes, Ordering::Relaxed);
            let total_count = ctx.scanned_files.fetch_add(1, Ordering::Relaxed) + 1;

            if total_count % 350 == 0 {
                if let Ok(mut last) = ctx.last_emit.try_lock() {
                    if last.elapsed() >= Duration::from_millis(120) {
                        *last = Instant::now();
                        let _ = ctx.app.emit(
                            "scan-progress",
                            ScanProgressEvent {
                                scan_id: ctx.scan_id.to_string(),
                                phase: "scanning".to_string(),
                                scanned_files: total_count,
                                scanned_bytes: ctx.scanned_bytes.load(Ordering::Relaxed),
                                current_path: path.to_string_lossy().to_string(),
                                completed: false,
                            },
                        );
                    }
                }
            }

            if size_bytes >= ctx.min_size_bytes {
                let rec = build_file_record(&path, &meta, ctx);
                local_records.push(rec);
            }
        }
    }

    if !local_records.is_empty() {
        if let Ok(mut buf) = ctx.batch_emitter.try_lock() {
            buf.extend(local_records.iter().take(40).cloned());
            if buf.len() >= 100 {
                let chunk = std::mem::take(&mut *buf);
                let _ = ctx.app.emit(
                    "forensics-batch",
                    ForensicsBatchEvent {
                        scan_id: ctx.scan_id.to_string(),
                        files: chunk,
                    },
                );
            }
        }
        if let Ok(mut all) = ctx.results.lock() {
            all.extend(local_records);
        }
    }

    if !subdirs.is_empty() {
        subdirs.par_iter().for_each(|sub| {
            scan_dir_recursive(sub, ctx);
        });
    }
}

pub fn run_forensics_scan(
    app: &AppHandle,
    scan_id: String,
    target_paths: Vec<String>,
    min_size_bytes: u64,
    whitelist: WhitelistConfig,
    cancel_flag: Arc<AtomicBool>,
) -> ForensicsScanResult {
    let start = Instant::now();
    let now = now_epoch();
    let signals = collect_os_forensic_signals();

    let scanned_files = AtomicUsize::new(0);
    let scanned_bytes = AtomicU64::new(0);
    let last_emit = Mutex::new(Instant::now());
    let batch_emitter = Mutex::new(Vec::<FileRecord>::with_capacity(120));
    let results = Mutex::new(Vec::<FileRecord>::with_capacity(4096));

    let ignored_files_lower: HashSet<String> = whitelist
        .ignored_files
        .iter()
        .map(|s| normalize_path_key(Path::new(s)))
        .collect();

    let roots = deduplicate_roots(&target_paths);

    let ctx = ParallelScanCtx {
        app,
        scan_id: &scan_id,
        now,
        min_size_bytes,
        signals: &signals,
        whitelist: &whitelist,
        ignored_files_lower: &ignored_files_lower,
        cancel_flag: &cancel_flag,
        scanned_files: &scanned_files,
        scanned_bytes: &scanned_bytes,
        last_emit: &last_emit,
        batch_emitter: &batch_emitter,
        results: &results,
    };

    roots.par_iter().for_each(|root| {
        scan_dir_recursive(root, &ctx);
    });

    // Flush any remaining streamed batch
    if let Ok(mut buf) = batch_emitter.lock() {
        if !buf.is_empty() {
            let chunk = std::mem::take(&mut *buf);
            let _ = app.emit(
                "forensics-batch",
                ForensicsBatchEvent {
                    scan_id: scan_id.clone(),
                    files: chunk,
                },
            );
        }
    }

    // Deduplicate records defensively by id
    let raw_records = results.into_inner().unwrap_or_default();
    let mut seen_ids = HashSet::with_capacity(raw_records.len());
    let mut records: Vec<FileRecord> = Vec::with_capacity(raw_records.len());
    for rec in raw_records {
        if seen_ids.insert(rec.id.clone()) {
            records.push(rec);
        }
    }

    let mut breakdown_map: HashMap<&'static str, (u64, usize, &'static str)> = HashMap::new();
    let mut reclaimable_bytes = 0u64;
    let mut stale_files_count = 0usize;

    for r in &records {
        let (label, color) = category_display_and_color(&r.category);
        breakdown_map
            .entry(label)
            .and_modify(|e| {
                e.0 += r.size_bytes;
                e.1 += 1;
            })
            .or_insert((r.size_bytes, 1, color));
        if r.days_unused >= 30 {
            reclaimable_bytes += r.size_bytes;
            stale_files_count += 1;
        }
    }

    let mut breakdown: Vec<StorageBreakdownItem> = breakdown_map
        .into_iter()
        .map(|(cat, (size_bytes, file_count, color))| StorageBreakdownItem {
            category: cat.to_string(),
            size_bytes,
            file_count,
            color: color.to_string(),
        })
        .collect();
    breakdown.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

    // No artificial record cap: every matching file is returned so the biggest / oldest
    // items can never be hidden by an internal limit. Sorting by impact (size-weighted)
    // keeps huge, long-forgotten files at the top, and the UI can re-sort by raw size.
    let mut sorted_records = records;
    sorted_records.sort_by(|a, b| {
        b.impact_score
            .partial_cmp(&a.impact_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let total_indexed = scanned_files.load(Ordering::Relaxed);
    let total_bytes = scanned_bytes.load(Ordering::Relaxed);
    let _ = app.emit(
        "scan-progress",
        ScanProgressEvent {
            scan_id: scan_id.clone(),
            phase: "complete".to_string(),
            scanned_files: total_indexed,
            scanned_bytes: total_bytes,
            current_path: String::new(),
            completed: true,
        },
    );

    ForensicsScanResult {
        scan_id,
        total_files_scanned: total_indexed,
        total_bytes_scanned: total_bytes,
        stale_files_count,
        reclaimable_bytes,
        duration_ms: start.elapsed().as_millis() as u64,
        breakdown,
        files: sorted_records,
    }
}

#[cfg(target_os = "windows")]
fn expand_env_vars(s: &str) -> String {
    let mut out = s.to_string();
    for var in [
        "SystemDrive",
        "SystemRoot",
        "WinDir",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
        "AppData",
        "LocalAppData",
        "UserProfile",
    ] {
        let key = format!("%{}%", var);
        if out.contains(&key) {
            if let Ok(val) = std::env::var(var) {
                out = out.replace(&key, &val);
            }
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn clean_path(raw: String) -> String {
    expand_env_vars(raw.trim().trim_matches('"'))
}

#[cfg(target_os = "windows")]
fn clean_display_icon(raw: &str) -> Option<String> {
    let cleaned = raw
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"');
    if cleaned.is_empty() {
        return None;
    }
    let p = PathBuf::from(expand_env_vars(cleaned));
    if p.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("exe"))
        .unwrap_or(false)
    {
        Some(p.to_string_lossy().to_string())
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn is_generic_root(path: &Path) -> bool {
    let key = normalize_path_key(path);
    let trimmed = key.trim_end_matches('\\');
    // Drive root, e.g. "c:" (normalized form of "C:\").
    if trimmed.len() == 2 && trimmed.as_bytes().get(1) == Some(&b':') {
        return true;
    }
    if trimmed.ends_with(":\\") {
        return true;
    }
    // Shared roots that must never be treated as a single app's install directory.
    if let Some((_drive, leaf)) = trimmed.split_once(":\\") {
        return matches!(
            leaf,
            "program files"
                | "program files (x86)"
                | "programdata"
                | "windows"
                | "users"
                | "recovery"
                | "system volume information"
        );
    }
    false
}

/// Best-effort extraction of an executable path from an UninstallString such as
/// `"C:\App\unins000.exe" /S` or `C:\App\uninstall.exe`.
#[cfg(target_os = "windows")]
fn exe_from_command(cmd: &str) -> Option<PathBuf> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_lowercase();
    let idx = lower.find(".exe")?;
    let end = idx + 4;
    let prefix = &trimmed[..end];
    let start = prefix.rfind('"').map(|i| i + 1).unwrap_or(0);
    let candidate = prefix[start..].trim().trim_matches('"');
    if candidate.is_empty() {
        return None;
    }
    let p = PathBuf::from(expand_env_vars(candidate));
    if p.exists()
        && p.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("exe"))
            .unwrap_or(false)
    {
        Some(p)
    } else {
        None
    }
}

#[cfg(target_os = "windows")]
fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var(var)
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

#[cfg(target_os = "windows")]
fn install_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(pf) = env_dir("ProgramFiles") {
        roots.push(pf);
    }
    if let Some(pf86) = env_dir("ProgramFiles(x86)") {
        roots.push(pf86);
    }
    if let Some(local) = dirs::data_local_dir() {
        let programs = local.join("Programs");
        if programs.exists() {
            roots.push(programs);
        }
    }
    roots
}

#[cfg(target_os = "windows")]
fn is_exe(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("exe"))
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn is_helper_exe(p: &Path) -> bool {
    let stem = p
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    stem.contains("unins")
        || stem.contains("setup")
        || stem.contains("update")
        || stem.contains("crash")
        || stem.contains("helper")
        || stem.contains("redist")
        || stem.contains("install")
}

#[cfg(target_os = "windows")]
fn collect_executables(dir: &Path, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if depth == 0 {
        return out;
    }
    if let Ok(rd) = fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                out.extend(collect_executables(&p, depth - 1));
            } else if p.is_file() && is_exe(&p) && !is_helper_exe(&p) {
                out.push(p);
            }
        }
    }
    out
}

#[cfg(target_os = "windows")]
fn pick_primary_exe(candidates: &[PathBuf], dir_name: &str) -> Option<PathBuf> {
    if candidates.is_empty() {
        return None;
    }
    let dn = dir_name.to_lowercase();
    if let Some(p) = candidates.iter().find(|p| {
        p.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case(&dn))
            .unwrap_or(false)
    }) {
        return Some(p.clone());
    }
    candidates
        .iter()
        .max_by_key(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
        .cloned()
}

#[cfg(target_os = "windows")]
fn dir_size(dir: &Path) -> u64 {
    let mut sum = 0u64;
    for entry in WalkDir::new(dir).follow_links(false).into_iter().flatten() {
        if entry.file_type().is_file() {
            sum += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    sum
}

#[cfg(target_os = "windows")]
fn last_launch_from_exe(
    exe: &Path,
    signals: &crate::os_metadata::ForensicSignals,
) -> (Option<i64>, String, Option<u32>) {
    let fname = exe
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_lowercase());
    let mut best: Option<i64> = None;
    let mut source = "No launch history".to_string();
    let mut run_count: Option<u32> = None;

    if let Some(ref f) = fname {
        if let Some(ua) = signals.user_assist.get(f) {
            best = Some(ua.last_exec);
            source = "UserAssist registry".to_string();
            run_count = Some(ua.run_count);
        }
        if let Some(&pf) = signals.prefetch_times.get(f) {
            if best.map(|b| pf > b).unwrap_or(true) {
                best = Some(pf);
                source = "Windows Prefetch".to_string();
            }
        }
    }

    (best, source, run_count)
}

#[cfg(target_os = "windows")]
struct BuildTask {
    name: String,
    publisher: String,
    dir: Option<PathBuf>,
    primary_exe: Option<PathBuf>,
    estimated_size_kb: u64,
    status: AppInstallStatus,
    exists: bool,
    registry_path: Option<String>,
    uninstall_string: Option<String>,
}

#[cfg(target_os = "windows")]
fn build_app_record(
    task: &BuildTask,
    signals: &crate::os_metadata::ForensicSignals,
    now: i64,
) -> AppUsageRecord {
    let size = match &task.dir {
        Some(dir) => dir_size(dir),
        None => task.estimated_size_kb * 1024,
    };

    let (last_launched_at, source, launch_count) = match &task.primary_exe {
        Some(exe) => last_launch_from_exe(exe, signals),
        None => (None, "No launch history".to_string(), None),
    };

    let days_unused = match last_launched_at {
        Some(t) => ((now - t).max(0)) / 86_400,
        // No recorded launch → treat as long-unused for sorting/bloat detection.
        None => 3650,
    };
    let relative_last_used = match last_launched_at {
        Some(t) => format!(
            "Last launched: {}",
            format_duration_human((now - t).max(0))
        ),
        None => "No launch history recorded".to_string(),
    };
    let is_bloated_unused = size >= 150 * 1024 * 1024 && days_unused >= 90;

    let key_material = task
        .registry_path
        .clone()
        .or_else(|| task.dir.as_ref().map(|d| d.to_string_lossy().to_string()))
        .unwrap_or_else(|| task.name.clone());

    AppUsageRecord {
        id: stable_id(&format!("app:{}:{}", task.name, key_material)),
        name: task.name.clone(),
        publisher: task.publisher.clone(),
        install_location: task
            .dir
            .as_ref()
            .map(|d| d.to_string_lossy().to_string())
            .unwrap_or_default(),
        executable_path: task
            .primary_exe
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        estimated_size_bytes: size,
        last_launched_at,
        last_launched_source: source,
        days_unused,
        relative_last_used,
        is_bloated_unused,
        exists: task.exists,
        status: task.status.clone(),
        registry_path: task.registry_path.clone(),
        uninstall_string: task.uninstall_string.clone(),
        launch_count,
    }
}

pub fn scan_installed_apps() -> Vec<AppUsageRecord> {
    let now = now_epoch();
    let signals = collect_os_forensic_signals();

    #[cfg(target_os = "windows")]
    {
        return scan_installed_apps_windows(&signals, now);
    }

    #[cfg(not(target_os = "windows"))]
    {
        return scan_installed_apps_unix(&signals, now);
    }
}

#[cfg(target_os = "windows")]
fn scan_installed_apps_windows(
    signals: &crate::os_metadata::ForensicSignals,
    now: i64,
) -> Vec<AppUsageRecord> {
    use winreg::enums::*;
    use winreg::RegKey;

    struct RegApp {
        name: String,
        publisher: String,
        install_location: String,
        display_icon_exe: Option<String>,
        uninstall_string: String,
        estimated_size_kb: u64,
        registry_path: String,
    }

    let roots = [
        (
            "HKEY_LOCAL_MACHINE",
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ),
        (
            "HKEY_LOCAL_MACHINE",
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ),
        (
            "HKEY_CURRENT_USER",
            HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        ),
    ];

    // ---- 1. Read uninstall registry entries (for name/publisher/version metadata + orphan detection) ----
    let mut reg_apps: Vec<RegApp> = Vec::new();
    for (root_label, hkey_root, subkey) in roots {
        let root = RegKey::predef(hkey_root);
        if let Ok(uninstall_key) = root.open_subkey(subkey) {
            for key_name in uninstall_key.enum_keys().flatten() {
                if let Ok(app_key) = uninstall_key.open_subkey(&key_name) {
                    let system_comp: u32 = app_key.get_value("SystemComponent").unwrap_or(0);
                    if system_comp == 1 {
                        continue;
                    }
                    let name: String = match app_key.get_value("DisplayName") {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let trimmed = name.trim().to_string();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let publisher: String = app_key
                        .get_value("Publisher")
                        .unwrap_or_else(|_| "Unknown Publisher".to_string());
                    let raw_location: String =
                        clean_path(app_key.get_value("InstallLocation").unwrap_or_default());
                    // Some installers write a shared root (e.g. "C:\Program Files\") as their
                    // InstallLocation. Treat those as "no specific location" so we never measure
                    // or reveal the whole Program Files tree for a single app.
                    let install_location = if raw_location.is_empty()
                        || is_generic_root(Path::new(&raw_location))
                    {
                        String::new()
                    } else {
                        raw_location
                    };
                    let display_icon_raw: String = app_key.get_value("DisplayIcon").unwrap_or_default();
                    let display_icon_exe = clean_display_icon(&display_icon_raw);
                    let uninstall_string: String =
                        app_key.get_value("UninstallString").unwrap_or_default();
                    let estimated_size_kb: u32 = app_key.get_value("EstimatedSize").unwrap_or(0);

                    reg_apps.push(RegApp {
                        name: trimmed,
                        publisher,
                        install_location,
                        display_icon_exe,
                        uninstall_string,
                        estimated_size_kb: estimated_size_kb as u64,
                        registry_path: format!("{}\\{}", root_label, subkey),
                    });
                }
            }
        }
    }

    // ---- 2. Classify each registry entry against the actual filesystem ----
    let mut tasks: Vec<BuildTask> = Vec::new();
    let mut known_dirs: HashSet<String> = HashSet::new();
    let mut seen: HashSet<String> = HashSet::new();

    for reg in reg_apps {
        enum Verdict {
            Alive {
                dir: Option<PathBuf>,
                exe: Option<PathBuf>,
            },
            Orphaned,
            Unknown,
        }

        let loc = if reg.install_location.is_empty() {
            None
        } else {
            Some(PathBuf::from(&reg.install_location))
        };
        let icon = reg.display_icon_exe.as_ref().map(PathBuf::from);
        let unins_exe = exe_from_command(&reg.uninstall_string);

        // Only accept a *specific* folder as the app's install directory; shared roots such as
        // "C:\Program Files" are rejected so we never measure or reveal the whole tree.
        let specific_dir = |p: &Path| -> Option<PathBuf> {
            p.parent()
                .map(|d| d.to_path_buf())
                .filter(|d| !is_generic_root(d))
        };

        let verdict = if let Some(loc) = loc.as_ref().filter(|p| p.exists()) {
            // Prefer the app's own executable (DisplayIcon / UninstallString) so "Reveal" and
            // launch-history matching target the real binary, even when InstallLocation is a
            // shared root such as a Steam library.
            let exe = icon
                .as_ref()
                .filter(|p| p.exists())
                .cloned()
                .or_else(|| unins_exe.as_ref().filter(|p| p.exists()).cloned());
            Verdict::Alive {
                dir: Some(loc.clone()),
                exe,
            }
        } else if let Some(icon) = icon.as_ref().filter(|p| p.exists()) {
            Verdict::Alive {
                dir: specific_dir(icon),
                exe: Some(icon.clone()),
            }
        } else if let Some(exe) = unins_exe.as_ref().filter(|p| p.exists()) {
            Verdict::Alive {
                dir: specific_dir(exe),
                exe: Some(exe.clone()),
            }
        } else if loc.is_some() || icon.is_some() || unins_exe.is_some() {
            // Every path the registry referenced is gone → already uninstalled.
            Verdict::Orphaned
        } else {
            Verdict::Unknown
        };

        match verdict {
            Verdict::Alive { dir, exe } => {
                let dedup_key = match &dir {
                    Some(d) => normalize_path_key(d),
                    None => format!("reg:{}", reg.registry_path),
                };
                if !seen.insert(dedup_key.clone()) {
                    continue;
                }
                if dir.is_some() {
                    known_dirs.insert(dedup_key);
                }

                let dir_name = dir
                    .as_ref()
                    .and_then(|d| d.file_name())
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let exes = dir
                    .as_ref()
                    .map(|d| collect_executables(d, 2))
                    .unwrap_or_default();
                let primary = exe.or_else(|| pick_primary_exe(&exes, &dir_name));

                let status = match &dir {
                    Some(_) if primary.is_some() => AppInstallStatus::Installed,
                    Some(_) => AppInstallStatus::Broken,
                    None => AppInstallStatus::Unknown,
                };

                tasks.push(BuildTask {
                    name: reg.name,
                    publisher: reg.publisher,
                    dir,
                    primary_exe: primary,
                    estimated_size_kb: reg.estimated_size_kb,
                    status,
                    exists: true,
                    registry_path: Some(reg.registry_path),
                    uninstall_string: Some(reg.uninstall_string),
                });
            }
            Verdict::Orphaned => {
                let dedup_key = format!("reg:{}", reg.registry_path);
                if !seen.insert(dedup_key) {
                    continue;
                }
                tasks.push(BuildTask {
                    name: reg.name,
                    publisher: reg.publisher,
                    dir: None,
                    primary_exe: None,
                    estimated_size_kb: reg.estimated_size_kb,
                    status: AppInstallStatus::Orphaned,
                    exists: false,
                    registry_path: Some(reg.registry_path),
                    uninstall_string: Some(reg.uninstall_string),
                });
            }
            Verdict::Unknown => {
                let dedup_key = format!("reg:{}", reg.registry_path);
                if !seen.insert(dedup_key) {
                    continue;
                }
                tasks.push(BuildTask {
                    name: reg.name,
                    publisher: reg.publisher,
                    dir: None,
                    primary_exe: None,
                    estimated_size_kb: reg.estimated_size_kb,
                    status: AppInstallStatus::Unknown,
                    exists: false,
                    registry_path: Some(reg.registry_path),
                    uninstall_string: Some(reg.uninstall_string),
                });
            }
        }
    }

    // ---- 3. Discover real per-user / portable installs the registry does not know about ----
    for root in install_roots() {
        if let Ok(rd) = fs::read_dir(&root) {
            for entry in rd.flatten() {
                let dir = entry.path();
                if !dir.is_dir() {
                    continue;
                }
                let norm = normalize_path_key(&dir);
                if known_dirs.contains(&norm) {
                    continue;
                }
                if !seen.insert(norm.clone()) {
                    continue;
                }
                let exes = collect_executables(&dir, 2);
                if exes.is_empty() {
                    continue;
                }
                let name = dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let primary = pick_primary_exe(&exes, &name);
                tasks.push(BuildTask {
                    name: name.clone(),
                    publisher: "Portable / Unregistered".to_string(),
                    dir: Some(dir),
                    primary_exe: primary,
                    estimated_size_kb: 0,
                    status: AppInstallStatus::Installed,
                    exists: true,
                    registry_path: None,
                    uninstall_string: None,
                });
            }
        }
    }

    let mut apps: Vec<AppUsageRecord> = tasks
        .into_par_iter()
        .map(|t| build_app_record(&t, signals, now))
        .collect();

    // Sort by bloated/unused impact: size * days_unused^0.7
    apps.sort_by(|a, b| {
        let score_a = (a.estimated_size_bytes as f64) * ((a.days_unused.max(1)) as f64).powf(0.7);
        let score_b = (b.estimated_size_bytes as f64) * ((b.days_unused.max(1)) as f64).powf(0.7);
        score_b
            .partial_cmp(&score_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    apps
}

#[cfg(not(target_os = "windows"))]
fn scan_installed_apps_unix(
    _signals: &crate::os_metadata::ForensicSignals,
    now: i64,
) -> Vec<AppUsageRecord> {
    let mut apps: Vec<AppUsageRecord> = Vec::new();
    let mut seen_names = HashSet::new();
    let mut app_dirs = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        app_dirs.push(home.join("Applications"));
    }
    for dir in app_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if !seen_names.insert(name.to_lowercase()) {
                    continue;
                }
                let meta = fs::metadata(&p).ok();
                let atime = meta
                    .as_ref()
                    .and_then(|m| crate::os_metadata::system_time_to_epoch(m.accessed()));
                let mtime = meta
                    .as_ref()
                    .and_then(|m| crate::os_metadata::system_time_to_epoch(m.modified()));
                let last_launched_at = atime.or(mtime);
                let days_unused = last_launched_at
                    .map(|t| ((now - t).max(0)) / 86_400)
                    .unwrap_or(180);
                let size = dir_size(&p);
                let relative_last_used = last_launched_at
                    .map(|t| {
                        format!(
                            "Last launched: {}",
                            format_duration_human((now - t).max(0))
                        )
                    })
                    .unwrap_or_else(|| "Unknown".to_string());
                apps.push(AppUsageRecord {
                    id: stable_id(&p.to_string_lossy()),
                    name,
                    publisher: "Installed App".to_string(),
                    install_location: p.to_string_lossy().to_string(),
                    executable_path: Some(p.to_string_lossy().to_string()),
                    estimated_size_bytes: size,
                    last_launched_at,
                    last_launched_source: "Bundle atime".to_string(),
                    days_unused,
                    relative_last_used,
                    is_bloated_unused: size >= 150 * 1024 * 1024 && days_unused >= 90,
                    exists: true,
                    status: AppInstallStatus::Installed,
                    registry_path: None,
                    uninstall_string: None,
                    launch_count: None,
                });
            }
        }
    }
    apps.sort_by(|a, b| b.estimated_size_bytes.cmp(&a.estimated_size_bytes));
    apps
}

/// Delete stale Uninstall registry entries for apps that are already gone from disk.
#[cfg(target_os = "windows")]
pub fn cleanup_orphaned_apps(keys: Vec<String>) -> AppCleanupResult {
    use crate::models::FailedAction;
    use winreg::enums::*;
    use winreg::RegKey;

    let mut removed = Vec::new();
    let mut failed = Vec::new();

    for key in keys {
        let (root, subkey) = match key.split_once('\\') {
            Some((r, s)) => (r, s),
            None => {
                failed.push(FailedAction {
                    path: key.clone(),
                    reason: "Invalid registry path".to_string(),
                });
                continue;
            }
        };
        let hkey = match root {
            "HKEY_LOCAL_MACHINE" | "HKLM" => HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER" | "HKCU" => HKEY_CURRENT_USER,
            _ => {
                failed.push(FailedAction {
                    path: key.clone(),
                    reason: "Unsupported registry root".to_string(),
                });
                continue;
            }
        };
        match RegKey::predef(hkey).delete_subkey_all(subkey) {
            Ok(()) => removed.push(key.clone()),
            Err(e) => failed.push(FailedAction {
                path: key.clone(),
                reason: format!("Registry delete failed: {}", e),
            }),
        }
    }

    AppCleanupResult {
        removed_keys: removed,
        failed,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn cleanup_orphaned_apps(keys: Vec<String>) -> AppCleanupResult {
    use crate::models::FailedAction;
    AppCleanupResult {
        removed_keys: Vec::new(),
        failed: keys
            .into_iter()
            .map(|k| FailedAction {
                path: k,
                reason: "Registry cleanup is Windows-only".to_string(),
            })
            .collect(),
    }
}

/// Convert a WizTree/MFT row into a FileRecord, enriching executables with launch forensics.
fn wiztree_row_to_record(
    row: &crate::mft::WizTreeRow,
    signals: &crate::os_metadata::ForensicSignals,
    now: i64,
) -> FileRecord {
    let path = PathBuf::from(&row.path);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent_dir = path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let category = classify_extension(&extension);

    let mut last_used_at = row.accessed_at.max(row.modified_at);
    let mut last_used_source = if row.accessed_at > row.modified_at + 60 {
        "MFT access time".to_string()
    } else {
        "MFT modified time".to_string()
    };

    // For executables, real launch history beats MFT timestamps.
    if extension.eq_ignore_ascii_case("exe") {
        if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
            let lower = fname.to_lowercase();
            if let Some(ua) = signals.user_assist.get(&lower) {
                if ua.last_exec > last_used_at {
                    last_used_at = ua.last_exec;
                    last_used_source = "UserAssist registry".to_string();
                }
            }
            if let Some(&pf) = signals.prefetch_times.get(&lower) {
                if pf > last_used_at {
                    last_used_at = pf;
                    last_used_source = "Windows Prefetch".to_string();
                }
            }
        }
    }

    let days_unused = if last_used_at > 0 {
        ((now - last_used_at).max(0)) / 86_400
    } else {
        3650
    };
    let impact_score = compute_impact_score(row.size_bytes, days_unused);
    let relative_last_used = if last_used_at > 0 {
        format!(
            "Last used: {}",
            format_duration_human((now - last_used_at).max(0))
        )
    } else {
        "Last use unknown".to_string()
    };

    let lower_path = row.path.to_lowercase();
    let is_in_downloads =
        lower_path.contains("\\downloads\\") || lower_path.contains("/downloads/");

    let mut tags = Vec::new();
    if is_in_downloads
        && matches!(
            category,
            FileCategory::Installer | FileCategory::Archive | FileCategory::DiskImage
        )
        && days_unused >= 14
    {
        tags.push("Download & Forget".to_string());
    }
    if row.size_bytes >= 500 * 1024 * 1024 && days_unused >= 180 {
        tags.push("Stale Giant".to_string());
    }
    if matches!(category, FileCategory::Installer) && days_unused >= 30 {
        tags.push("Forgotten Installer".to_string());
    }
    if matches!(category, FileCategory::DiskImage) && days_unused >= 30 {
        tags.push("Orphaned ISO".to_string());
    }

    FileRecord {
        id: stable_id(&normalize_path_key(&path)),
        name,
        path: row.path.clone(),
        parent_dir,
        extension,
        category,
        size_bytes: row.size_bytes,
        created_at: row.created_at,
        modified_at: row.modified_at,
        accessed_at: row.accessed_at,
        last_used_at,
        last_used_source,
        days_unused,
        relative_last_used,
        impact_score,
        tags,
        is_ignored: false,
    }
}

/// Whole-drive turbo scan via WizTree's NTFS MFT read. Returns an error string when WizTree is
/// missing or its export cannot be parsed, so the UI can fall back to the built-in walker.
pub fn run_wiztree_turbo_scan(
    scan_id: String,
    root: String,
    min_size_bytes: u64,
) -> Result<ForensicsScanResult, String> {
    let wiztree = crate::mft::detect_wiztree()
        .ok_or_else(|| "WizTree is not installed. Use the built-in Deep Scan, or install WizTree to enable whole-drive turbo scanning.".to_string())?;

    let out_csv = std::env::temp_dir().join(format!("optimizeme_wiztree_{}.csv", std::process::id()));
    crate::mft::run_wiztree_export(&wiztree, &root, &out_csv)?;

    let bytes = fs::read(&out_csv).map_err(|e| format!("Failed to read WizTree export: {}", e))?;
    let _ = fs::remove_file(&out_csv);

    let rows = crate::mft::parse_wiztree_csv(&bytes);
    if rows.is_empty() {
        return Err(
            "WizTree export produced no parseable rows (unexpected schema). Falling back to the built-in scanner."
                .to_string(),
        );
    }

    let start = Instant::now();
    let now = now_epoch();
    let signals = collect_os_forensic_signals();

    let total_files_scanned = rows.len();
    let total_bytes_scanned = rows.iter().map(|r| r.size_bytes).sum::<u64>();

    // Build records for every file at/above the min-size threshold (no record cap).
    let mut records: Vec<FileRecord> = rows
        .par_iter()
        .filter(|r| r.size_bytes >= min_size_bytes)
        .map(|r| wiztree_row_to_record(r, &signals, now))
        .collect();

    // Deduplicate defensively by id.
    let mut seen_ids = HashSet::with_capacity(records.len());
    records.retain(|r| seen_ids.insert(r.id.clone()));

    let mut breakdown_map: HashMap<&'static str, (u64, usize, &'static str)> = HashMap::new();
    let mut reclaimable_bytes = 0u64;
    let mut stale_files_count = 0usize;
    for r in &records {
        let (label, color) = category_display_and_color(&r.category);
        breakdown_map
            .entry(label)
            .and_modify(|e| {
                e.0 += r.size_bytes;
                e.1 += 1;
            })
            .or_insert((r.size_bytes, 1, color));
        if r.days_unused >= 30 {
            reclaimable_bytes += r.size_bytes;
            stale_files_count += 1;
        }
    }

    let mut breakdown: Vec<StorageBreakdownItem> = breakdown_map
        .into_iter()
        .map(|(cat, (size_bytes, file_count, color))| StorageBreakdownItem {
            category: cat.to_string(),
            size_bytes,
            file_count,
            color: color.to_string(),
        })
        .collect();
    breakdown.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

    records.sort_by(|a, b| {
        b.impact_score
            .partial_cmp(&a.impact_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(ForensicsScanResult {
        scan_id,
        total_files_scanned,
        total_bytes_scanned,
        stale_files_count,
        reclaimable_bytes,
        duration_ms: start.elapsed().as_millis() as u64,
        breakdown,
        files: records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplicate_roots_collapses_overlapping_paths() {
        let cwd = std::env::current_dir().unwrap();
        let src_dir = cwd.join("src");
        let roots = vec![
            src_dir.to_string_lossy().to_string(),
            cwd.to_string_lossy().to_string(),
            cwd.to_string_lossy().to_string(),
        ];
        let deduped = deduplicate_roots(&roots);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0], cwd);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_generic_root_detection() {
        assert!(is_generic_root(Path::new("C:\\")));
        assert!(is_generic_root(Path::new("C:\\Program Files")));
        assert!(is_generic_root(Path::new("C:\\Program Files\\")));
        assert!(is_generic_root(Path::new("D:\\Program Files (x86)")));
        assert!(is_generic_root(Path::new("C:\\ProgramData")));
        assert!(is_generic_root(Path::new("C:\\Users")));
        assert!(!is_generic_root(Path::new("C:\\Program Files\\Epic Games")));
        assert!(!is_generic_root(Path::new(
            "C:\\Program Files\\Epic Games\\Launcher"
        )));
    }
}
