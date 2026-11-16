use crate::models::{CleanExecutionResult, CleanRequestItem, QuickCleanCategory, QuickCleanScanResult};
use crate::os_metadata::{empty_recycle_bin, query_recycle_bin};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

struct CategoryBlueprint {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    group: &'static str,
    target_paths: Vec<PathBuf>,
    supports_cookie_toggle: bool,
    cookie_paths: Vec<PathBuf>,
    enabled_by_default: bool,
    is_recycle_bin: bool,
    extension_filter: Option<&'static [&'static str]>,
}

fn dir_stats(paths: &[PathBuf], ext_filter: Option<&[&str]>) -> (u64, usize, Vec<String>) {
    let mut bytes = 0u64;
    let mut count = 0usize;
    let mut samples = Vec::new();

    for root in paths {
        if !root.exists() {
            continue;
        }
        if root.is_file() {
            if let Ok(meta) = root.metadata() {
                bytes += meta.len();
                count += 1;
                if samples.len() < 4 {
                    samples.push(root.to_string_lossy().to_string());
                }
            }
            continue;
        }

        for entry in WalkDir::new(root).follow_links(false).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            if let Some(exts) = ext_filter {
                let matches = entry
                    .path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| exts.iter().any(|x| e.eq_ignore_ascii_case(x)))
                    .unwrap_or(false);
                if !matches {
                    continue;
                }
            }
            if let Ok(meta) = entry.metadata() {
                bytes += meta.len();
                count += 1;
                if samples.len() < 4 {
                    samples.push(entry.path().to_string_lossy().to_string());
                }
            }
        }
    }

    (bytes, count, samples)
}

fn collect_chromium_profiles(user_data_dir: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut cache_dirs = Vec::new();
    let mut cookie_files = Vec::new();
    if !user_data_dir.exists() {
        return (cache_dirs, cookie_files);
    }

    let mut profile_roots = vec![user_data_dir.join("Default")];
    if let Ok(entries) = fs::read_dir(user_data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("Profile ") && entry.path().is_dir() {
                profile_roots.push(entry.path());
            }
        }
    }

    for profile in profile_roots {
        if !profile.exists() {
            continue;
        }
        for sub in ["Cache", "Code Cache", "GPUCache", "DawnCache", "GrShaderCache", "Service Worker\\CacheStorage"] {
            let p = profile.join(sub);
            if p.exists() {
                cache_dirs.push(p);
            }
        }
        for c in ["Network\\Cookies", "Cookies", "Sessions"] {
            let cp = profile.join(c);
            if cp.exists() {
                cookie_files.push(cp);
            }
        }
    }

    // Also include top-level ShaderCache if present
    let top_shader = user_data_dir.join("ShaderCache");
    if top_shader.exists() {
        cache_dirs.push(top_shader);
    }

    (cache_dirs, cookie_files)
}

fn collect_firefox_paths() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut cache_dirs = Vec::new();
    let mut cookie_files = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Some(local) = dirs::data_local_dir() {
            let ff_cache = local.join("Mozilla").join("Firefox").join("Profiles");
            if let Ok(entries) = fs::read_dir(ff_cache) {
                for entry in entries.flatten() {
                    let c2 = entry.path().join("cache2");
                    if c2.exists() {
                        cache_dirs.push(c2);
                    }
                    let sc = entry.path().join("startupCache");
                    if sc.exists() {
                        cache_dirs.push(sc);
                    }
                }
            }
        }
        if let Some(roaming) = dirs::data_dir() {
            let ff_roaming = roaming.join("Mozilla").join("Firefox").join("Profiles");
            if let Ok(entries) = fs::read_dir(ff_roaming) {
                for entry in entries.flatten() {
                    let ck = entry.path().join("cookies.sqlite");
                    if ck.exists() {
                        cookie_files.push(ck);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    if let Some(home) = dirs::home_dir() {
        let ff_cache = home.join("Library/Caches/Firefox/Profiles");
        if let Ok(entries) = fs::read_dir(ff_cache) {
            for entry in entries.flatten() {
                let c2 = entry.path().join("cache2");
                if c2.exists() {
                    cache_dirs.push(c2);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(home) = dirs::home_dir() {
        let ff_cache = home.join(".cache/mozilla/firefox");
        if let Ok(entries) = fs::read_dir(ff_cache) {
            for entry in entries.flatten() {
                let c2 = entry.path().join("cache2");
                if c2.exists() {
                    cache_dirs.push(c2);
                }
            }
        }
    }

    (cache_dirs, cookie_files)
}

fn build_blueprints() -> Vec<CategoryBlueprint> {
    let mut blueprints = Vec::new();

    // 1. OS Temporary Files
    let mut os_temp_paths = vec![std::env::temp_dir()];
    #[cfg(target_os = "windows")]
    {
        let win_temp = PathBuf::from("C:\\Windows\\Temp");
        if win_temp.exists() {
            os_temp_paths.push(win_temp);
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = dirs::home_dir() {
        let mac_caches = home.join("Library/Caches");
        if mac_caches.exists() {
            os_temp_paths.push(mac_caches);
        }
    }
    #[cfg(unix)]
    {
        let tmp = PathBuf::from("/tmp");
        if tmp.exists() && !os_temp_paths.contains(&tmp) {
            os_temp_paths.push(tmp);
        }
    }

    blueprints.push(CategoryBlueprint {
        id: "os_temp",
        name: "OS Temporary Files",
        description: "System & user temp directories (%TEMP%, /tmp, OS caches) safe to purge.",
        group: "System Hygiene",
        target_paths: os_temp_paths,
        supports_cookie_toggle: false,
        cookie_paths: vec![],
        enabled_by_default: true,
        is_recycle_bin: false,
        extension_filter: None,
    });

    // 2. Browser Caches (Chrome, Edge, Brave, Firefox, Safari)
    #[cfg(target_os = "windows")]
    let local_app = dirs::data_local_dir();
    #[cfg(not(target_os = "windows"))]
    let local_app = dirs::cache_dir();

    // Chrome
    let (chrome_cache, chrome_cookies) = {
        #[cfg(target_os = "windows")]
        let base = local_app
            .as_ref()
            .map(|d| d.join("Google").join("Chrome").join("User Data"));
        #[cfg(target_os = "macos")]
        let base = dirs::home_dir()
            .map(|h| h.join("Library/Caches/Google/Chrome"));
        #[cfg(target_os = "linux")]
        let base = local_app.as_ref().map(|d| d.join("google-chrome"));

        base.map(|b| collect_chromium_profiles(&b)).unwrap_or_default()
    };
    blueprints.push(CategoryBlueprint {
        id: "browser_chrome",
        name: "Google Chrome Cache",
        description: "Cached web assets, shader cache & code cache. Logins preserved by default.",
        group: "Browser Caches",
        target_paths: chrome_cache,
        supports_cookie_toggle: true,
        cookie_paths: chrome_cookies,
        enabled_by_default: true,
        is_recycle_bin: false,
        extension_filter: None,
    });

    // Edge
    let (edge_cache, edge_cookies) = {
        #[cfg(target_os = "windows")]
        let base = local_app
            .as_ref()
            .map(|d| d.join("Microsoft").join("Edge").join("User Data"));
        #[cfg(target_os = "macos")]
        let base = dirs::home_dir()
            .map(|h| h.join("Library/Caches/Microsoft Edge"));
        #[cfg(target_os = "linux")]
        let base = local_app.as_ref().map(|d| d.join("microsoft-edge"));

        base.map(|b| collect_chromium_profiles(&b)).unwrap_or_default()
    };
    blueprints.push(CategoryBlueprint {
        id: "browser_edge",
        name: "Microsoft Edge Cache",
        description: "Cached scripts, media & GPU shader cache. Active sessions stay intact.",
        group: "Browser Caches",
        target_paths: edge_cache,
        supports_cookie_toggle: true,
        cookie_paths: edge_cookies,
        enabled_by_default: true,
        is_recycle_bin: false,
        extension_filter: None,
    });

    // Brave
    let (brave_cache, brave_cookies) = {
        #[cfg(target_os = "windows")]
        let base = local_app
            .as_ref()
            .map(|d| d.join("BraveSoftware").join("Brave-Browser").join("User Data"));
        #[cfg(target_os = "macos")]
        let base = dirs::home_dir()
            .map(|h| h.join("Library/Caches/BraveSoftware/Brave-Browser"));
        #[cfg(target_os = "linux")]
        let base = local_app.as_ref().map(|d| d.join("BraveSoftware/Brave-Browser"));

        base.map(|b| collect_chromium_profiles(&b)).unwrap_or_default()
    };
    blueprints.push(CategoryBlueprint {
        id: "browser_brave",
        name: "Brave Browser Cache",
        description: "Web cache & compiled JS bytecode. Bookmarks and logins untouched.",
        group: "Browser Caches",
        target_paths: brave_cache,
        supports_cookie_toggle: true,
        cookie_paths: brave_cookies,
        enabled_by_default: true,
        is_recycle_bin: false,
        extension_filter: None,
    });

    // Firefox
    let (ff_cache, ff_cookies) = collect_firefox_paths();
    blueprints.push(CategoryBlueprint {
        id: "browser_firefox",
        name: "Mozilla Firefox Cache",
        description: "Profile cache2 & startupCache data without clearing active logins.",
        group: "Browser Caches",
        target_paths: ff_cache,
        supports_cookie_toggle: true,
        cookie_paths: ff_cookies,
        enabled_by_default: true,
        is_recycle_bin: false,
        extension_filter: None,
    });

    // Safari (macOS)
    #[cfg(target_os = "macos")]
    {
        let safari_cache = dirs::home_dir()
            .map(|h| vec![h.join("Library/Caches/com.apple.Safari")])
            .unwrap_or_default();
        let safari_cookies = dirs::home_dir()
            .map(|h| vec![h.join("Library/Cookies/Cookies.binarycookies")])
            .unwrap_or_default();
        blueprints.push(CategoryBlueprint {
            id: "browser_safari",
            name: "Safari Browser Cache",
            description: "Safari disk cache and webpage previews.",
            group: "Browser Caches",
            target_paths: safari_cache,
            supports_cookie_toggle: true,
            cookie_paths: safari_cookies,
            enabled_by_default: true,
            is_recycle_bin: false,
            extension_filter: None,
        });
    }

    // 3. Application Logs & Crash Dumps
    let mut crash_paths = Vec::new();
    let mut log_paths = Vec::new();

    #[cfg(target_os = "windows")]
    if let Some(local) = &local_app {
        let dumps = local.join("CrashDumps");
        if dumps.exists() {
            crash_paths.push(dumps);
        }
        let wer = local.join("Microsoft").join("Windows").join("WER");
        if wer.exists() {
            crash_paths.push(wer);
        }
        let logs = local.join("Temp");
        if logs.exists() {
            log_paths.push(logs);
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = dirs::home_dir() {
        let logs = home.join("Library/Logs");
        if logs.exists() {
            log_paths.push(logs);
        }
        let diag = home.join("Library/Logs/DiagnosticReports");
        if diag.exists() {
            crash_paths.push(diag);
        }
    }

    blueprints.push(CategoryBlueprint {
        id: "crash_dumps",
        name: "Crash Dumps & Error Reports",
        description: "Windows Error Reporting (WER) & minidump files left behind by crashed apps.",
        group: "Diagnostics & Trash",
        target_paths: crash_paths,
        supports_cookie_toggle: false,
        cookie_paths: vec![],
        enabled_by_default: true,
        is_recycle_bin: false,
        extension_filter: None,
    });

    blueprints.push(CategoryBlueprint {
        id: "app_logs",
        name: "Application Log Files",
        description: "Accumulated .log and .dmp diagnostic files across user directories.",
        group: "Diagnostics & Trash",
        target_paths: log_paths,
        supports_cookie_toggle: false,
        cookie_paths: vec![],
        enabled_by_default: true,
        is_recycle_bin: false,
        extension_filter: Some(&["log", "dmp", "old"]),
    });

    // 4. Thumbnail Caches
    let mut thumb_paths = Vec::new();
    #[cfg(target_os = "windows")]
    if let Some(local) = &local_app {
        let explorer_dir = local.join("Microsoft").join("Windows").join("Explorer");
        if let Ok(entries) = fs::read_dir(explorer_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_lowercase();
                if name.starts_with("thumbcache_") || name.starts_with("iconcache_") {
                    thumb_paths.push(entry.path());
                }
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    if let Some(home) = dirs::home_dir() {
        let tc = home.join(".cache/thumbnails");
        if tc.exists() {
            thumb_paths.push(tc);
        }
    }

    blueprints.push(CategoryBlueprint {
        id: "thumb_cache",
        name: "Thumbnail & Icon Caches",
        description: "Explorer/Finder cached image thumbnails; automatically regenerated when needed.",
        group: "System Hygiene",
        target_paths: thumb_paths,
        supports_cookie_toggle: false,
        cookie_paths: vec![],
        enabled_by_default: true,
        is_recycle_bin: false,
        extension_filter: None,
    });

    // 5. Recycle Bin / Trash
    blueprints.push(CategoryBlueprint {
        id: "recycle_bin",
        name: if cfg!(target_os = "windows") {
            "Windows Recycle Bin"
        } else {
            "System Trash"
        },
        description: "Previously deleted files still occupying disk space in the Recycle Bin.",
        group: "Diagnostics & Trash",
        target_paths: vec![],
        supports_cookie_toggle: false,
        cookie_paths: vec![],
        enabled_by_default: false,
        is_recycle_bin: true,
        extension_filter: None,
    });

    blueprints
}

pub fn scan_quick_clean() -> QuickCleanScanResult {
    let start = Instant::now();
    let blueprints = build_blueprints();

    let categories: Vec<QuickCleanCategory> = blueprints
        .into_par_iter()
        .map(|bp| {
            if bp.is_recycle_bin {
                let (size_bytes, file_count) = query_recycle_bin();
                QuickCleanCategory {
                    id: bp.id.to_string(),
                    name: bp.name.to_string(),
                    description: bp.description.to_string(),
                    group: bp.group.to_string(),
                    size_bytes,
                    file_count,
                    sample_paths: vec![],
                    target_paths: vec![],
                    supports_cookie_toggle: false,
                    cookie_paths: vec![],
                    cookie_size_bytes: 0,
                    enabled_by_default: bp.enabled_by_default,
                    is_recycle_bin: true,
                }
            } else {
                let (size_bytes, file_count, sample_paths) =
                    dir_stats(&bp.target_paths, bp.extension_filter);
                let (cookie_size_bytes, _, _) = if bp.supports_cookie_toggle {
                    dir_stats(&bp.cookie_paths, None)
                } else {
                    (0, 0, vec![])
                };

                QuickCleanCategory {
                    id: bp.id.to_string(),
                    name: bp.name.to_string(),
                    description: bp.description.to_string(),
                    group: bp.group.to_string(),
                    size_bytes,
                    file_count,
                    sample_paths,
                    target_paths: bp
                        .target_paths
                        .into_iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect(),
                    supports_cookie_toggle: bp.supports_cookie_toggle,
                    cookie_paths: bp
                        .cookie_paths
                        .into_iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect(),
                    cookie_size_bytes,
                    enabled_by_default: bp.enabled_by_default,
                    is_recycle_bin: false,
                }
            }
        })
        .collect();

    let total_reclaimable_bytes: u64 = categories.iter().map(|c| c.size_bytes).sum();
    let total_files: usize = categories.iter().map(|c| c.file_count).sum();

    QuickCleanScanResult {
        total_reclaimable_bytes,
        total_files,
        categories,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn purge_path(path: &Path, ext_filter: Option<&[&str]>) -> (u64, usize, usize, Vec<String>) {
    let mut freed = 0u64;
    let mut deleted = 0usize;
    let mut skipped = 0usize;
    let mut errors = Vec::new();

    if !path.exists() {
        return (0, 0, 0, errors);
    }

    if path.is_file() {
        let len = path.metadata().map(|m| m.len()).unwrap_or(0);
        match fs::remove_file(path) {
            Ok(_) => {
                freed += len;
                deleted += 1;
            }
            Err(_) => {
                skipped += 1;
            }
        }
        return (freed, deleted, skipped, errors);
    }

    // Walk files bottom-up so subdirectories can also be cleaned if empty
    let entries: Vec<_> = WalkDir::new(path)
        .contents_first(true)
        .follow_links(false)
        .into_iter()
        .flatten()
        .collect();

    for entry in entries {
        let p = entry.path();
        if p == path {
            continue;
        }
        if entry.file_type().is_file() {
            if let Some(exts) = ext_filter {
                let matches = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| exts.iter().any(|x| e.eq_ignore_ascii_case(x)))
                    .unwrap_or(false);
                if !matches {
                    continue;
                }
            }
            let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
            match fs::remove_file(p) {
                Ok(_) => {
                    freed += len;
                    deleted += 1;
                }
                Err(_) => {
                    skipped += 1;
                }
            }
        } else if entry.file_type().is_dir() && ext_filter.is_none() {
            // Only remove empty directories
            let _ = fs::remove_dir(p);
        }
    }

    if skipped > 0 && deleted == 0 {
        errors.push(format!(
            "{} items in {} are in use by running processes.",
            skipped,
            path.display()
        ));
    }

    (freed, deleted, skipped, errors)
}

pub fn execute_quick_clean(items: Vec<CleanRequestItem>) -> CleanExecutionResult {
    let mut freed_bytes = 0u64;
    let mut deleted_count = 0usize;
    let mut skipped_count = 0usize;
    let mut errors = Vec::new();

    for item in items {
        if item.is_recycle_bin {
            let (rb_bytes, rb_count) = query_recycle_bin();
            match empty_recycle_bin() {
                Ok(_) => {
                    freed_bytes += rb_bytes;
                    deleted_count += rb_count;
                }
                Err(e) => errors.push(e),
            }
            continue;
        }

        let ext_filter: Option<&[&str]> = if item.category_id == "app_logs" {
            Some(&["log", "dmp", "old"])
        } else {
            None
        };

        for target in &item.target_paths {
            let (f, d, s, mut errs) = purge_path(Path::new(target), ext_filter);
            freed_bytes += f;
            deleted_count += d;
            skipped_count += s;
            errors.append(&mut errs);
        }

        if item.include_cookies {
            for cpath in &item.cookie_paths {
                let (f, d, s, mut errs) = purge_path(Path::new(cpath), None);
                freed_bytes += f;
                deleted_count += d;
                skipped_count += s;
                errors.append(&mut errs);
            }
        }
    }

    CleanExecutionResult {
        freed_bytes,
        deleted_count,
        skipped_count,
        errors,
    }
}
