mod actions;
mod forensics;
mod mft;
mod models;
mod os_metadata;
mod quick_clean;

use crate::actions::{
    delete_files, load_whitelist, open_with_default_app, quick_preview, reveal_in_explorer,
    save_whitelist,
};
use crate::forensics::{
    cleanup_orphaned_apps, get_default_scan_targets, run_forensics_scan, run_wiztree_turbo_scan,
    scan_installed_apps,
};
use crate::models::{
    AppCleanupResult, AppState, AppUsageRecord, CleanExecutionResult, CleanRequestItem,
    DefaultScanTarget, DeleteResult, FilePreviewInfo, ForensicsScanResult, QuickCleanScanResult,
    WhitelistConfig,
};
use crate::quick_clean::{execute_quick_clean, scan_quick_clean};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, State};

#[tauri::command]
fn get_default_targets() -> Vec<DefaultScanTarget> {
    get_default_scan_targets()
}

#[tauri::command]
async fn scan_quick_clean_cmd() -> Result<QuickCleanScanResult, String> {
    tokio::task::spawn_blocking(scan_quick_clean)
        .await
        .map_err(|e| format!("Quick scan task failed: {}", e))
}

#[tauri::command]
async fn execute_quick_clean_cmd(
    items: Vec<CleanRequestItem>,
) -> Result<CleanExecutionResult, String> {
    tokio::task::spawn_blocking(move || execute_quick_clean(items))
        .await
        .map_err(|e| format!("Quick clean task failed: {}", e))
}

#[tauri::command]
async fn start_forensics_scan_cmd(
    app: AppHandle,
    state: State<'_, AppState>,
    scan_id: String,
    target_paths: Vec<String>,
    min_size_bytes: u64,
) -> Result<ForensicsScanResult, String> {
    // Cancel any previous running scan
    let cancel_flag = Arc::new(AtomicBool::new(false));
    {
        let mut active = state
            .active_scan_cancel
            .lock()
            .map_err(|_| "State lock error")?;
        if let Some(prev) = active.take() {
            prev.store(true, Ordering::Relaxed);
        }
        *active = Some(cancel_flag.clone());
    }

    let whitelist = state
        .whitelist
        .lock()
        .map_err(|_| "Whitelist lock error")?
        .clone();

    let res = tokio::task::spawn_blocking(move || {
        run_forensics_scan(
            &app,
            scan_id,
            target_paths,
            min_size_bytes,
            whitelist,
            cancel_flag,
        )
    })
    .await
    .map_err(|e| format!("Forensics scan failed: {}", e))?;

    Ok(res)
}

#[tauri::command]
fn cancel_forensics_scan_cmd(state: State<'_, AppState>) -> Result<(), String> {
    if let Ok(active) = state.active_scan_cancel.lock() {
        if let Some(flag) = active.as_ref() {
            flag.store(true, Ordering::Relaxed);
        }
    }
    Ok(())
}

#[tauri::command]
async fn scan_installed_apps_cmd() -> Result<Vec<AppUsageRecord>, String> {
    tokio::task::spawn_blocking(scan_installed_apps)
        .await
        .map_err(|e| format!("App usage scan failed: {}", e))
}

#[tauri::command]
async fn cleanup_orphaned_apps_cmd(keys: Vec<String>) -> Result<AppCleanupResult, String> {
    tokio::task::spawn_blocking(move || cleanup_orphaned_apps(keys))
        .await
        .map_err(|e| format!("App cleanup task failed: {}", e))
}

#[tauri::command]
fn wiztree_status_cmd() -> Option<String> {
    crate::mft::detect_wiztree()
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
async fn run_turbo_scan_cmd(
    scan_id: String,
    root: String,
    min_size_bytes: u64,
) -> Result<ForensicsScanResult, String> {
    tokio::task::spawn_blocking(move || run_wiztree_turbo_scan(scan_id, root, min_size_bytes))
        .await
        .map_err(|e| format!("Turbo scan task failed: {}", e))?
}

#[tauri::command]
fn reveal_in_explorer_cmd(path: String) -> Result<(), String> {
    reveal_in_explorer(&path)
}

#[tauri::command]
fn open_with_default_app_cmd(path: String) -> Result<(), String> {
    open_with_default_app(&path)
}

#[tauri::command]
async fn quick_preview_cmd(path: String) -> Result<FilePreviewInfo, String> {
    tokio::task::spawn_blocking(move || quick_preview(&path))
        .await
        .map_err(|e| format!("Preview task failed: {}", e))?
}

#[tauri::command]
async fn delete_files_cmd(
    paths: Vec<String>,
    permanent_shred: bool,
) -> Result<DeleteResult, String> {
    tokio::task::spawn_blocking(move || delete_files(paths, permanent_shred))
        .await
        .map_err(|e| format!("Delete task failed: {}", e))
}

#[tauri::command]
fn get_whitelist_cmd(state: State<'_, AppState>) -> Result<WhitelistConfig, String> {
    state
        .whitelist
        .lock()
        .map(|w| w.clone())
        .map_err(|_| "Whitelist lock error".to_string())
}

#[tauri::command]
fn add_to_whitelist_cmd(
    state: State<'_, AppState>,
    path: String,
    is_folder: bool,
) -> Result<WhitelistConfig, String> {
    let mut wl = state
        .whitelist
        .lock()
        .map_err(|_| "Whitelist lock error".to_string())?;
    if is_folder {
        wl.ignored_folders.insert(path);
    } else {
        wl.ignored_files.insert(path);
    }
    save_whitelist(&state.whitelist_path, &wl)?;
    Ok(wl.clone())
}

#[tauri::command]
fn remove_from_whitelist_cmd(
    state: State<'_, AppState>,
    path: String,
    is_folder: bool,
) -> Result<WhitelistConfig, String> {
    let mut wl = state
        .whitelist
        .lock()
        .map_err(|_| "Whitelist lock error".to_string())?;
    if is_folder {
        wl.ignored_folders.remove(&path);
    } else {
        wl.ignored_files.remove(&path);
    }
    save_whitelist(&state.whitelist_path, &wl)?;
    Ok(wl.clone())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir().join("optimizeme"));
            let whitelist_path = data_dir.join("whitelist.json");
            let whitelist = load_whitelist(&whitelist_path);

            app.manage(AppState {
                whitelist: Mutex::new(whitelist),
                whitelist_path,
                active_scan_cancel: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_default_targets,
            scan_quick_clean_cmd,
            execute_quick_clean_cmd,
            start_forensics_scan_cmd,
            cancel_forensics_scan_cmd,
            scan_installed_apps_cmd,
            cleanup_orphaned_apps_cmd,
            wiztree_status_cmd,
            run_turbo_scan_cmd,
            reveal_in_explorer_cmd,
            open_with_default_app_cmd,
            quick_preview_cmd,
            delete_files_cmd,
            get_whitelist_cmd,
            add_to_whitelist_cmd,
            remove_from_whitelist_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
