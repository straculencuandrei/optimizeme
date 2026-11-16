use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileCategory {
    Installer,
    Archive,
    Media,
    DiskImage,
    Document,
    Application,
    Code,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRecord {
    pub id: String,
    pub name: String,
    pub path: String,
    pub parent_dir: String,
    pub extension: String,
    pub category: FileCategory,
    pub size_bytes: u64,
    pub created_at: i64,
    pub modified_at: i64,
    pub accessed_at: i64,
    pub last_used_at: i64,
    pub last_used_source: String,
    pub days_unused: i64,
    pub relative_last_used: String,
    pub impact_score: f64,
    pub tags: Vec<String>,
    pub is_ignored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageBreakdownItem {
    pub category: String,
    pub size_bytes: u64,
    pub file_count: usize,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForensicsScanResult {
    pub scan_id: String,
    pub total_files_scanned: usize,
    pub total_bytes_scanned: u64,
    pub stale_files_count: usize,
    pub reclaimable_bytes: u64,
    pub duration_ms: u64,
    pub breakdown: Vec<StorageBreakdownItem>,
    pub files: Vec<FileRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForensicsBatchEvent {
    pub scan_id: String,
    pub files: Vec<FileRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanProgressEvent {
    pub scan_id: String,
    pub phase: String,
    pub scanned_files: usize,
    pub scanned_bytes: u64,
    pub current_path: String,
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickCleanCategory {
    pub id: String,
    pub name: String,
    pub description: String,
    pub group: String,
    pub size_bytes: u64,
    pub file_count: usize,
    pub sample_paths: Vec<String>,
    pub target_paths: Vec<String>,
    pub supports_cookie_toggle: bool,
    pub cookie_paths: Vec<String>,
    pub cookie_size_bytes: u64,
    pub enabled_by_default: bool,
    pub is_recycle_bin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickCleanScanResult {
    pub total_reclaimable_bytes: u64,
    pub total_files: usize,
    pub categories: Vec<QuickCleanCategory>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanRequestItem {
    pub category_id: String,
    pub target_paths: Vec<String>,
    pub include_cookies: bool,
    pub cookie_paths: Vec<String>,
    pub is_recycle_bin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanExecutionResult {
    pub freed_bytes: u64,
    pub deleted_count: usize,
    pub skipped_count: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppInstallStatus {
    /// A real install directory with at least one binary was found on disk.
    Installed,
    /// The registry still lists the app but every referenced path is gone (already uninstalled).
    Orphaned,
    /// The install directory exists but its primary executable is missing.
    Broken,
    /// Registry entry with no path information we could verify either way.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUsageRecord {
    pub id: String,
    pub name: String,
    pub publisher: String,
    pub install_location: String,
    pub executable_path: Option<String>,
    pub estimated_size_bytes: u64,
    pub last_launched_at: Option<i64>,
    pub last_launched_source: String,
    pub days_unused: i64,
    pub relative_last_used: String,
    pub is_bloated_unused: bool,
    /// True when the install location / executable actually exists on disk right now.
    pub exists: bool,
    pub status: AppInstallStatus,
    /// Full registry path of the Uninstall subkey (set for orphaned entries so they can be cleaned).
    pub registry_path: Option<String>,
    pub uninstall_string: Option<String>,
    /// Launch count read from the UserAssist registry, when available.
    pub launch_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppCleanupResult {
    pub removed_keys: Vec<String>,
    pub failed: Vec<FailedAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResult {
    pub deleted_paths: Vec<String>,
    pub freed_bytes: u64,
    pub failed: Vec<FailedAction>,
    pub shredded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailedAction {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePreviewInfo {
    pub path: String,
    pub name: String,
    pub extension: String,
    pub size_bytes: u64,
    pub mime_hint: String,
    pub text_snippet: Option<String>,
    pub is_binary: bool,
    pub created_at: i64,
    pub modified_at: i64,
    pub accessed_at: i64,
    pub sha256_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WhitelistConfig {
    pub ignored_files: HashSet<String>,
    pub ignored_folders: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefaultScanTarget {
    pub id: String,
    pub label: String,
    pub path: String,
    pub exists: bool,
}

pub struct AppState {
    pub whitelist: Mutex<WhitelistConfig>,
    pub whitelist_path: PathBuf,
    pub active_scan_cancel: Mutex<Option<Arc<AtomicBool>>>,
}
