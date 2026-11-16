//! Local "reasoning" engine that turns raw forensic signals into plain-language
//! recommendations.
//!
//! There is no network call and no external model here — the "intelligence" is a set of
//! deterministic, auditable rules that weigh the exact data the app already collected from the
//! machine: file size, age, type and location, Windows UserAssist launch counts, Prefetch run
//! history, and installed-app registry state. Every recommendation carries the concrete reasons
//! that produced it, so the user can see *why* something is flagged.

use crate::models::{
    AppInstallStatus, AppUsageRecord, FileCategory, FileRecord, Insight, InsightAction,
    InsightDisposition, InsightKind, InsightReport, QuickCleanCategory, WhitelistConfig,
};
use crate::os_metadata::now_epoch;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tauri::AppHandle;

/// Files smaller than this are ignored by the insights pass (keeps it fast and focused).
const FILE_MIN_SIZE: u64 = 5 * 1024 * 1024;
/// Maximum number of file candidates to reason about in a single run.
const MAX_FILE_INSIGHTS: usize = 120;
/// Maximum number of "keep" examples (recently-used apps) to surface.
const MAX_KEEP_EXAMPLES: usize = 6;

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.1} {}", value, UNITS[unit])
}

fn category_label(cat: &FileCategory) -> &'static str {
    match cat {
        FileCategory::Installer => "Installer",
        FileCategory::Archive => "Archive",
        FileCategory::DiskImage => "Disk image",
        FileCategory::Media => "Media",
        FileCategory::Document => "Document",
        FileCategory::Application => "Application",
        FileCategory::Code => "Code",
        FileCategory::Other => "Other",
    }
}

fn is_downloads(path: &str) -> bool {
    let l = path.to_lowercase();
    l.contains("\\downloads") || l.contains("/downloads")
}

fn is_desktop(path: &str) -> bool {
    let l = path.to_lowercase();
    l.contains("\\desktop") || l.contains("/desktop")
}

fn file_disposition(score: u8) -> InsightDisposition {
    if score >= 65 {
        InsightDisposition::Remove
    } else if score >= 40 {
        InsightDisposition::Review
    } else {
        InsightDisposition::Keep
    }
}

/// Score a file 0-100 and produce the reasons that explain the score.
fn score_file(f: &FileRecord) -> (u8, Vec<String>) {
    let mut score: i32 = 0;
    let mut reasons: Vec<String> = Vec::new();

    // Age is the primary "forgotten" signal.
    if f.days_unused >= 730 {
        score += 30;
    } else if f.days_unused >= 365 {
        score += 24;
    } else if f.days_unused >= 180 {
        score += 18;
    } else if f.days_unused >= 30 {
        score += 10;
    } else {
        score += 2;
    }
    reasons.push(format!(
        "{} (tracked via {}).",
        f.relative_last_used, f.last_used_source
    ));

    // Size.
    if f.size_bytes >= 500 * 1024 * 1024 {
        score += 30;
        reasons.push(format!(
            "{} on disk — a very large single item.",
            human_size(f.size_bytes)
        ));
    } else if f.size_bytes >= 100 * 1024 * 1024 {
        score += 22;
        reasons.push(format!("{} on disk.", human_size(f.size_bytes)));
    } else if f.size_bytes >= 10 * 1024 * 1024 {
        score += 14;
    } else {
        score += 6;
    }

    // Type: installers / archives / disk images are transient and re-obtainable.
    if matches!(
        f.category,
        FileCategory::Installer | FileCategory::Archive | FileCategory::DiskImage
    ) {
        score += 15;
        reasons.push(format!(
            "{} files are typically re-downloadable and already served their purpose.",
            category_label(&f.category)
        ));
    }

    // Location: Downloads is meant to be transient.
    if is_downloads(&f.path) {
        score += 12;
        reasons.push("It sits in Downloads, a folder meant to be cleared out.".to_string());
    } else if is_desktop(&f.path) {
        score += 8;
    }

    // Tags assigned by the forensics engine.
    for tag in &f.tags {
        match tag.as_str() {
            "Download & Forget" => {
                score += 8;
                reasons.push("Flagged 'Download & Forget' — run once, then never touched again.".to_string());
            }
            "Never Opened" => {
                score += 5;
                reasons.push("Never opened since it was created or downloaded.".to_string());
            }
            "Stale Giant" => {
                score += 6;
            }
            "Forgotten Installer" => {
                score += 4;
            }
            "Orphaned ISO" => {
                score += 4;
            }
            _ => {}
        }
    }

    // Cap reasons at a readable number, preserving the most informative ones.
    if reasons.len() > 4 {
        reasons.truncate(4);
    }

    (score.clamp(0, 100) as u8, reasons)
}

/// Reason about a single installed-app record. Returns None when there is nothing notable to say.
fn app_insight(app: &AppUsageRecord) -> Option<Insight> {
    let mut reasons: Vec<String> = Vec::new();
    let (disposition, confidence, action, action_label) = match app.status {
        AppInstallStatus::Orphaned => {
            reasons.push(
                "It is already uninstalled — every path the registry points to is gone.".to_string(),
            );
            reasons.push(
                "Only the stale registry entry remains; removing it touches no files.".to_string(),
            );
            (
                InsightDisposition::Remove,
                94u8,
                InsightAction::RemoveRegistryEntry,
                "Remove stale entry".to_string(),
            )
        }
        AppInstallStatus::Broken => {
            reasons.push(
                "Its install folder exists but the main executable is missing.".to_string(),
            );
            reasons.push(
                "The app can no longer run — consider a clean reinstall or removal.".to_string(),
            );
            (
                InsightDisposition::Review,
                62u8,
                InsightAction::Reveal,
                "Inspect".to_string(),
            )
        }
        AppInstallStatus::Installed if app.is_bloated_unused => {
            reasons.push(format!(
                "{} installed on disk.",
                human_size(app.estimated_size_bytes)
            ));
            if app.last_launched_at.is_some() {
                reasons.push(format!("{}.", app.relative_last_used));
            }
            match app.launch_count {
                Some(n) if n > 0 => {
                    reasons.push(format!("Launched only {} time(s) in total.", n));
                }
                _ => {
                    if app.last_launched_at.is_none() {
                        reasons.push("No launch history was recorded for this app.".to_string());
                    }
                }
            }
            (
                InsightDisposition::Review,
                68u8,
                InsightAction::Reveal,
                "Reveal / Uninstall".to_string(),
            )
        }
        _ => return None,
    };

    Some(Insight {
        id: app.id.clone(),
        kind: InsightKind::App,
        title: app.name.clone(),
        subtitle: if app.install_location.is_empty() {
            app.publisher.clone()
        } else {
            app.install_location.clone()
        },
        size_bytes: app.estimated_size_bytes,
        confidence,
        disposition,
        reasons,
        action_label: action_label.to_string(),
        action,
        path: app
            .executable_path
            .clone()
            .or_else(|| {
                if app.install_location.is_empty() {
                    None
                } else {
                    Some(app.install_location.clone())
                }
            }),
        category_id: None,
        registry_path: app.registry_path.clone(),
    })
}

/// Reason about a junk category from the quick-clean scan.
fn junk_insight(cat: &QuickCleanCategory) -> Option<Insight> {
    if cat.size_bytes == 0 && cat.cookie_size_bytes == 0 {
        return None;
    }
    let mut reasons: Vec<String> = Vec::new();
    reasons.push(format!(
        "{} of reclaimable space in {}.",
        human_size(cat.size_bytes),
        cat.name
    ));
    reasons.push(cat.description.clone());
    if cat.supports_cookie_toggle && cat.cookie_size_bytes > 0 {
        reasons.push(format!(
            "Logins & cookies ({}) are preserved by default.",
            human_size(cat.cookie_size_bytes)
        ));
    }

    Some(Insight {
        id: format!("junk:{}", cat.id),
        kind: InsightKind::JunkCategory,
        title: cat.name.clone(),
        subtitle: format!("{} items", cat.file_count),
        size_bytes: cat.size_bytes,
        confidence: if cat.is_recycle_bin { 85 } else { 90 },
        disposition: InsightDisposition::Remove,
        reasons,
        action_label: "Clean".to_string(),
        action: InsightAction::CleanJunk,
        path: None,
        category_id: Some(cat.id.clone()),
        registry_path: None,
    })
}

fn insight_paths() -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(p) = dirs::download_dir() {
        paths.push(p.to_string_lossy().to_string());
    }
    if let Some(p) = dirs::desktop_dir() {
        paths.push(p.to_string_lossy().to_string());
    }
    if let Some(p) = dirs::document_dir() {
        paths.push(p.to_string_lossy().to_string());
    }
    if let Some(p) = dirs::video_dir() {
        paths.push(p.to_string_lossy().to_string());
    }
    if let Some(p) = dirs::picture_dir() {
        paths.push(p.to_string_lossy().to_string());
    }
    paths
}

pub fn generate_insights(app: &AppHandle, whitelist: WhitelistConfig) -> InsightReport {
    let now = now_epoch();
    let mut insights: Vec<Insight> = Vec::new();

    // 1. Junk categories (fast, high-confidence wins).
    let quick = crate::quick_clean::scan_quick_clean();
    for cat in &quick.categories {
        if let Some(ins) = junk_insight(cat) {
            insights.push(ins);
        }
    }

    // 2. Installed apps (filesystem + registry + launch history).
    let apps = crate::forensics::scan_installed_apps();
    for app in &apps {
        if let Some(ins) = app_insight(app) {
            insights.push(ins);
        }
    }

    // 3. Files in the user's own folders (largest / most-forgotten first).
    let cancel = Arc::new(AtomicBool::new(false));
    let scan = crate::forensics::run_forensics_scan(
        app,
        format!("insights_{}", now),
        insight_paths(),
        FILE_MIN_SIZE,
        whitelist,
        cancel,
    );
    for f in scan.files.iter().take(MAX_FILE_INSIGHTS) {
        let (score, reasons) = score_file(f);
        let disposition = file_disposition(score);
        // Keep files are noise in the "do something" list; only surface actionable ones here.
        if disposition == InsightDisposition::Keep {
            continue;
        }
        insights.push(Insight {
            id: f.id.clone(),
            kind: InsightKind::File,
            title: f.name.clone(),
            subtitle: f.path.clone(),
            size_bytes: f.size_bytes,
            confidence: score,
            disposition: disposition.clone(),
            reasons,
            action_label: if disposition == InsightDisposition::Remove {
                "Move to Trash".to_string()
            } else {
                "Reveal".to_string()
            },
            action: if disposition == InsightDisposition::Remove {
                InsightAction::DeleteFile
            } else {
                InsightAction::Reveal
            },
            path: Some(f.path.clone()),
            category_id: None,
            registry_path: None,
        });
    }

    // 4. "Keep" examples: recently-launched apps the user clearly still uses.
    let mut keep_candidates: Vec<&AppUsageRecord> = apps
        .iter()
        .filter(|a| {
            a.status == AppInstallStatus::Installed
                && a.last_launched_at.is_some()
                && a.days_unused < 30
                && a.estimated_size_bytes > 0
        })
        .collect();
    keep_candidates.sort_by(|a, b| b.estimated_size_bytes.cmp(&a.estimated_size_bytes));
    for app in keep_candidates.iter().take(MAX_KEEP_EXAMPLES) {
        insights.push(Insight {
            id: format!("keep:{}", app.id),
            kind: InsightKind::App,
            title: app.name.clone(),
            subtitle: if app.install_location.is_empty() {
                app.publisher.clone()
            } else {
                app.install_location.clone()
            },
            size_bytes: app.estimated_size_bytes,
            confidence: 0,
            disposition: InsightDisposition::Keep,
            reasons: vec![format!(
                "{} — you still use this, so leave it alone.",
                app.relative_last_used
            )],
            action_label: "Keep".to_string(),
            action: InsightAction::None,
            path: app.executable_path.clone(),
            category_id: None,
            registry_path: None,
        });
    }

    // Rank: Remove first, then Review, then Keep; within a tier, largest first.
    insights.sort_by(|a, b| {
        let rank = |d: &InsightDisposition| match d {
            InsightDisposition::Remove => 0u8,
            InsightDisposition::Review => 1,
            InsightDisposition::Keep => 2,
        };
        rank(&a.disposition)
            .cmp(&rank(&b.disposition))
            .then(b.size_bytes.cmp(&a.size_bytes))
            .then(a.title.cmp(&b.title))
    });

    let remove_count = insights
        .iter()
        .filter(|i| i.disposition == InsightDisposition::Remove)
        .count();
    let review_count = insights
        .iter()
        .filter(|i| i.disposition == InsightDisposition::Review)
        .count();
    let keep_count = insights
        .iter()
        .filter(|i| i.disposition == InsightDisposition::Keep)
        .count();
    let total_reclaimable = insights
        .iter()
        .filter(|i| i.disposition == InsightDisposition::Remove)
        .map(|i| i.size_bytes)
        .sum();

    InsightReport {
        total_reclaimable_bytes: total_reclaimable,
        remove_count,
        review_count,
        keep_count,
        generated_at: now,
        insights,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_size() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn test_disposition_thresholds() {
        assert_eq!(file_disposition(80), InsightDisposition::Remove);
        assert_eq!(file_disposition(50), InsightDisposition::Review);
        assert_eq!(file_disposition(10), InsightDisposition::Keep);
    }

    fn sample_file(size_bytes: u64, days_unused: i64, path: &str, category: FileCategory) -> FileRecord {
        crate::models::FileRecord {
            id: "test".to_string(),
            name: "sample.bin".to_string(),
            path: path.to_string(),
            parent_dir: "C:\\Downloads".to_string(),
            extension: "bin".to_string(),
            category,
            size_bytes,
            created_at: 0,
            modified_at: 0,
            accessed_at: 0,
            last_used_at: 0,
            last_used_source: "Modified mtime".to_string(),
            days_unused,
            relative_last_used: format!("Last opened: {} days ago", days_unused),
            impact_score: 0.0,
            tags: vec![],
            is_ignored: false,
        }
    }

    #[test]
    fn test_large_stale_installer_scores_high() {
        let f = sample_file(
            1024 * 1024 * 1024,
            500,
            "C:\\Users\\me\\Downloads\\setup.exe",
            FileCategory::Installer,
        );
        let (score, reasons) = score_file(&f);
        assert!(score >= 65, "score was {}", score);
        assert!(reasons.iter().any(|r| r.contains("Downloads")));
    }

    #[test]
    fn test_recent_small_file_scores_low() {
        let f = sample_file(
            6 * 1024 * 1024,
            5,
            "C:\\Users\\me\\Documents\\notes.docx",
            FileCategory::Document,
        );
        let (score, _) = score_file(&f);
        assert!(score < 65, "score was {}", score);
    }
}
