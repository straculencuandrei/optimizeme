use crate::models::{DeleteResult, FailedAction, FilePreviewInfo, WhitelistConfig};
use crate::os_metadata::system_time_to_epoch;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;

/// Strips surrounding quotes and trailing path separators (keeping drive roots like `C:\`).
fn normalize_reveal_path(path: &str) -> String {
    let mut p = path.trim().trim_matches('"').to_string();
    while p.len() > 3 && (p.ends_with('\\') || p.ends_with('/')) {
        p.pop();
    }
    p
}

pub fn reveal_in_explorer(path: &str) -> Result<(), String> {
    let target = normalize_reveal_path(path);
    let p = Path::new(&target);
    if !p.exists() {
        return Err(format!("Path does not exist: {}", path));
    }

    #[cfg(target_os = "windows")]
    {
        // `/select,` selects a file inside its parent folder and opens that folder. For a
        // directory we open the directory itself so the user lands directly inside it, which
        // avoids Explorer wandering off to an unrelated folder.
        let mut cmd = Command::new("explorer");
        if p.is_dir() {
            cmd.arg(&target);
        } else {
            cmd.arg(format!("/select,{}", target));
        }
        cmd.spawn()
            .map_err(|e| format!("Failed to launch Explorer: {}", e))?;
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .args(["-R", target.as_str()])
            .spawn()
            .map_err(|e| format!("Failed to reveal in Finder: {}", e))?;
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let open_target = if p.is_dir() { p } else { p.parent().unwrap_or(p) };
        Command::new("xdg-open")
            .arg(open_target)
            .spawn()
            .map_err(|e| format!("Failed to open file manager: {}", e))?;
        return Ok(());
    }
}

pub fn open_with_default_app(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(format!("File not found: {}", path));
    }
    open::that(p).map_err(|e| format!("Failed to open file: {}", e))
}

pub fn quick_preview(path: &str) -> Result<FilePreviewInfo, String> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(format!("File does not exist: {}", path));
    }

    let meta = fs::metadata(p).map_err(|e| format!("Cannot read metadata: {}", e))?;
    let size_bytes = meta.len();
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let extension = p
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let created_at = system_time_to_epoch(meta.created()).unwrap_or(0);
    let modified_at = system_time_to_epoch(meta.modified()).unwrap_or(0);
    let accessed_at = system_time_to_epoch(meta.accessed()).unwrap_or(0);

    let mime_hint = match extension.as_str() {
        "exe" | "msi" | "dmg" | "pkg" | "deb" => "Executable / Installer",
        "zip" | "rar" | "7z" | "tar" | "gz" => "Compressed Archive",
        "mp4" | "mkv" | "mov" | "avi" | "webm" => "Video Stream",
        "mp3" | "wav" | "flac" => "Audio Track",
        "iso" | "img" | "vhd" | "vhdx" => "Disk Image",
        "pdf" => "PDF Document",
        "png" | "jpg" | "jpeg" | "webp" | "gif" => "Raster Image",
        "txt" | "md" | "log" | "json" | "yaml" | "yml" | "toml" | "csv" | "rs" | "ts" | "tsx"
        | "js" | "py" | "html" | "css" => "Plain Text / Source",
        _ => "Binary / Data File",
    }
    .to_string();

    let mut text_snippet = None;
    let mut is_binary = true;
    let mut sha256_prefix = None;

    if let Ok(mut file) = File::open(p) {
        let mut buf = vec![0u8; 4096];
        if let Ok(n) = file.read(&mut buf) {
            let slice = &buf[..n];
            let mut hasher = Sha256::new();
            hasher.update(slice);
            let digest = hasher.finalize();
            sha256_prefix = Some(format!("{:x}", digest)[..16].to_string());

            let has_null = slice.contains(&0);
            if !has_null {
                if let Ok(text) = std::str::from_utf8(slice) {
                    is_binary = false;
                    text_snippet = Some(text.chars().take(1800).collect());
                }
            }
        }
    }

    Ok(FilePreviewInfo {
        path: path.to_string(),
        name,
        extension,
        size_bytes,
        mime_hint,
        text_snippet,
        is_binary,
        created_at,
        modified_at,
        accessed_at,
        sha256_prefix,
    })
}

fn secure_shred_file(path: &Path) -> Result<(), String> {
    let len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if len > 0 {
        // Overwrite first up to 16 MB in 64KB zero blocks + full overwrite if <= 64 MB
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            let max_overwrite = len.min(64 * 1024 * 1024);
            let zeros = [0u8; 65536];
            let mut written = 0u64;
            let _ = file.seek(SeekFrom::Start(0));
            while written < max_overwrite {
                let to_write = ((max_overwrite - written) as usize).min(zeros.len());
                if file.write_all(&zeros[..to_write]).is_err() {
                    break;
                }
                written += to_write as u64;
            }
            let _ = file.sync_all();
        }
    }
    fs::remove_file(path).map_err(|e| format!("Failed to remove file: {}", e))
}

pub fn delete_files(paths: Vec<String>, permanent_shred: bool) -> DeleteResult {
    let mut deleted_paths = Vec::new();
    let mut freed_bytes = 0u64;
    let mut failed = Vec::new();

    for p_str in paths {
        let p = Path::new(&p_str);
        if !p.exists() {
            failed.push(FailedAction {
                path: p_str,
                reason: "File or directory no longer exists".to_string(),
            });
            continue;
        }

        let size = fs::metadata(p).map(|m| m.len()).unwrap_or(0);

        let res = if permanent_shred {
            if p.is_dir() {
                fs::remove_dir_all(p).map_err(|e| e.to_string())
            } else {
                secure_shred_file(p)
            }
        } else {
            trash::delete(p).map_err(|e| format!("Recycle Bin move failed: {}", e))
        };

        match res {
            Ok(_) => {
                freed_bytes += size;
                deleted_paths.push(p_str);
            }
            Err(reason) => {
                failed.push(FailedAction { path: p_str, reason });
            }
        }
    }

    DeleteResult {
        deleted_paths,
        freed_bytes,
        failed,
        shredded: permanent_shred,
    }
}

pub fn load_whitelist(path: &Path) -> WhitelistConfig {
    if let Ok(data) = fs::read_to_string(path) {
        if let Ok(cfg) = serde_json::from_str::<WhitelistConfig>(&data) {
            return cfg;
        }
    }
    WhitelistConfig::default()
}

pub fn save_whitelist(path: &Path, cfg: &WhitelistConfig) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_reveal_path() {
        // Drive roots are preserved.
        assert_eq!(normalize_reveal_path("C:\\"), "C:\\");
        assert_eq!(normalize_reveal_path("C:/"), "C:/");
        // Trailing separators are stripped so Explorer's /select, works.
        assert_eq!(
            normalize_reveal_path("C:\\Program Files\\"),
            "C:\\Program Files"
        );
        assert_eq!(
            normalize_reveal_path("C:\\Program Files\\Epic Games\\Launcher\\"),
            "C:\\Program Files\\Epic Games\\Launcher"
        );
        // Surrounding quotes and whitespace are trimmed.
        assert_eq!(
            normalize_reveal_path("\"C:\\Program Files\\\\\""),
            "C:\\Program Files"
        );
        assert_eq!(normalize_reveal_path("  /home/user/  "), "/home/user");
    }
}
