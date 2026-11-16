# OptimizeMe

**Deep storage forensics & system hygiene for Windows, macOS and Linux — built for people who actually want their gigabytes back.**

[![Tauri](https://img.shields.io/badge/Tauri-v2-24C8DB?logo=tauri&logoColor=white)](https://tauri.app)
[![Rust](https://img.shields.io/badge/Rust-1.77%2B-000000?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=000000)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)](#requirements)

---

## Why OptimizeMe?

Most "cleaners" are surface-level: they empty `%TEMP%`, wipe a browser cache, and call it a day. The
space you actually want back is usually hiding in a handful of huge files you forgot existed — the
installer you ran once, the ISO for a laptop you no longer own, a 50 GB game you haven't opened since
last winter.

OptimizeMe combines **quick system hygiene** with **deep storage forensics**:

- **It does its own work.** The Unused Apps tracker doesn't just echo Windows' "Apps & features" list —
  it walks the filesystem, measures real on-disk footprints, and reads genuine launch history
  (`UserAssist` + `Prefetch`).
- **It shows you everything.** No hidden result caps, no silent size floors. If a file is the biggest
  thing on your drive, it will be at the top.
- **It cleans up after ghosts.** Apps you uninstalled months ago that left orphaned registry entries
  are detected and can be removed with one click.
- **It's fast.** A parallelised Rust scanning engine streams results in real time, with an optional
  WizTree/MFT turbo mode for whole-drive scans in seconds.

---

## Feature Overview

### Quick Clean — standard hygiene

One-click detection and cleanup, grouped into reviewable categories with exact byte counts:

| Category | What it covers |
| --- | --- |
| **OS Temporary Files** | `%TEMP%`, `C:\Windows\Temp`, `/tmp`, macOS caches |
| **Browser Caches** | Chrome, Edge, Brave, Firefox, Safari — logins/cookies preserved unless you explicitly opt in |
| **Crash Dumps & Error Reports** | Windows Error Reporting (WER), minidumps |
| **Application Logs** | Stale `.log`, `.dmp`, `.old` files |
| **Thumbnail & Icon Caches** | Explorer/Finder caches, regenerated on demand |
| **Recycle Bin / Trash** | Native `SHQueryRecycleBinW` / `SHEmptyRecycleBinW` on Windows, `.Trash`/XDG on Unix |

Every category is a checkbox with its own byte size, so you review before you delete.

### Deep Storage Forensics — the core feature

Point it at as many folders as you like (user directories, Program Files, whole drives — anything).
The engine walks them in parallel, streams results into a live sortable table, and surfaces the files
that matter:

- **Human-readable staleness** — *"Last opened: 1 year, 4 months ago"*, *"Never opened since download 8 months ago"*.
- **Space-Time Impact Score** — `size(MB) × days_unused^0.85`, so a 40 GB file untouched for 3 years
  outranks a 5 MB file untouched for a decade.
- **Smart tags** — `Download & Forget`, `Never Opened`, `Stale Giant`, `Forgotten Installer`, `Orphaned ISO`.
- **Dual sorting & filtering** — by size, by last-used, by impact; filter by type (installers,
  archives, media, disk images, documents) and by age (`30+ days`, `6+ months`, `1+ year`, `2+ years`).
- **No hidden limits** — every matching file is returned; a minimum-size filter is available including
  **"Any size (0 B+)"**.

#### Where the "last used" data comes from

Windows does not reliably track last-access time (`atime` is disabled by default on Windows 10/11), so
OptimizeMe combines multiple OS-level signals:

| Signal | What it tells us |
| --- | --- |
| **UserAssist** (`HKCU\…\Explorer\UserAssist`) | ROT13-decoded per-executable **launch counts + last execution time** — the strongest launch signal on Windows |
| **Prefetch** (`C:\Windows\Prefetch\*.pf`) | Executable run history (when available) |
| **File timestamps** | `atime` / `mtime` / `ctime` fallbacks, with explicit provenance shown per row |

Each row tells you which signal produced its timestamp, so you always know how trustworthy it is.

### Unused Applications & Binaries Tracker

This module was rebuilt to stop "copying Windows' homework":

- **Filesystem-first discovery** — enumerates real install roots (`Program Files`,
  `Program Files (x86)`, `%LOCALAPPDATA%\Programs`), verifies binaries actually exist, and computes
  the **full** on-disk footprint of each app (no truncated 600-file walks).
- **Registry cross-reference** — uses the Uninstall keys only for display metadata (name, publisher).
- **True launch history** — UserAssist + Prefetch, not file timestamps pretending to be launches.
- **Status classification** per app:

  | Status | Meaning |
  | --- | --- |
  | `Installed` | Install directory exists and contains a runnable binary |
  | `Broken` | Directory exists but the primary executable is gone |
  | `Orphaned` | Registry still lists it, but **every referenced path is missing** — it was already uninstalled |
  | `Unverified` | Registry entry with no verifiable path information |

- **One-click ghost cleanup** — orphaned entries show a **Remove entry** action (and a bulk
  *"Remove all N stale entries"* button). This deletes only the stale **registry key**; the files are
  already gone, so nothing of value is touched. Missing paths never crash the scan.

### Optional WizTree / MFT Turbo Scan

WizTree reads the **NTFS Master File Table** directly, so it can enumerate an entire drive in seconds
instead of walking the tree. When WizTree is detected, an **MFT Turbo Scan** button appears and uses
that export, merging rows with the same UserAssist/Prefetch launch signals.

- Auto-detected; nothing to configure.
- Parsed defensively (tolerant CSV schema handling).
- Any failure (not installed, unusual schema) falls back to the built-in parallel walker automatically.

> **Why not WinDirStat?** WinDirStat walks the directory tree just like our built-in scanner, so it
> offers no speed advantage here. The meaningful improvement is the MFT approach, which is what
> WizTree provides.

### Safe Actions & File Triage

- **Quick Look** preview — metadata, MIME hint, SHA-256 prefix, and a text snippet for text files.
- **Reveal in Explorer / Finder** before deleting anything.
- **Recycle Bin / Trash by default** — nothing is unrecoverable unless you opt in.
- **Permanent shred** toggle — zero-overwrite then unlink (with an explicit confirmation modal).
- **Whitelist / Ignore** — protect specific files or whole folders so they never clutter future scans.

---

## Requirements

| Requirement | Notes |
| --- | --- |
| **Rust** 1.77+ | `cargo` must be on `PATH` |
| **Node.js** 18+ | npm is used for the frontend |
| **Windows** | WebView2 Runtime (pre-installed on Win 10/11) + MSVC C++ Build Tools |
| **macOS** | Xcode Command Line Tools |
| **Linux** | `libwebkit2gtk-4.1-dev`, `libappindicator3-dev`, `librsvg2-dev` |

---

## Quick Start

```bash
git clone https://github.com/straculencuandrei/optimizeme.git
cd optimizeme
npm install
npm run tauri dev
```

Or use the bundled dev runner (auto-installs deps if missing, frees stale port `1420`, and starts
Vite HMR + Rust auto-reload):

```powershell
.\run-dev.ps1            # launch dev mode
.\run-dev.ps1 -Check     # TypeScript check + Rust unit tests
.\run-dev.ps1 -CleanTarget  # reclaim the Rust build cache
```

### Production build

```bash
npm run tauri build
```

Installers / bundles are emitted to `src-tauri/target/release/bundle/`.

### Verification

```bash
npx tsc --noEmit                                             # frontend type-check
cargo test --manifest-path src-tauri/Cargo.toml --lib        # backend unit tests
npm run build                                                # tsc + Vite production bundle
```

---

## Architecture

```
optimizeme/
├── src/                         # React 19 + TypeScript frontend
│   ├── App.tsx                  # application shell, state, scan orchestration
│   ├── api/tauri.ts             # typed wrappers around every Tauri command
│   ├── types/forensics.ts       # shared data contracts
│   ├── utils/format.ts          # byte/size formatting, category & severity metadata
│   └── components/
│       ├── Sidebar.tsx          # navigation + shred toggle + session stats
│       ├── TopBar.tsx           # reclaimable summary + scan progress / cancel
│       ├── QuickCleanView.tsx   # category checkboxes & cleanup execution
│       ├── ForensicsView.tsx    # live sortable deep-scan table, breakdown bar, bulk actions
│       ├── AppsTrackerView.tsx  # installed / orphaned app analysis & cleanup
│       ├── WhitelistView.tsx    # ignored files & folders
│       └── QuickLookModal.tsx   # per-file preview
└── src-tauri/                   # Rust backend (Tauri v2)
    └── src/
        ├── lib.rs               # Tauri builder, command registration, shared state
        ├── models.rs            # serialised DTOs (serde camelCase)
        ├── forensics.rs         # deep scanner + installed-app engine + orphan cleanup
        ├── os_metadata.rs       # UserAssist / Prefetch / Recent signals, timestamps, scoring
        ├── mft.rs               # optional WizTree MFT turbo-scan integration
        ├── quick_clean.rs       # junk scanners & purge engine
        └── actions.rs           # reveal / preview / trash / shred / whitelist persistence
```

### Performance model

- All filesystem work runs on **Rust worker threads** inside `tokio::task::spawn_blocking`, never on
  the UI thread.
- Directory recursion fans out with **`rayon`** parallel iterators.
- Metadata is read with `symlink_metadata`, skipping reparse points and symlinks to avoid loops.
- Results stream to the frontend as `scan-progress` / `forensics-batch` events, so the table fills in
  live while the scan is still running.
- A shared `AtomicBool` cancel flag lets the UI abort a scan instantly.

### Tauri command surface

| Command | Purpose |
| --- | --- |
| `get_default_targets` | Discover scannable roots (user dirs, Program Files, drives…) |
| `scan_quick_clean_cmd` / `execute_quick_clean_cmd` | Scan & purge junk categories |
| `start_forensics_scan_cmd` / `cancel_forensics_scan_cmd` | Streamed deep scans |
| `scan_installed_apps_cmd` | Filesystem + registry + launch-history app analysis |
| `cleanup_orphaned_apps_cmd` | Delete stale registry entries for already-uninstalled apps |
| `wiztree_status_cmd` / `run_turbo_scan_cmd` | Optional WizTree MFT turbo scan |
| `reveal_in_explorer_cmd` / `open_with_default_app_cmd` | Safe navigation |
| `quick_preview_cmd` | Metadata + text-snippet preview |
| `delete_files_cmd` | Recycle Bin move or permanent shred |
| `get_/add_/remove_whitelist_cmd` | Persistent ignore list |

---

## Safety Model

1. **Recycle Bin first.** The default delete action moves files to the OS trash — fully recoverable.
2. **Shred is opt-in and confirmed.** It overwrites with zeros before unlinking and always requires a
   second confirmation in the UI.
3. **Whitelist is durable.** Ignored files/folders are stored in `whitelist.json` under the app data
   directory and re-applied on every future scan.
4. **Protected system directories are skipped** (`$Recycle.Bin`, `System Volume Information`,
   `WinSxS`, `Recovery`) so a deep scan can never offer to nuke boot-critical data.
5. **Orphan cleanup only touches the registry key** of an entry whose paths have already vanished.

---

## Configuration

The persistent whitelist lives at the platform app-data directory:

| OS | Path |
| --- | --- |
| Windows | `%APPDATA%\com.optimizeme.app\whitelist.json` |
| macOS | `~/Library/Application Support/com.optimizeme.app/whitelist.json` |
| Linux | `~/.local/share/com.optimizeme.app/whitelist.json` |

```json
{
  "ignoredFiles": ["C:\\Users\\me\\keep-me.zip"],
  "ignoredFolders": ["D:\\Projects"]
}
```

---

## Roadmap

- [ ] Export scan results to CSV / JSON
- [ ] Duplicate-file detection (size → partial hash → full hash)
- [ ] Scheduled background hygiene reports
- [ ] Per-directory savings history over time
- [ ] Linux AppImage / Flatpak packaging

---

## License

Released under the [MIT License](LICENSE). © 2026 Andrei Straculencu.
