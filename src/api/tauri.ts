import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  AppCleanupResult,
  AppUsageRecord,
  CleanExecutionResult,
  CleanRequestItem,
  DefaultScanTarget,
  DeleteResult,
  FilePreviewInfo,
  ForensicsBatchEvent,
  ForensicsScanResult,
  QuickCleanScanResult,
  ScanProgressEvent,
  WhitelistConfig,
} from "../types/forensics";

export const api = {
  getDefaultTargets: () => invoke<DefaultScanTarget[]>("get_default_targets"),

  scanQuickClean: () => invoke<QuickCleanScanResult>("scan_quick_clean_cmd"),

  executeQuickClean: (items: CleanRequestItem[]) =>
    invoke<CleanExecutionResult>("execute_quick_clean_cmd", { items }),

  startForensicsScan: (
    scanId: string,
    targetPaths: string[],
    minSizeBytes: number
  ) =>
    invoke<ForensicsScanResult>("start_forensics_scan_cmd", {
      scanId,
      targetPaths,
      minSizeBytes,
    }),

  cancelForensicsScan: () => invoke<void>("cancel_forensics_scan_cmd"),

  scanInstalledApps: () => invoke<AppUsageRecord[]>("scan_installed_apps_cmd"),

  cleanupOrphanedApps: (keys: string[]) =>
    invoke<AppCleanupResult>("cleanup_orphaned_apps_cmd", { keys }),

  wiztreeStatus: () => invoke<string | null>("wiztree_status_cmd"),

  runTurboScan: (scanId: string, root: string, minSizeBytes: number) =>
    invoke<ForensicsScanResult>("run_turbo_scan_cmd", {
      scanId,
      root,
      minSizeBytes,
    }),

  revealInExplorer: (path: string) =>
    invoke<void>("reveal_in_explorer_cmd", { path }),

  openWithDefaultApp: (path: string) =>
    invoke<void>("open_with_default_app_cmd", { path }),

  quickPreview: (path: string) =>
    invoke<FilePreviewInfo>("quick_preview_cmd", { path }),

  deleteFiles: (paths: string[], permanentShred: boolean) =>
    invoke<DeleteResult>("delete_files_cmd", { paths, permanentShred }),

  getWhitelist: () => invoke<WhitelistConfig>("get_whitelist_cmd"),

  addToWhitelist: (path: string, isFolder: boolean) =>
    invoke<WhitelistConfig>("add_to_whitelist_cmd", { path, isFolder }),

  removeFromWhitelist: (path: string, isFolder: boolean) =>
    invoke<WhitelistConfig>("remove_from_whitelist_cmd", { path, isFolder }),

  pickFolder: async (): Promise<string | null> => {
    const selected = await openDialog({
      directory: true,
      multiple: false,
      title: "Select Directory for Deep Storage Forensics",
    });
    return typeof selected === "string" ? selected : null;
  },

  onScanProgress: (
    handler: (event: ScanProgressEvent) => void
  ): Promise<UnlistenFn> =>
    listen<ScanProgressEvent>("scan-progress", (e) => handler(e.payload)),

  onForensicsBatch: (
    handler: (event: ForensicsBatchEvent) => void
  ): Promise<UnlistenFn> =>
    listen<ForensicsBatchEvent>("forensics-batch", (e) => handler(e.payload)),
};
