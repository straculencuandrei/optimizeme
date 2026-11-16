import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertCircle, CheckCircle2, Flame, X } from "lucide-react";
import { api } from "./api/tauri";
import {
  AppUsageRecord,
  CleanExecutionResult,
  CleanRequestItem,
  DefaultScanTarget,
  FilePreviewInfo,
  FileRecord,
  ForensicsScanResult,
  Insight,
  InsightReport,
  NavTab,
  QuickCleanScanResult,
  ScanProgressEvent,
  WhitelistConfig,
} from "./types/forensics";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { QuickCleanView } from "./components/QuickCleanView";
import { ForensicsView } from "./components/ForensicsView";
import { AppsTrackerView } from "./components/AppsTrackerView";
import { WhitelistView } from "./components/WhitelistView";
import { InsightsView } from "./components/InsightsView";
import { QuickLookModal } from "./components/QuickLookModal";
import { formatBytes } from "./utils/format";

interface ToastMessage {
  id: number;
  kind: "success" | "error";
  text: string;
}

export function App() {
  const [activeTab, setActiveTab] = useState<NavTab>("forensics");
  const [permanentShred, setPermanentShred] = useState(false);
  const [sessionFreedBytes, setSessionFreedBytes] = useState(0);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  // Quick Clean state
  const [quickResult, setQuickResult] = useState<QuickCleanScanResult | null>(null);
  const [quickSelectedIds, setQuickSelectedIds] = useState<Set<string>>(new Set());
  const [quickCookieIds, setQuickCookieIds] = useState<Set<string>>(new Set());
  const [isQuickScanning, setIsQuickScanning] = useState(false);
  const [isQuickCleaning, setIsQuickCleaning] = useState(false);
  const [cleanResult, setCleanResult] = useState<CleanExecutionResult | null>(null);

  // Forensics state
  const [defaultTargets, setDefaultTargets] = useState<DefaultScanTarget[]>([]);
  const [selectedTargetPaths, setSelectedTargetPaths] = useState<string[]>([]);
  const [customTargetPaths, setCustomTargetPaths] = useState<string[]>([]);
  const [minSizeBytes, setMinSizeBytes] = useState<number>(1024 * 1024); // 1 MB+
  const [isForensicsScanning, setIsForensicsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgressEvent | null>(null);
  const [forensicsResult, setForensicsResult] = useState<ForensicsScanResult | null>(null);
  const [streamedFiles, setStreamedFiles] = useState<FileRecord[]>([]);
  const activeScanIdRef = useRef<string>("");

  // Apps Tracker state
  const [apps, setApps] = useState<AppUsageRecord[]>([]);
  const [isAppsScanning, setIsAppsScanning] = useState(false);

  // WizTree (MFT turbo scan) availability
  const [wiztreePath, setWiztreePath] = useState<string | null>(null);

  // Insights / recommendations state
  const [insightReport, setInsightReport] = useState<InsightReport | null>(null);
  const [isInsightsScanning, setIsInsightsScanning] = useState(false);
  const [applyingInsightIds, setApplyingInsightIds] = useState<Set<string>>(
    new Set()
  );

  // Whitelist state
  const [whitelist, setWhitelist] = useState<WhitelistConfig>({
    ignoredFiles: [],
    ignoredFolders: [],
  });

  // Quick Look state
  const [previewFile, setPreviewFile] = useState<FileRecord | null>(null);
  const [previewInfo, setPreviewInfo] = useState<FilePreviewInfo | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  // Shred confirmation modal state
  const [pendingShredPaths, setPendingShredPaths] = useState<string[] | null>(null);

  const pushToast = useCallback((kind: "success" | "error", text: string) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev.slice(-3), { id, kind, text }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4500);
  }, []);

  // Load initial defaults & subscribe to Rust real-time streaming events
  useEffect(() => {
    api
      .getDefaultTargets()
      .then((targets) => {
        setDefaultTargets(targets);
        // Pre-select a broad set of user + program directories by default (everything except
        // whole-drive roots, which are intentionally opt-in since they are huge).
        const DEFAULT_SELECTED_IDS = new Set([
          "downloads",
          "desktop",
          "documents",
          "videos",
          "pictures",
          "appdata_local",
          "appdata_roaming",
          "program_files",
          "program_files_x86",
          "program_data",
          "public",
        ]);
        const defaults = targets
          .filter((t) => t.exists && DEFAULT_SELECTED_IDS.has(t.id))
          .map((t) => t.path);
        setSelectedTargetPaths(defaults);
      })
      .catch((err) => pushToast("error", String(err)));

    api
      .getWhitelist()
      .then(setWhitelist)
      .catch(() => {});

    api
      .wiztreeStatus()
      .then(setWiztreePath)
      .catch(() => {});

    let unlistenProgress: (() => void) | null = null;
    let unlistenBatch: (() => void) | null = null;

    api
      .onScanProgress((ev) => {
        if (ev.scanId === activeScanIdRef.current) {
          setScanProgress(ev);
        }
      })
      .then((fn) => {
        unlistenProgress = fn;
      });

    api
      .onForensicsBatch((batch) => {
        if (batch.scanId === activeScanIdRef.current) {
          setStreamedFiles((prev) => {
            if (prev.length >= 20000) return prev;
            const seen = new Set(prev.map((f) => f.id));
            const unique = batch.files.filter((f) => {
              if (seen.has(f.id)) return false;
              seen.add(f.id);
              return true;
            });
            return unique.length > 0 ? prev.concat(unique) : prev;
          });
        }
      })
      .then((fn) => {
        unlistenBatch = fn;
      });

    return () => {
      unlistenProgress?.();
      unlistenBatch?.();
    };
  }, [pushToast]);

  // Quick Clean handlers
  const handleRunQuickScan = useCallback(async () => {
    setIsQuickScanning(true);
    setCleanResult(null);
    try {
      const res = await api.scanQuickClean();
      setQuickResult(res);
      setQuickSelectedIds(
        new Set(
          res.categories
            .filter((c) => c.enabledByDefault && c.sizeBytes > 0)
            .map((c) => c.id)
        )
      );
    } catch (err) {
      pushToast("error", `Quick scan failed: ${String(err)}`);
    } finally {
      setIsQuickScanning(false);
    }
  }, [pushToast]);

  const handleExecuteQuickClean = useCallback(
    async (items: CleanRequestItem[]) => {
      setIsQuickCleaning(true);
      try {
        const res = await api.executeQuickClean(items);
        setCleanResult(res);
        setSessionFreedBytes((s) => s + res.freedBytes);
        pushToast(
          "success",
          `Cleaned ${res.deletedCount} items (${formatBytes(res.freedBytes)} reclaimed)`
        );
        // Re-scan to refresh remaining sizes
        const updated = await api.scanQuickClean();
        setQuickResult(updated);
      } catch (err) {
        pushToast("error", `Clean error: ${String(err)}`);
      } finally {
        setIsQuickCleaning(false);
      }
    },
    [pushToast]
  );

  // Forensics handlers
  const handleRunForensics = useCallback(async () => {
    const targets = Array.from(
      new Set([...selectedTargetPaths, ...customTargetPaths])
    );
    if (targets.length === 0) {
      pushToast("error", "Select at least one directory to scan.");
      return;
    }

    const scanId = `scan_${Date.now()}`;
    activeScanIdRef.current = scanId;
    setIsForensicsScanning(true);
    setForensicsResult(null);
    setStreamedFiles([]);
    setScanProgress({
      scanId,
      phase: "initializing",
      scannedFiles: 0,
      scannedBytes: 0,
      currentPath: targets[0],
      completed: false,
    });

    try {
      const res = await api.startForensicsScan(scanId, targets, minSizeBytes);
      if (activeScanIdRef.current === scanId) {
        setForensicsResult(res);
        setStreamedFiles([]);
        pushToast(
          "success",
          `Indexed ${res.totalFilesScanned.toLocaleString()} files in ${(
            res.durationMs / 1000
          ).toFixed(2)}s`
        );
      }
    } catch (err) {
      pushToast("error", `Forensics scan failed: ${String(err)}`);
    } finally {
      setIsForensicsScanning(false);
    }
  }, [selectedTargetPaths, customTargetPaths, minSizeBytes, pushToast]);

  const handleCancelScan = useCallback(async () => {
    await api.cancelForensicsScan();
    setIsForensicsScanning(false);
    pushToast("error", "Scan cancelled.");
  }, [pushToast]);

  const handleScanApps = useCallback(async () => {
    setIsAppsScanning(true);
    try {
      const list = await api.scanInstalledApps();
      setApps(list);
      pushToast("success", `Analyzed ${list.length} installed applications.`);
    } catch (err) {
      pushToast("error", `App tracker failed: ${String(err)}`);
    } finally {
      setIsAppsScanning(false);
    }
  }, [pushToast]);

  const handleCleanupOrphans = useCallback(
    async (keys: string[]) => {
      if (keys.length === 0) return;
      try {
        const res = await api.cleanupOrphanedApps(keys);
        if (res.removedKeys.length > 0) {
          setApps((prev) =>
            prev.filter(
              (a) => !a.registryPath || !res.removedKeys.includes(a.registryPath)
            )
          );
          pushToast(
            "success",
            `Removed ${res.removedKeys.length} stale registry ${
              res.removedKeys.length === 1 ? "entry" : "entries"
            } for already-uninstalled apps.`
          );
        }
        if (res.failed.length > 0) {
          pushToast(
            "error",
            `${res.failed.length} failed: ${res.failed[0].reason}`
          );
        }
      } catch (err) {
        pushToast("error", String(err));
      }
    },
    [pushToast]
  );

  const handleRunTurboScan = useCallback(
    async (root: string) => {
      const scanId = `turbo_${Date.now()}`;
      activeScanIdRef.current = scanId;
      setIsForensicsScanning(true);
      setForensicsResult(null);
      setStreamedFiles([]);
      setScanProgress({
        scanId,
        phase: "turbo",
        scannedFiles: 0,
        scannedBytes: 0,
        currentPath: root,
        completed: false,
      });
      try {
        const res = await api.runTurboScan(scanId, root, minSizeBytes);
        if (activeScanIdRef.current === scanId) {
          setForensicsResult(res);
          setStreamedFiles([]);
          pushToast(
            "success",
            `MFT turbo scan indexed ${res.totalFilesScanned.toLocaleString()} files in ${(
              res.durationMs / 1000
            ).toFixed(2)}s`
          );
        }
      } catch (err) {
        pushToast("error", `Turbo scan failed: ${String(err)}`);
      } finally {
        setIsForensicsScanning(false);
      }
    },
    [minSizeBytes, pushToast]
  );

  const handleRunInsights = useCallback(async () => {
    setIsInsightsScanning(true);
    setInsightReport(null);
    try {
      const report = await api.generateInsights();
      setInsightReport(report);
      pushToast(
        "success",
        `Generated ${report.insights.length} recommendations (${formatBytes(
          report.totalReclaimableBytes
        )} reclaimable).`
      );
    } catch (err) {
      pushToast("error", `Insights failed: ${String(err)}`);
    } finally {
      setIsInsightsScanning(false);
    }
  }, [pushToast]);

  // Actions
  const handleQuickLook = useCallback(async (file: FileRecord) => {
    setPreviewFile(file);
    setPreviewInfo(null);
    setPreviewLoading(true);
    try {
      const info = await api.quickPreview(file.path);
      setPreviewInfo(info);
    } catch {
      setPreviewInfo(null);
    } finally {
      setPreviewLoading(false);
    }
  }, []);

  const handleReveal = useCallback(
    async (path: string) => {
      try {
        await api.revealInExplorer(path);
      } catch (err) {
        pushToast("error", String(err));
      }
    },
    [pushToast]
  );

  const handleOpenDefault = useCallback(
    async (path: string) => {
      try {
        await api.openWithDefaultApp(path);
      } catch (err) {
        pushToast("error", String(err));
      }
    },
    [pushToast]
  );

  const handleIgnoreFile = useCallback(
    async (path: string) => {
      try {
        const updated = await api.addToWhitelist(path, false);
        setWhitelist(updated);
        setForensicsResult((prev) =>
          prev
            ? { ...prev, files: prev.files.filter((f) => f.path !== path) }
            : prev
        );
        setStreamedFiles((prev) => prev.filter((f) => f.path !== path));
        pushToast("success", "Added to Whitelist — protected from future scans.");
      } catch (err) {
        pushToast("error", String(err));
      }
    },
    [pushToast]
  );

  const executeDeletion = useCallback(
    async (paths: string[], shred: boolean) => {
      try {
        const res = await api.deleteFiles(paths, shred);
        if (res.deletedPaths.length > 0) {
          const deletedSet = new Set(res.deletedPaths);
          setForensicsResult((prev) =>
            prev
              ? {
                  ...prev,
                  files: prev.files.filter((f) => !deletedSet.has(f.path)),
                  reclaimableBytes: Math.max(
                    0,
                    prev.reclaimableBytes - res.freedBytes
                  ),
                }
              : prev
          );
          setStreamedFiles((prev) =>
            prev.filter((f) => !deletedSet.has(f.path))
          );
          setSessionFreedBytes((s) => s + res.freedBytes);
          pushToast(
            "success",
            `${shred ? "Shredded" : "Moved to Trash"} ${
              res.deletedPaths.length
            } file(s) • ${formatBytes(res.freedBytes)} freed`
          );
        }
        if (res.failed.length > 0) {
          pushToast(
            "error",
            `${res.failed.length} file(s) failed: ${res.failed[0].reason}`
          );
        }
      } catch (err) {
        pushToast("error", String(err));
      }
    },
    [pushToast]
  );

  const handleDeleteRequest = useCallback(
    (paths: string[]) => {
      if (paths.length === 0) return;
      if (permanentShred) {
        setPendingShredPaths(paths);
      } else {
        executeDeletion(paths, false);
      }
    },
    [permanentShred, executeDeletion]
  );

  // Apply a batch of insights (files, junk categories, and orphan registry entries).
  const applyInsights = useCallback(
    async (list: Insight[]) => {
      if (list.length === 0) return;
      const files = list
        .filter((i) => i.action === "delete_file" && i.path)
        .map((i) => i.path as string);
      const orphanKeys = list
        .filter((i) => i.action === "remove_registry_entry" && i.registryPath)
        .map((i) => i.registryPath as string);
      const junkIds = list
        .filter((i) => i.action === "clean_junk" && i.categoryId)
        .map((i) => i.categoryId as string);

      setApplyingInsightIds(new Set(list.map((i) => i.id)));
      try {
        if (files.length > 0) await executeDeletion(files, permanentShred);
        if (orphanKeys.length > 0) await handleCleanupOrphans(orphanKeys);
        if (junkIds.length > 0) {
          const res = await api.scanQuickClean();
          const items: CleanRequestItem[] = res.categories
            .filter((c) => junkIds.includes(c.id))
            .map((c) => ({
              categoryId: c.id,
              targetPaths: c.targetPaths,
              includeCookies: false,
              cookiePaths: c.cookiePaths,
              isRecycleBin: c.isRecycleBin,
            }));
          if (items.length > 0) {
            const r = await api.executeQuickClean(items);
            setSessionFreedBytes((s) => s + r.freedBytes);
            pushToast(
              "success",
              `Cleaned ${items.length} junk ${
                items.length === 1 ? "category" : "categories"
              } (${formatBytes(r.freedBytes)} reclaimed).`
            );
          }
        }
        const applied = new Set(list.map((i) => i.id));
        setInsightReport((prev) =>
          prev
            ? {
                ...prev,
                insights: prev.insights.filter((i) => !applied.has(i.id)),
              }
            : prev
        );
      } catch (err) {
        pushToast("error", String(err));
      } finally {
        setApplyingInsightIds((prev) => {
          const next = new Set(prev);
          list.forEach((i) => next.delete(i.id));
          return next;
        });
      }
    },
    [permanentShred, executeDeletion, handleCleanupOrphans, pushToast]
  );

  const handleApplyInsight = useCallback(
    (insight: Insight) => {
      applyInsights([insight]);
    },
    [applyInsights]
  );

  const handleApplyAllInsights = useCallback(() => {
    if (!insightReport) return;
    applyInsights(
      insightReport.insights.filter((i) => i.disposition === "remove")
    );
  }, [insightReport, applyInsights]);

  // Total Reclaimable calculation for TopBar
  const totalReclaimable = useMemo(() => {
    const quickBytes = quickResult?.totalReclaimableBytes ?? 0;
    const forensicsBytes = forensicsResult?.reclaimableBytes ?? 0;
    if (activeTab === "quick_clean") return quickBytes;
    if (activeTab === "apps") {
      return apps
        .filter((a) => a.isBloatedUnused)
        .reduce((s, a) => s + a.estimatedSizeBytes, 0);
    }
    if (activeTab === "insights") {
      return insightReport?.totalReclaimableBytes ?? 0;
    }
    return forensicsBytes + quickBytes;
  }, [activeTab, quickResult, forensicsResult, apps, insightReport]);

  const anyScanning =
    isQuickScanning || isForensicsScanning || isAppsScanning || isInsightsScanning;

  const handlePrimaryScan = () => {
    if (activeTab === "quick_clean") handleRunQuickScan();
    else if (activeTab === "apps") handleScanApps();
    else if (activeTab === "insights") handleRunInsights();
    else handleRunForensics();
  };

  return (
    <div className="h-screen w-screen bg-[#0D0F12] text-[#F1F5F9] flex overflow-hidden">
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        permanentShred={permanentShred}
        onToggleShred={setPermanentShred}
        sessionFreedBytes={sessionFreedBytes}
        whitelistCount={
          whitelist.ignoredFiles.length + whitelist.ignoredFolders.length
        }
        isScanning={anyScanning}
      />

      <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
        <TopBar
          activeTab={activeTab}
          reclaimableBytes={totalReclaimable}
          isScanning={anyScanning}
          scanProgress={scanProgress}
          onPrimaryScan={handlePrimaryScan}
          onCancelScan={handleCancelScan}
        />

        <main className="flex-1 min-h-0 overflow-auto">
          {activeTab === "quick_clean" && (
            <QuickCleanView
              scanResult={quickResult}
              selectedIds={quickSelectedIds}
              cookieToggleIds={quickCookieIds}
              isScanning={isQuickScanning}
              isCleaning={isQuickCleaning}
              cleanResult={cleanResult}
              onToggleCategory={(id) =>
                setQuickSelectedIds((prev) => {
                  const next = new Set(prev);
                  if (next.has(id)) next.delete(id);
                  else next.add(id);
                  return next;
                })
              }
              onToggleCookies={(id) =>
                setQuickCookieIds((prev) => {
                  const next = new Set(prev);
                  if (next.has(id)) next.delete(id);
                  else next.add(id);
                  return next;
                })
              }
              onSelectAll={(select) => {
                if (!quickResult) return;
                setQuickSelectedIds(
                  select
                    ? new Set(quickResult.categories.map((c) => c.id))
                    : new Set()
                );
              }}
              onRunScan={handleRunQuickScan}
              onExecuteClean={handleExecuteQuickClean}
            />
          )}

          {activeTab === "insights" && (
            <InsightsView
              report={insightReport}
              isScanning={isInsightsScanning}
              permanentShred={permanentShred}
              applyingIds={applyingInsightIds}
              onRun={handleRunInsights}
              onApply={handleApplyInsight}
              onApplyAll={handleApplyAllInsights}
              onReveal={handleReveal}
            />
          )}

          {activeTab === "forensics" && (
            <ForensicsView
              defaultTargets={defaultTargets}
              selectedTargetPaths={selectedTargetPaths}
              customTargetPaths={customTargetPaths}
              minSizeBytes={minSizeBytes}
              isScanning={isForensicsScanning}
              scanResult={forensicsResult}
              streamedFiles={streamedFiles}
              permanentShred={permanentShred}
              wiztreePath={wiztreePath}
              onToggleTargetPath={(path) =>
                setSelectedTargetPaths((prev) =>
                  prev.includes(path)
                    ? prev.filter((p) => p !== path)
                    : [...prev, path]
                )
              }
              onAddCustomPath={async () => {
                const picked = await api.pickFolder();
                if (
                  picked &&
                  !customTargetPaths.includes(picked) &&
                  !selectedTargetPaths.includes(picked)
                ) {
                  setCustomTargetPaths((prev) => [...prev, picked]);
                }
              }}
              onRemoveCustomPath={(path) =>
                setCustomTargetPaths((prev) => prev.filter((p) => p !== path))
              }
              onChangeMinSize={setMinSizeBytes}
              onRunScan={handleRunForensics}
              onRunTurboScan={handleRunTurboScan}
              onQuickLook={handleQuickLook}
              onReveal={handleReveal}
              onIgnoreFile={handleIgnoreFile}
              onDeleteFiles={handleDeleteRequest}
            />
          )}

          {activeTab === "apps" && (
            <AppsTrackerView
              apps={apps}
              isScanning={isAppsScanning}
              onRunScan={handleScanApps}
              onReveal={handleReveal}
              onCleanupOrphans={handleCleanupOrphans}
            />
          )}

          {activeTab === "whitelist" && (
            <WhitelistView
              whitelist={whitelist}
              onAddIgnoredFolder={async () => {
                const picked = await api.pickFolder();
                if (picked) {
                  const updated = await api.addToWhitelist(picked, true);
                  setWhitelist(updated);
                  pushToast("success", `Excluded folder: ${picked}`);
                }
              }}
              onRemoveItem={async (path, isFolder) => {
                const updated = await api.removeFromWhitelist(path, isFolder);
                setWhitelist(updated);
              }}
            />
          )}
        </main>
      </div>

      {/* Quick Look Modal */}
      <QuickLookModal
        file={previewFile}
        preview={previewInfo}
        loading={previewLoading}
        permanentShred={permanentShred}
        onClose={() => setPreviewFile(null)}
        onReveal={handleReveal}
        onOpenDefault={handleOpenDefault}
        onWhitelist={handleIgnoreFile}
        onDelete={(path) => handleDeleteRequest([path])}
      />

      {/* Permanent Shred Confirmation Modal */}
      <AnimatePresence>
        {pendingShredPaths && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="max-w-md w-full rounded-2xl bg-[#161920] border border-red-500/35 p-6 shadow-2xl"
            >
              <div className="flex items-center gap-3 text-red-400 mb-3">
                <div className="w-10 h-10 rounded-xl bg-red-500/15 border border-red-500/30 flex items-center justify-center">
                  <Flame className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-[15px] font-semibold text-white">
                    Confirm Permanent Shred
                  </h3>
                  <p className="text-[12px] text-red-300/80">
                    This bypasses the Recycle Bin and cannot be undone.
                  </p>
                </div>
              </div>
              <p className="text-[12.5px] text-slate-300 leading-relaxed mb-5">
                {pendingShredPaths.length} file(s) will be overwritten with zeros and permanently unlinked from disk.
              </p>
              <div className="flex items-center justify-end gap-2.5">
                <button
                  onClick={() => setPendingShredPaths(null)}
                  className="px-4 py-2 rounded-xl bg-white/[0.06] hover:bg-white/[0.1] text-[12.5px] font-medium text-slate-200 cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    const targets = pendingShredPaths;
                    setPendingShredPaths(null);
                    executeDeletion(targets, true);
                  }}
                  className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-[12.5px] font-semibold cursor-pointer"
                >
                  Shred Permanently
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Toast Notifications */}
      <div className="fixed bottom-5 right-5 z-50 space-y-2 pointer-events-none">
        <AnimatePresence>
          {toasts.map((t) => (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 12, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.96 }}
              className={`pointer-events-auto px-4 py-2.5 rounded-xl border shadow-xl flex items-center gap-2.5 text-[12.5px] font-medium backdrop-blur-md ${
                t.kind === "success"
                  ? "bg-[#161920]/95 border-emerald-500/35 text-emerald-200"
                  : "bg-[#161920]/95 border-red-500/35 text-red-200"
              }`}
            >
              {t.kind === "success" ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              )}
              <span>{t.text}</span>
              <button
                onClick={() =>
                  setToasts((prev) => prev.filter((item) => item.id !== t.id))
                }
                className="text-slate-500 hover:text-white ml-1 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}

export default App;
