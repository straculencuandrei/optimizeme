import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  CheckSquare,
  Square,
  Globe,
  HardDrive,
  FileWarning,
  Trash2,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  Sparkles,
  CheckCircle2,
} from "lucide-react";
import {
  CleanExecutionResult,
  CleanRequestItem,
  QuickCleanCategory,
  QuickCleanScanResult,
} from "../types/forensics";
import { formatBytes } from "../utils/format";

interface QuickCleanViewProps {
  scanResult: QuickCleanScanResult | null;
  selectedIds: Set<string>;
  cookieToggleIds: Set<string>;
  isScanning: boolean;
  isCleaning: boolean;
  cleanResult: CleanExecutionResult | null;
  onToggleCategory: (id: string) => void;
  onToggleCookies: (id: string) => void;
  onSelectAll: (select: boolean) => void;
  onRunScan: () => void;
  onExecuteClean: (items: CleanRequestItem[]) => void;
}

const GROUP_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  "System Hygiene": HardDrive,
  "Browser Caches": Globe,
  "Diagnostics & Trash": FileWarning,
};

export const QuickCleanView: React.FC<QuickCleanViewProps> = ({
  scanResult,
  selectedIds,
  cookieToggleIds,
  isScanning,
  isCleaning,
  cleanResult,
  onToggleCategory,
  onToggleCookies,
  onSelectAll,
  onRunScan,
  onExecuteClean,
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const grouped = useMemo(() => {
    if (!scanResult) return [];
    const map = new Map<string, QuickCleanCategory[]>();
    for (const cat of scanResult.categories) {
      const list = map.get(cat.group) ?? [];
      list.push(cat);
      map.set(cat.group, list);
    }
    return Array.from(map.entries());
  }, [scanResult]);

  const selectedBytes = useMemo(() => {
    if (!scanResult) return 0;
    return scanResult.categories.reduce((acc, c) => {
      if (!selectedIds.has(c.id)) return acc;
      const cookieAdd =
        c.supportsCookieToggle && cookieToggleIds.has(c.id)
          ? c.cookieSizeBytes
          : 0;
      return acc + c.sizeBytes + cookieAdd;
    }, 0);
  }, [scanResult, selectedIds, cookieToggleIds]);

  const handleClean = () => {
    if (!scanResult) return;
    const items: CleanRequestItem[] = scanResult.categories
      .filter((c) => selectedIds.has(c.id) && (c.sizeBytes > 0 || (c.supportsCookieToggle && cookieToggleIds.has(c.id) && c.cookieSizeBytes > 0)))
      .map((c) => ({
        categoryId: c.id,
        targetPaths: c.targetPaths,
        includeCookies: c.supportsCookieToggle && cookieToggleIds.has(c.id),
        cookiePaths: c.cookiePaths,
        isRecycleBin: c.isRecycleBin,
      }));
    if (items.length > 0) {
      onExecuteClean(items);
    }
  };

  if (!scanResult && !isScanning) {
    return (
      <div className="h-full flex items-center justify-center p-8">
        <div className="max-w-md w-full p-7 rounded-2xl bg-[#161920] border border-white/[0.08] text-center">
          <div className="w-12 h-12 rounded-2xl bg-[#06B6D4]/10 border border-[#06B6D4]/25 flex items-center justify-center mx-auto mb-4">
            <Sparkles className="w-6 h-6 text-[#06B6D4]" />
          </div>
          <h2 className="text-[16px] font-semibold text-white">
            Ready for System Hygiene Scan
          </h2>
          <p className="text-[13px] text-slate-400 mt-1.5 leading-relaxed">
            Scan temporary directories, browser caches (preserving logins), crash dumps,
            thumbnail caches, and the Recycle Bin in parallel.
          </p>
          <button
            onClick={onRunScan}
            className="mt-5 w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] text-white text-[13px] font-medium hover:brightness-110 transition-all cursor-pointer"
          >
            Scan Hygiene Targets
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      {/* Clean Execution Feedback Banner */}
      {cleanResult && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-between gap-4"
        >
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <div>
              <div className="text-[13px] font-semibold text-emerald-200">
                Hygiene Clean Complete — Reclaimed {formatBytes(cleanResult.freedBytes)}
              </div>
              <div className="text-[12px] text-emerald-300/75">
                Removed {cleanResult.deletedCount.toLocaleString()} items
                {cleanResult.skippedCount > 0
                  ? ` • ${cleanResult.skippedCount.toLocaleString()} locked items skipped safely`
                  : ""}
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Action Summary Bar */}
      {scanResult && (
        <div className="p-4 rounded-2xl bg-[#161920] border border-white/[0.08] flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-6">
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                Selected to Purge
              </div>
              <div className="text-[22px] font-semibold font-mono text-white tabular-nums">
                {formatBytes(selectedBytes)}
              </div>
            </div>
            <div className="h-9 w-[1px] bg-white/[0.08]" />
            <div>
              <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                Detected Junk Files
              </div>
              <div className="text-[15px] font-mono text-slate-200 tabular-nums mt-0.5">
                {scanResult.totalFiles.toLocaleString()} files{" "}
                <span className="text-slate-500 text-[12px]">
                  ({scanResult.durationMs} ms)
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={() => onSelectAll(true)}
              className="px-3 py-2 rounded-lg text-[12px] font-medium text-slate-300 bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] transition-colors cursor-pointer"
            >
              Select All
            </button>
            <button
              onClick={() => onSelectAll(false)}
              className="px-3 py-2 rounded-lg text-[12px] font-medium text-slate-400 bg-white/[0.02] hover:bg-white/[0.06] border border-white/[0.08] transition-colors cursor-pointer"
            >
              Clear
            </button>
            <button
              onClick={handleClean}
              disabled={isCleaning || selectedBytes === 0}
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] disabled:opacity-40 disabled:cursor-not-allowed text-white text-[13px] font-semibold flex items-center gap-2 hover:brightness-110 transition-all cursor-pointer"
            >
              <Trash2 className="w-4 h-4" />
              {isCleaning
                ? "Cleaning..."
                : `Clean ${formatBytes(selectedBytes)}`}
            </button>
          </div>
        </div>
      )}

      {/* Categorized Checkboxes */}
      <div className="space-y-5">
        {grouped.map(([groupName, categories]) => {
          const GroupIcon = GROUP_ICONS[groupName] ?? HardDrive;
          const groupBytes = categories.reduce((s, c) => s + c.sizeBytes, 0);

          return (
            <div key={groupName} className="space-y-2.5">
              <div className="flex items-center justify-between px-1">
                <div className="flex items-center gap-2 text-[12px] font-semibold uppercase tracking-wider text-slate-400">
                  <GroupIcon className="w-3.5 h-3.5 text-[#06B6D4]" />
                  <span>{groupName}</span>
                </div>
                <span className="text-[12px] font-mono text-slate-400 tabular-nums">
                  {formatBytes(groupBytes)}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {categories.map((cat) => {
                  const checked = selectedIds.has(cat.id);
                  const cookiesEnabled = cookieToggleIds.has(cat.id);
                  const expanded = expandedId === cat.id;
                  const effectiveBytes =
                    cat.sizeBytes +
                    (cat.supportsCookieToggle && cookiesEnabled
                      ? cat.cookieSizeBytes
                      : 0);

                  return (
                    <motion.div
                      key={cat.id}
                      layout
                      className={`rounded-xl bg-[#161920] border transition-colors ${
                        checked
                          ? "border-[#06B6D4]/40 bg-[#161920]"
                          : "border-white/[0.08] opacity-80"
                      }`}
                    >
                      <div className="p-4 flex items-start gap-3">
                        <button
                          onClick={() => onToggleCategory(cat.id)}
                          className="mt-0.5 text-[#06B6D4] hover:brightness-125 cursor-pointer shrink-0"
                        >
                          {checked ? (
                            <CheckSquare className="w-4.5 h-4.5" />
                          ) : (
                            <Square className="w-4.5 h-4.5 text-slate-500" />
                          )}
                        </button>

                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[13.5px] font-semibold text-white truncate">
                              {cat.name}
                            </span>
                            <span className="text-[13px] font-mono font-semibold text-white tabular-nums shrink-0">
                              {formatBytes(effectiveBytes)}
                            </span>
                          </div>

                          <p className="text-[12px] text-slate-400 mt-1 leading-relaxed">
                            {cat.description}
                          </p>

                          <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2">
                            <span className="text-[11px] font-mono text-slate-500 tabular-nums">
                              {cat.fileCount.toLocaleString()} items
                            </span>

                            <div className="flex items-center gap-2">
                              {cat.supportsCookieToggle && (
                                <button
                                  onClick={() => onToggleCookies(cat.id)}
                                  className={`px-2 py-1 rounded-md text-[11px] font-medium border flex items-center gap-1 transition-colors cursor-pointer ${
                                    cookiesEnabled
                                      ? "bg-amber-500/15 border-amber-500/40 text-amber-300"
                                      : "bg-white/[0.03] border-white/[0.08] text-slate-400 hover:text-slate-200"
                                  }`}
                                  title="Off by default to keep logins & sessions active"
                                >
                                  <ShieldAlert className="w-3 h-3" />
                                  {cookiesEnabled
                                    ? `Cookies Included (+${formatBytes(cat.cookieSizeBytes)})`
                                    : "Preserve Logins"}
                                </button>
                              )}

                              {cat.samplePaths.length > 0 && (
                                <button
                                  onClick={() =>
                                    setExpandedId(expanded ? null : cat.id)
                                  }
                                  className="px-2 py-1 rounded-md text-[11px] text-slate-400 hover:text-white bg-white/[0.03] border border-white/[0.06] flex items-center gap-1 cursor-pointer"
                                >
                                  {expanded ? (
                                    <ChevronDown className="w-3 h-3" />
                                  ) : (
                                    <ChevronRight className="w-3 h-3" />
                                  )}
                                  Paths
                                </button>
                              )}
                            </div>
                          </div>

                          {expanded && cat.samplePaths.length > 0 && (
                            <div className="mt-3 pt-2.5 border-t border-white/[0.06] space-y-1">
                              {cat.samplePaths.map((p, idx) => (
                                <div
                                  key={idx}
                                  className="text-[11px] font-mono text-slate-500 truncate"
                                  title={p}
                                >
                                  {p}
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
