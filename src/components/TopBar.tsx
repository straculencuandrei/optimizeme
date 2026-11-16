import React from "react";
import { motion } from "framer-motion";
import { Play, Square, Sparkles, Loader2 } from "lucide-react";
import { NavTab, ScanProgressEvent } from "../types/forensics";
import { formatBytes } from "../utils/format";

interface TopBarProps {
  activeTab: NavTab;
  reclaimableBytes: number;
  isScanning: boolean;
  scanProgress: ScanProgressEvent | null;
  onPrimaryScan: () => void;
  onCancelScan: () => void;
}

const TAB_META: Record<NavTab, { title: string; subtitle: string }> = {
  quick_clean: {
    title: "Quick System Hygiene",
    subtitle: "Purge OS temp files, browser caches, logs, and trash without touching logins.",
  },
  forensics: {
    title: "Deep Storage Forensics",
    subtitle: "Uncover massive, stale, and 'Download & Forget' files ranked by Space-Time Impact.",
  },
  apps: {
    title: "Unused Applications & Binaries",
    subtitle: "Inspect installed software launch recency to catch dormant disk bloat.",
  },
  whitelist: {
    title: "Ignore & Whitelist Rules",
    subtitle: "Protected files and directories excluded from future scans and cleanup.",
  },
};

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  reclaimableBytes,
  isScanning,
  scanProgress,
  onPrimaryScan,
  onCancelScan,
}) => {
  const meta = TAB_META[activeTab];

  return (
    <header className="shrink-0 px-6 py-4 bg-[#0D0F12]/90 backdrop-blur-md border-b border-white/[0.08]">
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-[17px] font-semibold tracking-tight text-white truncate">
            {meta.title}
          </h1>
          <p className="text-[12px] text-slate-400 mt-0.5 truncate">
            {meta.subtitle}
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          {/* Total Reclaimable Pill */}
          <div className="px-3.5 py-2 rounded-xl bg-[#161920] border border-white/[0.08] flex items-center gap-3">
            <div className="flex flex-col items-end">
              <span className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold">
                Total Reclaimable
              </span>
              <span className="text-[15px] font-semibold font-mono text-[#06B6D4] tabular-nums leading-tight">
                {formatBytes(reclaimableBytes)}
              </span>
            </div>
            <div className="w-8 h-8 rounded-lg bg-[#06B6D4]/10 border border-[#06B6D4]/25 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-[#06B6D4]" />
            </div>
          </div>

          {/* Primary Scan / Cancel CTA */}
          {activeTab !== "whitelist" && (
            isScanning ? (
              <button
                onClick={onCancelScan}
                className="px-4 py-2.5 rounded-xl bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 text-[13px] font-medium flex items-center gap-2 transition-colors"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                Stop Scan
              </button>
            ) : (
              <button
                onClick={onPrimaryScan}
                className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-[#06B6D4] to-[#3B82F6] hover:brightness-110 text-white text-[13px] font-medium flex items-center gap-2 shadow-[0_0_24px_rgba(6,182,212,0.22)] transition-all cursor-pointer"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                {activeTab === "quick_clean"
                  ? "Scan Hygiene"
                  : activeTab === "apps"
                  ? "Scan Apps"
                  : "Run Forensics"}
              </button>
            )
          )}
        </div>
      </div>

      {/* Live Scan Progress Strip */}
      {isScanning && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          className="mt-3 pt-3 border-t border-white/[0.06]"
        >
          <div className="flex items-center justify-between text-[11px] text-slate-400 mb-1.5">
            <div className="flex items-center gap-2 min-w-0">
              <Loader2 className="w-3.5 h-3.5 text-[#06B6D4] animate-spin shrink-0" />
              <span className="uppercase tracking-wider font-semibold text-[#06B6D4]">
                {scanProgress?.phase || "Scanning"}
              </span>
              <span className="truncate font-mono text-slate-500">
                {scanProgress?.currentPath || "Enumerating filesystem worker threads..."}
              </span>
            </div>
            <div className="shrink-0 font-mono tabular-nums text-slate-300 ml-3">
              {(scanProgress?.scannedFiles ?? 0).toLocaleString()} files •{" "}
              {formatBytes(scanProgress?.scannedBytes ?? 0)}
            </div>
          </div>
          <div className="h-1 w-full rounded-full bg-white/[0.06] overflow-hidden">
            <motion.div
              className="h-full bg-gradient-to-r from-[#06B6D4] via-[#3B82F6] to-[#06B6D4] w-1/3 rounded-full"
              animate={{ x: ["-100%", "320%"] }}
              transition={{ repeat: Infinity, duration: 1.35, ease: "easeInOut" }}
            />
          </div>
        </motion.div>
      )}
    </header>
  );
};
